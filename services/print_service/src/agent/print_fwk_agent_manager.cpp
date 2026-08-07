/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "agent/print_fwk_agent_manager.h"

#include <atomic>
#include <cups/http.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "print_constant.h"
#include "print_cups_client.h"
#include "agent/print_fwk_agent_client_api.h"
#include "print_json_util.h"
#include "print_log.h"
#include "print_system_data.h"
#include "print_util.h"
#include "printer_info.h"
#include "singleton.h"
#include "vendor_manager.h"

namespace OHOS::Print {
namespace {
constexpr int IPP_DEFAULT_PORT = 631;

const char *MapAgentErrorMessage(int32_t errCode)
{
    switch (errCode) {
        case PRINT_FWK_AGENT_CLIENT_ERR_PARAM:
            return "Invalid parameters";
        case PRINT_FWK_AGENT_CLIENT_ERR_SERVER:
            return "Server error";
        case PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS:
            return "Printer already exists";
        case PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND:
            return "Printer not found";
        case PRINT_FWK_AGENT_CLIENT_ERR_RPC:
            return "RPC error";
        case PRINT_FWK_AGENT_CLIENT_ERR_UNIMPLEMENTED:
            return "Not implemented";
        case PRINT_FWK_AGENT_CLIENT_ERR_BACKEND_CONFIG:
            return "Backend config error";
        case PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR:
            return "No package manager";
        case PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED:
            return "Driver install failed";
        case PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY:
            return "Driver install busy";
        case PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT:
            return "Operation timeout";
        default:
            return "Unknown error";
    }
}

PrinterInfo BuildAgentProgressInfo(
    const std::string &printerName, const std::string &stage, const std::string &status,
    std::optional<int32_t> errorCode = std::nullopt)
{
    PrinterInfo info;
    info.SetPrinterId("");
    info.SetPrinterName(printerName);
    info.SetPrinterState(PRINTER_UNKNOWN);
    Json::Value option;
    option["driver"] = PRINT_DRIVER_AGENT;
    option["agentAddProgress"]["stage"] = stage;
    option["agentAddProgress"]["status"] = status;
    if (errorCode.has_value()) {
        option["agentAddProgress"]["errorCode"] = *errorCode;
        option["agentAddProgress"]["errorMsg"] = MapAgentErrorMessage(*errorCode);
    }
    info.SetOption(PrintJsonUtil::WriteString(option));
    return info;
}

PrinterInfo BuildAgentFailureInfo(
    const std::string &printerName, const std::string &stage, int32_t errCode)
{
    return BuildAgentProgressInfo(printerName, stage, "FAILED", errCode);
}

enum class AsyncContextOwnership {
    SUBMITTING,
    ASYNC,
    DONE_DURING_SUBMIT,
};

template<typename Context>
void FinishAsyncContext(Context *context)
{
    AsyncContextOwnership expected = AsyncContextOwnership::SUBMITTING;
    if (!context->ownership.compare_exchange_strong(
        expected, AsyncContextOwnership::DONE_DURING_SUBMIT) &&
        expected == AsyncContextOwnership::ASYNC) {
        delete context;
    }
}

} // namespace

struct PrintFwkAgentManager::AddPrinterContext {
    PrintFwkAgentManager *manager = nullptr;
    std::string printerName;
    std::string uri;
    std::string driverInstall;
    std::string backendType;
    std::atomic<AsyncContextOwnership> ownership { AsyncContextOwnership::SUBMITTING };
};

struct PrintFwkAgentManager::RemovePrinterContext {
    PrintFwkAgentManager *manager = nullptr;
    std::string finalPrinterId;
    std::string finalPrinterName;
    std::atomic<AsyncContextOwnership> ownership { AsyncContextOwnership::SUBMITTING };
};

PrintFwkAgentManager::PrintFwkAgentManager(PrintSystemData &systemData, VendorManager &vendorManager,
    PrintFwkAgentHost &host, std::unique_ptr<PrintFwkAgentClientLoader> loader, NowProvider nowProvider)
    : systemData_(systemData), vendorManager_(vendorManager), host_(host), loader_(std::move(loader)),
      nowProvider_(std::move(nowProvider))
{}

PrintFwkAgentManager::~PrintFwkAgentManager()
{
    Shutdown();
}

bool PrintFwkAgentManager::Init()
{
    if (loader_ == nullptr) {
        loader_ = std::make_unique<PrintFwkAgentClientLoader>();
    }
    if (!loader_->IsLoaded() && !loader_->Load()) {
        state_.store(State::STOPPED);
        PRINT_HILOGE("agent manager Init: client loader unavailable");
        return false;
    }
    state_.store(State::RUNNING);
    return true;
}

void PrintFwkAgentManager::Shutdown()
{
    State expected = State::RUNNING;
    if (!state_.compare_exchange_strong(expected, State::STOPPING)) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPrinters_.clear();
        inFlightAddCount_ = 0;
    }
    if (loader_ != nullptr) {
        loader_->Unload();
    }
    state_.store(State::STOPPED);
}

bool PrintFwkAgentManager::IsRunning() const
{
    return state_.load() == State::RUNNING;
}

void PrintFwkAgentManager::PruneExpiredPendingLocked(Clock::time_point now)
{
    for (auto it = pendingPrinters_.begin(); it != pendingPrinters_.end();) {
        if (it->second.expiresAt <= now) {
            it = pendingPrinters_.erase(it);
        } else {
            ++it;
        }
    }
}

bool PrintFwkAgentManager::TryReserveAddSlot()
{
    const auto now = nowProvider_();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    PruneExpiredPendingLocked(now);
    if (state_.load() != State::RUNNING ||
        inFlightAddCount_ + pendingPrinters_.size() >= MAX_PENDING_AGENT_PRINTERS) {
        return false;
    }
    ++inFlightAddCount_;
    return true;
}

void PrintFwkAgentManager::ReleaseAddSlot()
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    if (inFlightAddCount_ > 0) {
        --inFlightAddCount_;
    }
}

bool PrintFwkAgentManager::CompleteAddSlotWithPending(
    const std::string &uri, const std::string &agentPrinterName, const std::string &backendType)
{
    const std::string uriKey = BuildPendingUriMatchKey(uri);
    const auto now = nowProvider_();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    PruneExpiredPendingLocked(now);
    if (state_.load() != State::RUNNING || inFlightAddCount_ == 0) {
        return false;
    }
    --inFlightAddCount_;
    pendingPrinters_[uriKey] = {
        uri,
        agentPrinterName,
        backendType,
        now + PENDING_TIMEOUT,
    };
    return true;
}

bool PrintFwkAgentManager::ClaimPendingAgentPrinter(const std::string &uri)
{
    if (uri.empty()) {
        return false;
    }
    const std::string uriKey = BuildPendingUriMatchKey(uri);
    const auto now = nowProvider_();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    PruneExpiredPendingLocked(now);
    auto it = pendingPrinters_.find(uriKey);
    if (it == pendingPrinters_.end()) {
        return false;
    }
    it->second.expiresAt = now + PENDING_TIMEOUT;
    return true;
}

bool PrintFwkAgentManager::AttachPendingAgentPrinter(PrinterInfo &printerInfo)
{
    const std::string uri = printerInfo.GetUri();
    if (uri.empty()) {
        return false;
    }
    const std::string uriKey = BuildPendingUriMatchKey(uri);

    PendingAgentPrinter pending;
    {
        const auto now = nowProvider_();
        std::lock_guard<std::mutex> lock(pendingMutex_);
        PruneExpiredPendingLocked(now);
        auto it = pendingPrinters_.find(uriKey);
        if (it == pendingPrinters_.end()) {
            return false;
        }
        pending = it->second;
        pendingPrinters_.erase(it);
    }

    Json::Value option(Json::objectValue);
    Json::Value parsedOption;
    if (PrintJsonUtil::Parse(printerInfo.GetOption(), parsedOption) && parsedOption.isObject()) {
        option = parsedOption;
    }
    option["driver"] = PRINT_DRIVER_AGENT;
    option["agent"]["printerName"] = pending.agentPrinterName;
    option["agent"]["uri"] = pending.agentIppUri;
    option["agent"]["backendType"] = pending.backendType;
    printerInfo.SetOption(PrintJsonUtil::WriteString(option));
    return true;
}

bool PrintFwkAgentManager::IsAgentRouted(const std::string &options)
{
    if (options.empty()) {
        return false;
    }
    Json::Value root;
    if (!PrintJsonUtil::Parse(options, root)) {
        return false;
    }
    std::string driver;
    if (!PrintJsonUtil::FindJsonStringMember(root, "driver", driver)) {
        return false;
    }
    return driver == PRINT_DRIVER_AGENT;
}

bool PrintFwkAgentManager::IsAgentRouteRequested(const std::string &options) const
{
    return host_.IsCallerSystemApp() && IsAgentRouted(options);
}

bool PrintFwkAgentManager::IsAgentRoutedPrinterByName(const std::string &printerName) const
{
    if (!host_.IsCallerSystemApp()) {
        return false;
    }
    std::string standardizedName = PrintUtil::StandardizePrinterName(printerName);
    std::string printerId = systemData_.QueryPrinterIdByStandardizeName(standardizedName);
    if (printerId.empty()) {
        return false;
    }
    PrinterInfo printerInfo;
    return systemData_.QueryAddedPrinterInfoByPrinterId(printerId, printerInfo) &&
        IsAgentRouted(printerInfo.GetOption());
}

bool PrintFwkAgentManager::ExtractAgentAddOptions(
    const std::string &options, std::string &backendType, std::string &driverInstall)
{
    Json::Value root;
    if (!PrintJsonUtil::Parse(options, root) ||
        !root.isMember("agentBackendType") ||
        !root["agentBackendType"].isString()) {
        return false;
    }
    backendType = root["agentBackendType"].asString();
    if (backendType.empty()) {
        return false;
    }
    driverInstall.clear();
    if (!root.isMember("agentDriverInstall")) {
        return true;
    }
    if (!root["agentDriverInstall"].isObject()) {
        return false;
    }
    driverInstall = PrintJsonUtil::WriteString(root["agentDriverInstall"]);
    return true;
}

bool PrintFwkAgentManager::ExtractAgentPrinterMetadata(
    const std::string &options, std::string &printerName, std::string &backendType)
{
    Json::Value option;
    if (!PrintJsonUtil::Parse(options, option) ||
        !option.isMember("driver") ||
        !option["driver"].isString() ||
        option["driver"].asString() != PRINT_DRIVER_AGENT ||
        !option.isMember("agent") ||
        !option["agent"].isObject() ||
        !option["agent"].isMember("printerName") ||
        !option["agent"]["printerName"].isString() ||
        !option["agent"].isMember("backendType") ||
        !option["agent"]["backendType"].isString()) {
        return false;
    }
    printerName = option["agent"]["printerName"].asString();
    backendType = option["agent"]["backendType"].asString();
    return !printerName.empty() && !backendType.empty();
}

std::string PrintFwkAgentManager::BuildPendingUriMatchKey(const std::string &uri)
{
    char scheme[HTTP_MAX_URI] = {0};
    char username[HTTP_MAX_URI] = {0};
    char host[HTTP_MAX_URI] = {0};
    char resource[HTTP_MAX_URI] = {0};
    int port = 0;
    http_uri_status_t status = httpSeparateURI(HTTP_URI_CODING_ALL, uri.c_str(), scheme, sizeof(scheme),
        username, sizeof(username), host, sizeof(host), &port, resource, sizeof(resource));
    if (status != HTTP_URI_STATUS_OK ||
        (std::string(scheme) != "ipp" && std::string(scheme) != "ipps")) {
        return uri;
    }
    if (port <= 0) {
        port = IPP_DEFAULT_PORT;
    }

    std::string key;
    key.reserve(uri.size() + sizeof(port));
    // Keep URI components exact while using unambiguous separators in the internal-only map key.
    auto appendPart = [&key](const char *part) {
        key.append(part);
        key.push_back('\0');
    };
    appendPart(scheme);
    appendPart(username);
    appendPart(host);
    key.append(std::to_string(port));
    key.push_back('\0');
    key.append(resource);
    return key;
}

bool PrintFwkAgentManager::ExtractPrinterIpFromUri(const std::string &uri, std::string &printerIp)
{
    char scheme[HTTP_MAX_URI] = {0};
    char username[HTTP_MAX_URI] = {0};
    char host[HTTP_MAX_URI] = {0};
    char resource[HTTP_MAX_URI] = {0};
    int port = 0;
    http_uri_status_t status = httpSeparateURI(HTTP_URI_CODING_ALL, uri.c_str(), scheme, sizeof(scheme),
        username, sizeof(username), host, sizeof(host), &port, resource, sizeof(resource));
    printerIp = host;
    if (status != HTTP_URI_STATUS_OK ||
        !DelayedSingleton<PrintCupsClient>::GetInstance()->IsIpAddress(printerIp.c_str())) {
        PRINT_HILOGW("AddPrinterViaAgent invalid uri, ret=%{public}u", status);
        return false;
    }
    return true;
}

int32_t PrintFwkAgentManager::SubmitAddPrinter(std::unique_ptr<AddPrinterContext> context)
{
    PrintAddPrinterParam param = {};
    param.uri = context->uri.c_str();
    param.name = context->printerName.c_str();
    param.driverInstall = context->driverInstall.empty() ? nullptr : context->driverInstall.c_str();
    param.backendType = context->backendType.c_str();

    int32_t ret = loader_->AddPrinter(param, HandleAddDone, HandleAddProgress, context.get());
    if (ret != E_PRINT_NONE) {
        ReleaseAddSlot();
        vendorManager_.ClearConnectingPrinter();
        return ret;
    }

    AsyncContextOwnership expected = AsyncContextOwnership::SUBMITTING;
    if (context->ownership.compare_exchange_strong(expected, AsyncContextOwnership::ASYNC)) {
        context.release();
    }
    return E_PRINT_NONE;
}

int32_t PrintFwkAgentManager::AddPrinterViaAgent(const std::string &printerName, const std::string &uri,
    const std::string &options)
{
    if (!IsRunning() || loader_ == nullptr) {
        return E_PRINT_RPC_FAILURE;
    }

    std::string backendType;
    std::string driverInstall;
    if (!ExtractAgentAddOptions(options, backendType, driverInstall)) {
        return E_PRINT_INVALID_PARAMETER;
    }

    std::string printerIp;
    if (!ExtractPrinterIpFromUri(uri, printerIp)) {
        return E_PRINT_INVALID_PRINTER;
    }

    if (!TryReserveAddSlot()) {
        PRINT_HILOGW("AddPrinterViaAgent pending capacity reached");
        return E_PRINT_SERVER_FAILURE;
    }

    vendorManager_.SetConnectingPrinterName(printerName);
    vendorManager_.SetConnectingPrinter(IP_AUTO, printerIp);

    auto context = std::make_unique<AddPrinterContext>();
    context->manager = this;
    context->printerName = printerName;
    context->uri = uri;
    context->driverInstall = driverInstall;
    context->backendType = backendType;
    return SubmitAddPrinter(std::move(context));
}

void PrintFwkAgentManager::HandleAddProgress(int32_t progress, void *userData)
{
    auto *context = static_cast<AddPrinterContext *>(userData);
    if (context == nullptr || context->manager == nullptr || !context->manager->IsRunning()) {
        return;
    }

    const char *stage = "UNKNOWN";
    switch (progress) {
        case PRINT_AGENT_PROGRESS_ENV_INIT:
            stage = "ENV_INIT";
            break;
        case PRINT_AGENT_PROGRESS_ADDING_PRINTER:
            stage = "ADDING_PRINTER";
            break;
        case PRINT_AGENT_PROGRESS_INSTALLING_DRIVER:
            stage = "INSTALLING_DRIVER";
            break;
        case PRINT_AGENT_PROGRESS_RETRYING_ADD:
            stage = "RETRYING_ADD";
            break;
        case PRINT_AGENT_PROGRESS_DONE:
            stage = "DONE";
            break;
        default:
            break;
    }
    PrinterInfo info = BuildAgentProgressInfo(context->printerName, stage, "RUNNING");
    context->manager->host_.NotifyPrinterInfoChanged(info);
}

void PrintFwkAgentManager::HandleAddDone(int32_t errCode, const PrintAddPrinterResult *result, void *userData)
{
    auto *context = static_cast<AddPrinterContext *>(userData);
    if (context == nullptr) {
        return;
    }

    auto *manager = context->manager;
    if (manager == nullptr) {
        PRINT_HILOGW("AddPrinter done without manager");
    } else if (!manager->IsRunning()) {
        manager->ReleaseAddSlot();
    } else if (errCode != PRINT_FWK_AGENT_CLIENT_OK) {
        manager->ReleaseAddSlot();
        PrinterInfo info = BuildAgentFailureInfo(context->printerName, "ENV_INIT", errCode);
        manager->host_.NotifyPrinterInfoChanged(info);
    } else {
        std::string ippUri = result != nullptr && result->ippUri != nullptr ? result->ippUri : "";
        if (ippUri.empty()) {
            manager->ReleaseAddSlot();
            PrinterInfo info = BuildAgentFailureInfo(
                context->printerName, "DONE", PRINT_FWK_AGENT_CLIENT_ERR_SERVER);
            manager->host_.NotifyPrinterInfoChanged(info);
        } else if (manager->CompleteAddSlotWithPending(
            ippUri, context->printerName, context->backendType)) {
            PrinterInfo info = BuildAgentProgressInfo(context->printerName, "DONE", "PENDING_DISCOVERY");
            info.SetUri(ippUri);
            manager->host_.NotifyPrinterInfoChanged(info);
        }
    }

    if (manager != nullptr) {
        manager->vendorManager_.ClearConnectingPrinter();
    }
    FinishAsyncContext(context);
}

int32_t PrintFwkAgentManager::DeletePrinterFromAgent(const std::string &printerName)
{
    if (!IsRunning() || loader_ == nullptr) {
        return E_PRINT_RPC_FAILURE;
    }

    std::string standardizedName = PrintUtil::StandardizePrinterName(printerName);
    std::string printerId = systemData_.QueryPrinterIdByStandardizeName(standardizedName);
    PrinterInfo printerInfo;
    std::string agentPrinterName;
    std::string backendType;
    if (printerId.empty() || !systemData_.QueryAddedPrinterInfoByPrinterId(printerId, printerInfo) ||
        !ExtractAgentPrinterMetadata(printerInfo.GetOption(), agentPrinterName, backendType)) {
        PRINT_HILOGW("DeletePrinterFromAgent missing persisted agent metadata");
        return E_PRINT_INVALID_PRINTER;
    }

    auto context = std::make_unique<RemovePrinterContext>();
    context->manager = this;
    context->finalPrinterName = printerInfo.GetPrinterName();
    context->finalPrinterId = printerId;
    const std::string standardizedAgentPrinterName = PrintUtil::StandardizePrinterName(agentPrinterName);
    int32_t ret = loader_->RemovePrinter(
        standardizedAgentPrinterName, backendType, HandleRemoveDone, context.get());
    if (ret != E_PRINT_NONE) {
        return ret;
    }

    AsyncContextOwnership expected = AsyncContextOwnership::SUBMITTING;
    if (context->ownership.compare_exchange_strong(expected, AsyncContextOwnership::ASYNC)) {
        context.release();
    }
    return E_PRINT_NONE;
}

void PrintFwkAgentManager::HandleRemoveDone(int32_t errCode, void *userData)
{
    auto *context = static_cast<RemovePrinterContext *>(userData);
    if (context == nullptr) {
        return;
    }

    auto *manager = context->manager;
    const bool canContinue = errCode == PRINT_FWK_AGENT_CLIENT_OK ||
        errCode == PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND;
    if (manager != nullptr && manager->IsRunning() && canContinue) {
        manager->host_.CommitAgentPrinterDeleted(context->finalPrinterId, context->finalPrinterName);
    }

    FinishAsyncContext(context);
}

} // namespace OHOS::Print
