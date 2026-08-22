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

#include <arpa/inet.h>
#include <atomic>
#include <cups/http.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "agent/print_fwk_agent_client_api.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_log.h"
#include "print_system_data.h"
#include "print_util.h"
#include "printer_info.h"

namespace OHOS::Print {
namespace {
constexpr int IPP_DEFAULT_PORT = 631;
constexpr const char *CUPS_PRINTER_RESOURCE_PREFIX = "/printers/";
constexpr const char *AGENT_BACKEND_KEEPALIVE_TASK = "AgentBackendKeepalive";

struct ParsedIppUri {
    std::string scheme;
    std::string username;
    std::string host;
    int port = IPP_DEFAULT_PORT;
    std::string resource;
};

bool ParseIppUri(const std::string &uri, ParsedIppUri &parsed)
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
        parsed = {};
        return false;
    }
    parsed = { scheme, username, host, port > 0 ? port : IPP_DEFAULT_PORT, resource };
    return true;
}

std::string BuildParsedUriMatchKey(const ParsedIppUri &parsed, size_t uriLength)
{
    std::string key;
    key.reserve(uriLength + sizeof(parsed.port));
    auto appendPart = [&key](const std::string &part) {
        key.append(part);
        key.push_back('\0');
    };
    appendPart(parsed.scheme);
    appendPart(parsed.username);
    appendPart(parsed.host);
    key.append(std::to_string(parsed.port));
    key.push_back('\0');
    key.append(parsed.resource);
    return key;
}

bool IsIpAddress(const std::string &host)
{
    struct in_addr addr4 = {};
    struct in6_addr addr6 = {};
    return inet_pton(AF_INET, host.c_str(), &addr4) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &addr6) == 1;
}

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
        case PRINT_FWK_AGENT_CLIENT_BACKEND_STOPPED:
            return "Backend Stopped";
        case PRINT_FWK_AGENT_CLIENT_BACKEND_RESUME_FAILED:
            return "Backend resume failed";
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

// Supports callbacks that may complete either during the loader call or asynchronously afterwards.
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

class PrintFwkAgentManager::AgentPrinterOptionCodec {
public:
    static bool IsAgentRouted(const std::string &options)
    {
        Json::Value root;
        std::string driver;
        return PrintJsonUtil::Parse(options, root) &&
            PrintJsonUtil::FindJsonStringMember(root, "driver", driver) &&
            driver == PRINT_DRIVER_AGENT;
    }

    static bool ParseAddOptions(const std::string &options, AgentAddOptions &addOptions)
    {
        Json::Value root;
        if (!PrintJsonUtil::Parse(options, root)) {
            return false;
        }
        return ParseAddOptions(root, addOptions);
    }

    static RoutedAddOptionsResult ParseRoutedAddOptions(
        const std::string &options, AgentAddOptions &addOptions)
    {
        Json::Value root;
        std::string driver;
        if (!PrintJsonUtil::Parse(options, root) ||
            !PrintJsonUtil::FindJsonStringMember(root, "driver", driver) ||
            driver != PRINT_DRIVER_AGENT) {
            return RoutedAddOptionsResult::NOT_AGENT_ROUTE;
        }
        return ParseAddOptions(root, addOptions) ? RoutedAddOptionsResult::VALID_OPTIONS :
            RoutedAddOptionsResult::INVALID_OPTIONS;
    }

    static bool ParseAddOptions(const Json::Value &root, AgentAddOptions &addOptions)
    {
        if (!root.isMember("agentBackendType") || !root["agentBackendType"].isString()) {
            return false;
        }
        addOptions = {};
        addOptions.backendType = root["agentBackendType"].asString();
        if (addOptions.backendType.empty()) {
            return false;
        }
        if (!root.isMember("agentDriverInstall")) {
            return true;
        }
        if (!root["agentDriverInstall"].isObject()) {
            return false;
        }
        addOptions.driverInstall = PrintJsonUtil::WriteString(root["agentDriverInstall"]);
        return true;
    }

    static bool ParsePersistedMetadata(
        const std::string &options, PersistedAgentPrinterMetadata &metadata)
    {
        Json::Value option;
        if (!ParsePersistedOption(options, option)) {
            return false;
        }
        metadata = {};
        metadata.queueName = option["agent"]["queueName"].asString();
        metadata.backendType = option["agent"]["backendType"].asString();
        if (option["agent"].isMember("sourceUri") && option["agent"]["sourceUri"].isString()) {
            metadata.source = PrintFwkAgentManager::BuildSourcePrinterIdentity(
                option["agent"]["sourceUri"].asString());
        }
        return !metadata.queueName.empty() && !metadata.backendType.empty();
    }

    static bool ParseSourceIdentity(const std::string &options, SourcePrinterIdentity &source)
    {
        Json::Value option;
        if (!PrintJsonUtil::Parse(options, option) ||
            !option.isMember("driver") || !option["driver"].isString() ||
            option["driver"].asString() != PRINT_DRIVER_AGENT ||
            !option.isMember("agent") || !option["agent"].isObject() ||
            !option["agent"].isMember("sourceUri") || !option["agent"]["sourceUri"].isString()) {
            return false;
        }
        source = PrintFwkAgentManager::BuildSourcePrinterIdentity(
            option["agent"]["sourceUri"].asString());
        return !source.uri.empty();
    }

    static void ApplyPendingMetadata(const PendingAgentPrinterMetadata &metadata, PrinterInfo &printerInfo)
    {
        Json::Value option(Json::objectValue);
        Json::Value parsedOption;
        if (PrintJsonUtil::Parse(printerInfo.GetOption(), parsedOption) && parsedOption.isObject()) {
            option = parsedOption;
        }
        option["driver"] = PRINT_DRIVER_AGENT;
        option["agent"]["queueName"] = metadata.queue.name;
        option["agent"]["uri"] = metadata.queue.uri;
        option["agent"]["queueUri"] = metadata.queue.uri;
        option["agent"]["sourceUri"] = metadata.source.uri;
        option["agent"]["backendType"] = metadata.backendType;
        printerInfo.SetOption(PrintJsonUtil::WriteString(option));
    }

private:
    static bool ParsePersistedOption(const std::string &options, Json::Value &option)
    {
        return PrintJsonUtil::Parse(options, option) &&
            option.isMember("driver") && option["driver"].isString() &&
            option["driver"].asString() == PRINT_DRIVER_AGENT &&
            option.isMember("agent") && option["agent"].isObject() &&
            option["agent"].isMember("queueName") && option["agent"]["queueName"].isString() &&
            option["agent"].isMember("backendType") && option["agent"]["backendType"].isString();
    }
};

struct PrintFwkAgentManager::AddReservation {
    AddReservation(PrintFwkAgentManager &owner, SourcePrinterIdentity sourceIdentity)
        : manager(&owner), source(std::move(sourceIdentity))
    {}

    ~AddReservation()
    {
        if (active && manager != nullptr) {
            manager->ReleaseAddSlot(source);
        }
    }

    void Commit()
    {
        active = false;
    }

    PrintFwkAgentManager *manager = nullptr;
    SourcePrinterIdentity source;
    // True while the destructor must release the in-flight source.
    bool active = true;
};

struct PrintFwkAgentManager::PrepareAddResult {
    int32_t code = E_PRINT_NONE;
    std::unique_ptr<AddReservation> reservation;
};

struct PrintFwkAgentManager::AddPrinterContext {
    PrintFwkAgentManager *manager = nullptr;
    std::string printerName;
    SourcePrinterIdentity source;
    std::string driverInstall;
    std::string backendType;
    std::unique_ptr<AddReservation> reservation;
    std::atomic<AsyncContextOwnership> ownership { AsyncContextOwnership::SUBMITTING };
};

struct PrintFwkAgentManager::RemovePrinterContext {
    PrintFwkAgentManager *manager = nullptr;
    std::string finalPrinterId;
    std::string finalPrinterName;
    SourcePrinterIdentity source;
    std::atomic<AsyncContextOwnership> ownership { AsyncContextOwnership::SUBMITTING };
};

PrintFwkAgentManager &PrintFwkAgentManager::GetInstance()
{
    static PrintFwkAgentManager instance;
    return instance;
}

PrintFwkAgentManager::~PrintFwkAgentManager()
{
    Shutdown();
}

bool PrintFwkAgentManager::Init(PrintSystemData &systemData, PrintFwkAgentHost &host,
    DelayedTaskPoster delayedTaskPoster, std::unique_ptr<PrintFwkAgentClientLoader> loader,
    NowProvider nowProvider)
{
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (state_.load() == State::RUNNING) {
        return true;
    }
    if (!delayedTaskPoster) {
        PRINT_HILOGE("agent manager Init: delayed task poster unavailable");
        return false;
    }
    systemData_ = &systemData;
    host_ = &host;
    nowProvider_ = std::move(nowProvider);
    delayedTaskPoster_ = std::move(delayedTaskPoster);
    if (loader != nullptr) {
        loader_ = std::move(loader);
    }
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
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (state_.load() == State::STOPPING) {
        return;
    }
    state_.store(State::STOPPING);
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPrinters_.clear();
        inFlightPrinters_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(keepaliveMutex_);
        keepaliveJobIds_.clear();
        ++keepaliveTaskGeneration_;
        keepaliveTaskScheduled_ = false;
    }
    delayedTaskPoster_ = {};
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

PrintFwkAgentManager::AddSlotResult PrintFwkAgentManager::TryReserveAddSlot(
    const SourcePrinterIdentity &source, const std::string &printerName, PrinterInfo &currentInfo)
{
    const auto now = nowProvider_();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    PruneExpiredPendingLocked(now);
    if (state_.load() != State::RUNNING) {
        return AddSlotResult::NOT_RUNNING;
    }
    auto inFlight = inFlightPrinters_.find(source.matchKey);
    if (inFlight != inFlightPrinters_.end()) {
        currentInfo = BuildAgentProgressInfo(
            inFlight->second.displayName, inFlight->second.stage, "RUNNING");
        return AddSlotResult::IN_FLIGHT;
    }
    const std::string pendingKey = FindPendingPrinterKeyBySourceLocked(source.matchKey);
    auto pending = pendingPrinters_.find(pendingKey);
    if (pending != pendingPrinters_.end()) {
        currentInfo = BuildAgentProgressInfo(
            pending->second.metadata.displayName, "DONE", "PENDING_DISCOVERY");
        currentInfo.SetUri(pending->second.metadata.queue.uri);
        return AddSlotResult::PENDING_DISCOVERY;
    }
    if (inFlightPrinters_.size() + pendingPrinters_.size() >= MAX_PENDING_AGENT_PRINTERS) {
        return AddSlotResult::CAPACITY_REACHED;
    }
    inFlightPrinters_[source.matchKey] = { printerName, "ENV_INIT" };
    return AddSlotResult::RESERVED;
}

void PrintFwkAgentManager::ReleaseAddSlot(const SourcePrinterIdentity &source)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    inFlightPrinters_.erase(source.matchKey);
}

bool PrintFwkAgentManager::UpdateInFlightProgress(
    const SourcePrinterIdentity &source, const std::string &stage)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    auto inFlight = inFlightPrinters_.find(source.matchKey);
    if (inFlight == inFlightPrinters_.end()) {
        return false;
    }
    inFlight->second.stage = stage;
    return true;
}

bool PrintFwkAgentManager::CompleteAddSlotWithPending(PendingAgentPrinterMetadata metadata)
{
    const std::string uriKey = BuildUriMatchKey(metadata.queue.uri);
    const auto now = nowProvider_();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    PruneExpiredPendingLocked(now);
    if (state_.load() != State::RUNNING ||
        inFlightPrinters_.erase(metadata.source.matchKey) == 0) {
        return false;
    }
    const std::string sameSourceKey = FindPendingPrinterKeyBySourceLocked(metadata.source.matchKey);
    if (!sameSourceKey.empty() && sameSourceKey != uriKey) {
        pendingPrinters_.erase(sameSourceKey);
    }
    pendingPrinters_[uriKey] = {
        std::move(metadata),
        now + PENDING_TIMEOUT,
        false,
    };
    return true;
}

std::string PrintFwkAgentManager::FindPendingPrinterKeyLocked(const std::string &uri) const
{
    const std::string exactKey = BuildUriMatchKey(uri);
    if (pendingPrinters_.find(exactKey) != pendingPrinters_.end()) {
        return exactKey;
    }

    AgentQueueIdentity discoveredQueue;
    if (!BuildAgentQueueIdentity(uri, discoveredQueue)) {
        return {};
    }

    std::string matchedKey;
    for (const auto &[key, pending] : pendingPrinters_) {
        if (pending.metadata.queue.name != discoveredQueue.name) {
            continue;
        }
        if (!matchedKey.empty()) {
            PRINT_HILOGW("Agent pending queue name is ambiguous");
            return {};
        }
        matchedKey = key;
    }
    return matchedKey;
}

std::string PrintFwkAgentManager::FindPendingPrinterKeyBySourceLocked(const std::string &sourceKey) const
{
    for (const auto &[key, pending] : pendingPrinters_) {
        if (pending.metadata.source.matchKey == sourceKey) {
            return key;
        }
    }
    return {};
}

bool PrintFwkAgentManager::ClaimPendingAgentPrinter(PrinterInfo &printerInfo)
{
    const std::string uri = printerInfo.GetUri();
    if (uri.empty()) {
        return false;
    }
    const auto now = nowProvider_();
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        PruneExpiredPendingLocked(now);
        const std::string uriKey = FindPendingPrinterKeyLocked(uri);
        auto it = pendingPrinters_.find(uriKey);
        if (it == pendingPrinters_.end() || it->second.attached) {
            return false;
        }
        it->second.expiresAt = now + PENDING_TIMEOUT;
        printerInfo.SetPrinterName(it->second.metadata.displayName);
    }
    return true;
}

bool PrintFwkAgentManager::AttachPendingAgentPrinter(PrinterInfo &printerInfo)
{
    const std::string uri = printerInfo.GetUri();
    if (uri.empty()) {
        return false;
    }
    PendingAgentPrinter pending;
    {
        const auto now = nowProvider_();
        std::lock_guard<std::mutex> lock(pendingMutex_);
        PruneExpiredPendingLocked(now);
        const std::string uriKey = FindPendingPrinterKeyLocked(uri);
        auto it = pendingPrinters_.find(uriKey);
        if (it == pendingPrinters_.end() || it->second.attached) {
            return false;
        }
        pending = it->second;
        it->second.attached = true;
    }
    AgentPrinterOptionCodec::ApplyPendingMetadata(pending.metadata, printerInfo);
    return true;
}

void PrintFwkAgentManager::ConfirmAgentPrinterPersisted(const PrinterInfo &printerInfo)
{
    PersistedAgentPrinterMetadata metadata;
    if (!AgentPrinterOptionCodec::ParsePersistedMetadata(printerInfo.GetOption(), metadata)) {
        return;
    }
    ReleaseTrackedSource(metadata.source, metadata.queueName);
}

int32_t PrintFwkAgentManager::EnsureAgentBackendReady()
{
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (state_.load() != State::RUNNING || loader_ == nullptr) {
        return E_PRINT_RPC_FAILURE;
    }
    return loader_->EnsureBackendReady();
}

bool PrintFwkAgentManager::IsAgentPrinter(const std::string &printerId) const
{
    if (systemData_ == nullptr) {
        return false;
    }
    PrinterInfo info;
    return systemData_->QueryAddedPrinterInfoByPrinterId(printerId, info) &&
        AgentPrinterOptionCodec::IsAgentRouted(info.GetOption());
}

bool PrintFwkAgentManager::HasPersistedAgentPrinters() const
{
    if (systemData_ == nullptr) {
        return false;
    }
    for (const auto &printerId : systemData_->QueryAddedPrinterIdList()) {
        if (IsAgentPrinter(printerId)) {
            return true;
        }
    }
    return false;
}

int32_t PrintFwkAgentManager::EnsureBackendReadyForPersistedPrinters()
{
    if (!IsRunning() || !HasPersistedAgentPrinters()) {
        return E_PRINT_NONE;
    }
    PRINT_HILOGI("Agent printers found, ensuring backend ready on startup.");
    int32_t code = EnsureAgentBackendReady();
    if (code != E_PRINT_NONE) {
        PRINT_HILOGW("Agent backend not ready on startup, code=%{public}d", code);
    }
    return code;
}

void PrintFwkAgentManager::PreparePrintJob(const std::string &jobId, const std::string &printerId)
{
    if (!IsAgentPrinter(printerId) || !IsRunning()) {
        return;
    }
    int32_t code = EnsureAgentBackendReady();
    if (code != E_PRINT_NONE) {
        PRINT_HILOGW("PreparePrintJob: backend wakeup failed, continue printing, code=%{public}d", code);
    }
    StartAgentBackendKeepalive(jobId);
}

void PrintFwkAgentManager::OnPrintJobStateChanged(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    if (state == PRINT_JOB_COMPLETED ||
        (state == PRINT_JOB_BLOCKED && subState == PRINT_JOB_BLOCKED_INTERRUPT)) {
        StopAgentBackendKeepalive(jobId);
    }
}

void PrintFwkAgentManager::StartAgentBackendKeepalive(const std::string &jobId)
{
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
        if (state_.load() != State::RUNNING) {
            return;
        }
        std::lock_guard<std::mutex> lock(keepaliveMutex_);
        keepaliveJobIds_.insert(jobId);
        if (keepaliveTaskScheduled_) {
            PRINT_HILOGI("StartAgentBackendKeepalive: jobId=%{public}s", jobId.c_str());
            return;
        }
        generation = ++keepaliveTaskGeneration_;
        keepaliveTaskScheduled_ = true;
    }
    PRINT_HILOGI("StartAgentBackendKeepalive: jobId=%{public}s", jobId.c_str());
    ScheduleBackendKeepaliveTask(generation);
}

void PrintFwkAgentManager::StopAgentBackendKeepalive(const std::string &jobId)
{
    std::lock_guard<std::mutex> lock(keepaliveMutex_);
    if (keepaliveJobIds_.erase(jobId) != 0) {
        if (keepaliveJobIds_.empty()) {
            ++keepaliveTaskGeneration_;
            keepaliveTaskScheduled_ = false;
        }
        PRINT_HILOGI("StopAgentBackendKeepalive: jobId=%{public}s", jobId.c_str());
    }
}

void PrintFwkAgentManager::ScheduleBackendKeepaliveTask(uint64_t generation)
{
    DelayedTaskPoster delayedTaskPoster;
    {
        std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
        std::lock_guard<std::mutex> keepaliveLock(keepaliveMutex_);
        if (state_.load() != State::RUNNING || generation != keepaliveTaskGeneration_ ||
            !keepaliveTaskScheduled_ || keepaliveJobIds_.empty()) {
            return;
        }
        delayedTaskPoster = delayedTaskPoster_;
    }

    const int64_t delayMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        BACKEND_KEEPALIVE_INTERVAL).count();
    bool posted = delayedTaskPoster && delayedTaskPoster(
        [this, generation]() { HandleBackendKeepaliveTask(generation); },
        AGENT_BACKEND_KEEPALIVE_TASK, delayMs);
    if (posted) {
        return;
    }

    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    std::lock_guard<std::mutex> keepaliveLock(keepaliveMutex_);
    if (generation == keepaliveTaskGeneration_) {
        keepaliveTaskScheduled_ = false;
    }
    PRINT_HILOGW("ScheduleBackendKeepaliveTask: post task failed");
}

void PrintFwkAgentManager::HandleBackendKeepaliveTask(uint64_t generation)
{
    {
        std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
        std::lock_guard<std::mutex> keepaliveLock(keepaliveMutex_);
        if (state_.load() != State::RUNNING || loader_ == nullptr ||
            generation != keepaliveTaskGeneration_ || !keepaliveTaskScheduled_ || keepaliveJobIds_.empty()) {
            return;
        }
        loader_->BackendKeepaliveTick();
    }
    ScheduleBackendKeepaliveTask(generation);
}

std::optional<int32_t> PrintFwkAgentManager::TryAddPrinterViaAgent(
    const std::string &printerName, const std::string &uri, const std::string &options)
{
    if (host_ == nullptr || !host_->IsCallerSystemApp()) {
        return std::nullopt;
    }
    AgentAddOptions addOptions;
    RoutedAddOptionsResult parseResult = AgentPrinterOptionCodec::ParseRoutedAddOptions(options, addOptions);
    if (parseResult == RoutedAddOptionsResult::NOT_AGENT_ROUTE) {
        return std::nullopt;
    }
    if (!IsRunning()) {
        return E_PRINT_RPC_FAILURE;
    }
    if (parseResult == RoutedAddOptionsResult::INVALID_OPTIONS) {
        return E_PRINT_INVALID_PARAMETER;
    }
    return AddPrinterViaAgent(printerName, uri, std::move(addOptions));
}

bool PrintFwkAgentManager::IsAgentRoutedPrinterByName(const std::string &printerName) const
{
    if (host_ == nullptr || systemData_ == nullptr || !host_->IsCallerSystemApp()) {
        return false;
    }
    std::string standardizedName = PrintUtil::StandardizePrinterName(printerName);
    std::string printerId = systemData_->QueryPrinterIdByStandardizeName(standardizedName);
    if (printerId.empty()) {
        return false;
    }
    PrinterInfo printerInfo;
    return systemData_->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo) &&
        AgentPrinterOptionCodec::IsAgentRouted(printerInfo.GetOption());
}

std::string PrintFwkAgentManager::BuildUriMatchKey(const std::string &uri)
{
    ParsedIppUri parsed;
    if (!ParseIppUri(uri, parsed)) {
        return uri;
    }
    return BuildParsedUriMatchKey(parsed, uri.size());
}

PrintFwkAgentManager::SourcePrinterIdentity PrintFwkAgentManager::BuildSourcePrinterIdentity(
    const std::string &uri)
{
    return { uri, BuildUriMatchKey(uri) };
}

bool PrintFwkAgentManager::ParseSourcePrinterUri(const std::string &uri, SourcePrinterIdentity &source)
{
    ParsedIppUri parsed;
    if (!ParseIppUri(uri, parsed) || !IsIpAddress(parsed.host)) {
        source = {};
        PRINT_HILOGW("AddPrinterViaAgent invalid source uri");
        return false;
    }
    source = { uri, BuildParsedUriMatchKey(parsed, uri.size()) };
    return true;
}

bool PrintFwkAgentManager::BuildAgentQueueIdentity(const std::string &uri, AgentQueueIdentity &queue)
{
    ParsedIppUri parsed;
    if (!ParseIppUri(uri, parsed)) {
        queue = {};
        return false;
    }
    const std::string &resourcePath = parsed.resource;
    const size_t prefixLength = std::char_traits<char>::length(CUPS_PRINTER_RESOURCE_PREFIX);
    if (resourcePath.compare(0, prefixLength, CUPS_PRINTER_RESOURCE_PREFIX) != 0 ||
        resourcePath.size() <= prefixLength ||
        resourcePath.find('/', prefixLength) != std::string::npos) {
        queue = {};
        return false;
    }
    queue = { uri, resourcePath.substr(prefixLength) };
    return true;
}

bool PrintFwkAgentManager::IsSourcePrinterAdded(const SourcePrinterIdentity &source) const
{
    if (systemData_ == nullptr) {
        return false;
    }
    for (const auto &printerId : systemData_->QueryAddedPrinterIdList()) {
        PrinterInfo printerInfo;
        if (!systemData_->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo)) {
            continue;
        }
        SourcePrinterIdentity persistedSource;
        if (!AgentPrinterOptionCodec::ParseSourceIdentity(printerInfo.GetOption(), persistedSource)) {
            continue;
        }
        if (persistedSource.matchKey == source.matchKey) {
            return true;
        }
    }
    return false;
}

void PrintFwkAgentManager::ReleaseTrackedSource(
    const SourcePrinterIdentity &source, const std::string &queueName)
{
    if (source.matchKey.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(pendingMutex_);
    const std::string pendingKey = FindPendingPrinterKeyBySourceLocked(source.matchKey);
    auto pending = pendingPrinters_.find(pendingKey);
    if (pending == pendingPrinters_.end()) {
        return;
    }
    if (!queueName.empty() && pending->second.metadata.queue.name != queueName) {
        return;
    }
    pendingPrinters_.erase(pending);
}

int32_t PrintFwkAgentManager::SubmitAddPrinter(std::unique_ptr<AddPrinterContext> context)
{
    PrintAddPrinterParam param = {};
    param.uri = context->source.uri.c_str();
    param.name = context->printerName.c_str();
    param.driverInstall = context->driverInstall.empty() ? nullptr : context->driverInstall.c_str();
    param.backendType = context->backendType.c_str();

    int32_t ret = E_PRINT_RPC_FAILURE;
    {
        std::lock_guard<std::mutex> lock(lifecycleMutex_);
        if (state_.load() == State::RUNNING && loader_ != nullptr) {
            ret = loader_->AddPrinter(param, HandleAddDone, HandleAddProgress, context.get());
        }
    }
    if (ret != E_PRINT_NONE) {
        return ret;
    }

    AsyncContextOwnership expected = AsyncContextOwnership::SUBMITTING;
    if (context->ownership.compare_exchange_strong(expected, AsyncContextOwnership::ASYNC)) {
        context.release();
    }
    return E_PRINT_NONE;
}

PrintFwkAgentManager::PrepareAddResult PrintFwkAgentManager::PrepareAgentAdd(
    const std::string &printerName, const SourcePrinterIdentity &source)
{
    PrepareAddResult result;
    if (IsSourcePrinterAdded(source)) {
        PrinterInfo info = BuildAgentFailureInfo(
            printerName, "ENV_INIT", PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS);
        host_->NotifyPrinterInfoChanged(info);
        return result;
    }
    PrinterInfo currentInfo;
    const AddSlotResult slotResult = TryReserveAddSlot(source, printerName, currentInfo);
    if (slotResult == AddSlotResult::IN_FLIGHT ||
        slotResult == AddSlotResult::PENDING_DISCOVERY) {
        host_->NotifyPrinterInfoChanged(currentInfo);
        return result;
    }
    if (slotResult == AddSlotResult::CAPACITY_REACHED) {
        PRINT_HILOGW("AddPrinterViaAgent pending capacity reached");
        result.code = E_PRINT_SERVER_FAILURE;
        return result;
    }
    if (slotResult == AddSlotResult::NOT_RUNNING) {
        result.code = E_PRINT_RPC_FAILURE;
        return result;
    }
    result.reservation = std::make_unique<AddReservation>(*this, source);
    if (IsSourcePrinterAdded(source)) {
        PrinterInfo info = BuildAgentFailureInfo(
            printerName, "ENV_INIT", PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS);
        host_->NotifyPrinterInfoChanged(info);
        result.reservation.reset();
        return result;
    }
    result.code = EnsureAgentBackendReady();
    if (result.code != E_PRINT_NONE) {
        PRINT_HILOGE("AddPrinterViaAgent: agent backend not ready, code=%{public}d", result.code);
    }
    return result;
}

int32_t PrintFwkAgentManager::AddPrinterViaAgent(const std::string &printerName, const std::string &uri,
    const std::string &options)
{
    if (!IsRunning()) {
        return E_PRINT_RPC_FAILURE;
    }

    AgentAddOptions addOptions;
    if (!AgentPrinterOptionCodec::ParseAddOptions(options, addOptions)) {
        return E_PRINT_INVALID_PARAMETER;
    }
    return AddPrinterViaAgent(printerName, uri, std::move(addOptions));
}

int32_t PrintFwkAgentManager::AddPrinterViaAgent(
    const std::string &printerName, const std::string &uri, AgentAddOptions addOptions)
{
    SourcePrinterIdentity source;
    if (!ParseSourcePrinterUri(uri, source)) {
        return E_PRINT_INVALID_PRINTER;
    }

    PrepareAddResult prepared = PrepareAgentAdd(printerName, source);
    if (prepared.reservation == nullptr || prepared.code != E_PRINT_NONE) {
        return prepared.code;
    }

    auto context = std::make_unique<AddPrinterContext>();
    context->manager = this;
    context->printerName = printerName;
    context->source = std::move(source);
    context->driverInstall = std::move(addOptions.driverInstall);
    context->backendType = std::move(addOptions.backendType);
    context->reservation = std::move(prepared.reservation);
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
    if (!context->manager->UpdateInFlightProgress(context->source, stage)) {
        return;
    }
    PrinterInfo info = BuildAgentProgressInfo(context->printerName, stage, "RUNNING");
    context->manager->host_->NotifyPrinterInfoChanged(info);
}

void PrintFwkAgentManager::ProcessAddResult(
    int32_t errCode, const PrintAddPrinterResult *result, AddPrinterContext &context)
{
    auto *manager = context.manager;
    if (manager == nullptr) {
        PRINT_HILOGW("AddPrinter done without manager");
        return;
    }
    if (!manager->IsRunning()) {
        return;
    }
    if (errCode != PRINT_FWK_AGENT_CLIENT_OK) {
        PrinterInfo info = BuildAgentFailureInfo(context.printerName, "ENV_INIT", errCode);
        manager->host_->NotifyPrinterInfoChanged(info);
        return;
    }
    std::string ippUri = result != nullptr && result->ippUri != nullptr ? result->ippUri : "";
    AgentQueueIdentity queue;
    if (ippUri.empty() || !BuildAgentQueueIdentity(ippUri, queue)) {
        PrinterInfo info = BuildAgentFailureInfo(
            context.printerName, "DONE", PRINT_FWK_AGENT_CLIENT_ERR_SERVER);
        manager->host_->NotifyPrinterInfoChanged(info);
        return;
    }
    PendingAgentPrinterMetadata metadata {
        context.source, std::move(queue), context.printerName, context.backendType
    };
    if (!manager->CompleteAddSlotWithPending(std::move(metadata))) {
        return;
    }
    context.reservation->Commit();
    PrinterInfo info = BuildAgentProgressInfo(context.printerName, "DONE", "PENDING_DISCOVERY");
    info.SetUri(ippUri);
    manager->host_->NotifyPrinterInfoChanged(info);
}

void PrintFwkAgentManager::HandleAddDone(int32_t errCode, const PrintAddPrinterResult *result, void *userData)
{
    auto *context = static_cast<AddPrinterContext *>(userData);
    if (context == nullptr) {
        return;
    }

    ProcessAddResult(errCode, result, *context);
    FinishAsyncContext(context);
}

int32_t PrintFwkAgentManager::DeletePrinterFromAgent(const std::string &printerName)
{
    if (!IsRunning() || systemData_ == nullptr) {
        return E_PRINT_RPC_FAILURE;
    }

    std::string standardizedName = PrintUtil::StandardizePrinterName(printerName);
    std::string printerId = systemData_->QueryPrinterIdByStandardizeName(standardizedName);
    PrinterInfo printerInfo;
    PersistedAgentPrinterMetadata metadata;
    if (printerId.empty() || !systemData_->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo) ||
        !AgentPrinterOptionCodec::ParsePersistedMetadata(printerInfo.GetOption(), metadata)) {
        PRINT_HILOGW("DeletePrinterFromAgent missing persisted agent metadata");
        return E_PRINT_INVALID_PRINTER;
    }

    auto context = std::make_unique<RemovePrinterContext>();
    context->manager = this;
    context->finalPrinterName = printerInfo.GetPrinterName();
    context->finalPrinterId = printerId;
    context->source = std::move(metadata.source);
    int32_t ret = E_PRINT_RPC_FAILURE;
    {
        std::lock_guard<std::mutex> lock(lifecycleMutex_);
        if (state_.load() == State::RUNNING && loader_ != nullptr) {
            ret = loader_->RemovePrinter(
                metadata.queueName, metadata.backendType, HandleRemoveDone, context.get());
        }
    }
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
        manager->host_->CommitAgentPrinterDeleted(context->finalPrinterId, context->finalPrinterName);
        manager->ReleaseTrackedSource(context->source);
    }

    FinishAsyncContext(context);
}

} // namespace OHOS::Print
