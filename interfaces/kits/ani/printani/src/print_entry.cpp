/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "print_entry.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_manager_client.h"
#include "print_utils.h"
#include "ability.h"
#include "ui_ability_thread.h"
#include "fd_list_wrapper.h"
#include "print_ets_ui_callback.h"

namespace OHOS::Print {
static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string UI_EXTENSION_TYPE_NAME = "ability.want.params.uiExtensionType";
static const std::string PRINT_UI_EXTENSION_TYPE = "sysDialog/print";
static const std::string CALLER_PKG_NAME = "caller.pkgName";
static const std::string ABILITY_PARAMS_STREAM = "ability.params.stream";
static const int32_t MAX_FILE_LIST_SIZE = 100;

PrintEntry& PrintEntry::GetInstance()
{
    static PrintEntry instance;
    return instance;
}

int32_t PrintEntry::StartPrintWithContext(const std::vector<std::string>& files,
    std::shared_ptr<AbilityRuntime::Context> ctx)
{
    if (files.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    FdListWrapper fdList;
    if (files.begin()->find("fd://") == 0) {
        PRINT_HILOGD("list type: fdlist");
        for (auto fdPath : files) {
            uint32_t fd = PrintUtils::GetIdFromFdPath(fdPath);
            fdList.Add(fd);
        }
    } else {
        PRINT_HILOGD("list type: filelist");
        for (auto file : files) {
            int32_t fd = PrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList.Add(fd);
        }
    }
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    std::string jobId = PrintUtils::GetPrintJobId();
    adapterParam->jobId = jobId;
    adapterParam->documentName = "";
    adapterParam->isCheckFdList = true;
    uint32_t ret = CallSpooler(adapterParam, files, ctx);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler fail");
        return ret;
    }
    return PrintManagerClient::GetInstance()->StartPrint(files, fdList.Get(), jobId);
}

int32_t PrintEntry::StartPrintWithAttributes(const std::string& jobName, std::shared_ptr<AbilityRuntime::Context> ctx,
    const PrintAttributes& attributes, const sptr<IPrintCallback> &listener)
{
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(ctx);
    sptr<IRemoteObject> callerToken = abilityContext->GetToken();
    std::string jobId = PrintUtils::GetPrintJobId();
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->documentName = jobName;
    adapterParam->isCheckFdList = false;
    adapterParam->printAttributes = attributes;
    adapterParam->jobId = jobId;
    uint32_t ret = CallSpooler(adapterParam, {}, ctx);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler fail");
        return ret;
    }
    return PrintManagerClient::GetInstance()->Print(
        jobName, listener, attributes, jobId, callerToken);
}

int32_t PrintEntry::On(const std::string& type, const sptr<IPrintCallback> &listener)
{
    PRINT_HILOGI("PrintEntry On");
    int32_t ret = PrintManagerClient::GetInstance()->On("", type, listener);
    return ret;
}

int32_t PrintEntry::Off(const std::string& type)
{
    PRINT_HILOGI("PrintEntry Off");
    int32_t ret = PrintManagerClient::GetInstance()->Off("", type);
    return ret;
}

OHOS::Ace::UIContent* PrintEntry::GetUIContent(std::shared_ptr<OHOS::AbilityRuntime::Context> ctx)
{
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(ctx);
    if (abilityContext != nullptr) {
        return abilityContext->GetUIContent();
    }
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> uiExtensionContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(ctx);
    if (uiExtensionContext != nullptr) {
        return uiExtensionContext->GetUIContent();
    }
    return nullptr;
}

uint32_t PrintEntry::CallSpooler(const std::shared_ptr<AdapterParam>& adapterParam,
    const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx)
{
    if (adapterParam == nullptr || ctx == nullptr) {
        PRINT_HILOGE("Invalid parameters");
        return E_PRINT_INVALID_PARAMETER;
    }
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, adapterParam->jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, files);
    if (!files.empty() && files.size() <= MAX_FILE_LIST_SIZE) {
        want.SetParam(LAUNCH_PARAMETER_FILE_LIST, files);
        want.SetParam(ABILITY_PARAMS_STREAM, files);
    }
    PrintUtils::BuildAdapterParam(adapterParam, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(CALLER_PKG_NAME, PrintUtils::GetBundleNameForUid(IPCSkeleton::GetCallingUid()));
    want.SetParam(UI_EXTENSION_TYPE_NAME, PRINT_UI_EXTENSION_TYPE);
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION);
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    auto uiContent = GetUIContent(ctx);
    if (uiContent == nullptr) {
        PRINT_HILOGE("GetUIContent failed");
        return E_PRINT_GENERIC_FAILURE;
    }
    auto callback = std::make_shared<PrintEtsUICallback>(uiContent);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [callback](int32_t releaseCode) { callback->OnRelease(releaseCode); },
        [callback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            callback->OnResultForModal(resultCode, result);
        },
        [callback](const OHOS::AAFwk::WantParams& request) { callback->OnReceive(request); },
        [callback](int32_t code, const std::string& name, const std::string& message) {
            callback->OnError(code, name, message);
        }
    };
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, config);
    callback->SetSessionId(sessionId);
    PRINT_HILOGD("Created session: %{public}d", sessionId);

    return E_PRINT_NONE;
}

int32_t PrintEntry::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    PRINT_HILOGI("enter QueryAllExtension.");
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    return ret;
}

int32_t PrintEntry::CancelPrintJob(const std::string &jobId)
{
    PRINT_HILOGI("enter CancelPrintJob.");
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    return ret;
}

int32_t PrintEntry::StartDiscoverPrinter(const std::vector<std::string>& extensionList)
{
    PRINT_HILOGI("enter StartDiscoverPrinter.");
    return PrintManagerClient::GetInstance()->StartDiscoverPrinter(extensionList);
}

int32_t PrintEntry::StopDiscoverPrinter()
{
    PRINT_HILOGI("enter StopDiscoverPrinter.");
    return PrintManagerClient::GetInstance()->StopDiscoverPrinter();
}

int32_t PrintEntry::ConnectPrinter(const std::string& printerId)
{
    PRINT_HILOGI("enter ConnectPrinter.");
    return PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
}

int32_t PrintEntry::DisconnectPrinter(const std::string& printerId)
{
    PRINT_HILOGI("enter DisconnectPrinter.");
    return PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
}

int32_t PrintEntry::QueryPrinterCapability(const std::string& printerId)
{
    PRINT_HILOGI("enter QueryPrinterCapability.");
    return PrintManagerClient::GetInstance()->QueryPrinterCapability(printerId);
}

int32_t PrintEntry::StartPrintJob(PrintJob& jobInfo)
{
    PRINT_HILOGI("enter StartPrintJob.");
    return PrintManagerClient::GetInstance()->StartPrintJob(jobInfo);
}

int32_t PrintEntry::RequestPrintPreview(PrintJob& jobInfo, int32_t& result)
{
    PRINT_HILOGI("enter RequestPrintPreview.");
    std::string previewResult;
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobInfo, previewResult);
    if (ret == E_PRINT_NONE) {
        result = std::stoi(previewResult);
    }
    return ret;
}

int32_t PrintEntry::AddPrinters(const std::vector<PrinterInfo>& printers)
{
    PRINT_HILOGI("enter AddPrinters.");
    return PrintManagerClient::GetInstance()->AddPrinters(printers);
}

int32_t PrintEntry::RemovePrinters(const std::vector<std::string>& printerIds)
{
    PRINT_HILOGI("enter RemovePrinters.");
    return PrintManagerClient::GetInstance()->RemovePrinters(printerIds);
}

int32_t PrintEntry::UpdatePrinters(const std::vector<PrinterInfo>& printers)
{
    PRINT_HILOGI("enter UpdatePrinters.");
    return PrintManagerClient::GetInstance()->UpdatePrinters(printers);
}

int32_t PrintEntry::UpdatePrinterState(const std::string& printerId, uint32_t state)
{
    PRINT_HILOGI("enter UpdatePrinterState.");
    return PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
}

int32_t PrintEntry::UpdatePrintJobState(const std::string& jobId, uint32_t state, uint32_t subState)
{
    PRINT_HILOGI("enter UpdatePrintJobState.");
    return PrintManagerClient::GetInstance()->UpdatePrintJobStateForNormalApp(jobId, state, subState);
}

int32_t PrintEntry::UpdateExtensionInfo(const std::string& info)
{
    PRINT_HILOGI("enter UpdateExtensionInfo.");
    return PrintManagerClient::GetInstance()->UpdateExtensionInfo(info);
}

int32_t PrintEntry::QueryAllPrintJobs(std::vector<PrintJob>& jobs)
{
    PRINT_HILOGI("enter QueryAllPrintJobs.");
    return PrintManagerClient::GetInstance()->QueryAllPrintJob(jobs);
}

int32_t PrintEntry::QueryPrintJobList(std::vector<PrintJob>& jobs)
{
    PRINT_HILOGI("enter QueryPrintJobList.");
    // 使用QueryAllPrintJob作为实现，如有不同可调整
    return PrintManagerClient::GetInstance()->QueryAllPrintJob(jobs);
}

int32_t PrintEntry::QueryPrintJobById(std::string& jobId, PrintJob& job)
{
    PRINT_HILOGI("enter QueryPrintJobById.");
    return PrintManagerClient::GetInstance()->QueryPrintJobById(jobId, job);
}

int32_t PrintEntry::StartGettingPrintFile(const std::string& jobId, const PrintAttributes& attrs, uint32_t fd)
{
    PRINT_HILOGI("enter StartGettingPrintFile.");
    return PrintManagerClient::GetInstance()->StartGetPrintFile(jobId, attrs, fd);
}

int32_t PrintEntry::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    PRINT_HILOGI("enter NotifyPrintService with state.");
    return PrintManagerClient::GetInstance()->NotifyPrintService(jobId, type);
}

int32_t PrintEntry::GetAddedPrinters(std::vector<std::string>& printers)
{
    PRINT_HILOGI("enter GetAddedPrinters.");
    return PrintManagerClient::GetInstance()->QueryAddedPrinter(printers);
}

int32_t PrintEntry::GetPrinterInfoById(const std::string& printerId, PrinterInfo& info)
{
    PRINT_HILOGI("enter GetPrinterInfoById.");
    return PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
}

int32_t PrintEntry::NotifyPrintServiceEvent(uint32_t event)
{
    PRINT_HILOGI("enter NotifyPrintServiceEvent.");
    std::string jobId;
    return PrintManagerClient::GetInstance()->NotifyPrintServiceEvent(jobId, event);
}

int32_t PrintEntry::AddPrinterToDiscovery(const PrinterInfo& printerInfo)
{
    PRINT_HILOGI("enter AddPrinterToDiscovery.");
    return PrintManagerClient::GetInstance()->AddPrinterToDiscovery(printerInfo);
}

int32_t PrintEntry::UpdatePrinterInDiscovery(const PrinterInfo& printerInfo)
{
    PRINT_HILOGI("enter UpdatePrinterInDiscovery.");
    return PrintManagerClient::GetInstance()->UpdatePrinterInDiscovery(printerInfo);
}

int32_t PrintEntry::RemovePrinterFromDiscovery(const std::string& printerId)
{
    PRINT_HILOGI("enter RemovePrinterFromDiscovery.");
    return PrintManagerClient::GetInstance()->RemovePrinterFromDiscovery(printerId);
}

int32_t PrintEntry::QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info)
{
    PRINT_HILOGI("enter QueryPrinterInfoByPrinterId.");
    return PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
}

} // namespace OHOS::Print
