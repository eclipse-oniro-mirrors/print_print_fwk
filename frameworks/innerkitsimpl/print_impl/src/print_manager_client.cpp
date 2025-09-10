/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "napi/native_common.h"
#include "ui_content.h"
#include "ipc_skeleton.h"
#include "want.h"
#include "bundle_mgr_client.h"

#include "print_manager_client.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "print_utils.h"
#include "print_callback.h"
#include "print_innerkit_modal_ui_callback.h"

namespace OHOS::Print {

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string TOKEN_KEY = "ohos.ability.params.token";
static const std::string UI_EXTENSION_TYPE_NAME = "ability.want.params.uiExtensionType";
static const std::string PRINT_UI_EXTENSION_TYPE = "sysDialog/print";
static const std::string CALLER_PKG_NAME = "caller.pkgName";

PrintManagerClient::PrintManagerClient() : printServiceProxy_(nullptr), deathRecipient_(nullptr) {}

PrintManagerClient::~PrintManagerClient() {}

PrintManagerClient* PrintManagerClient::GetInstance()
{
    static PrintManagerClient instance;
    return &instance;
}

bool PrintManagerClient::GetPrintServiceProxy()
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    if (printServiceProxy_ != nullptr) {
        PRINT_HILOGD("printServiceProxy_ is not null");
        return true;
    }
    bool result = false;
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager != nullptr) {
        auto systemAbility = systemAbilityManager->GetSystemAbility(PRINT_SERVICE_ID, "");
        if (systemAbility != nullptr) {
            deathRecipient_ = new (std::nothrow) PrintSaDeathRecipient();
            if (deathRecipient_ != nullptr) {
                systemAbility->AddDeathRecipient(deathRecipient_);
                printServiceProxy_ = iface_cast<IPrintService>(systemAbility);
                PRINT_HILOGD("Getting PrintManagerClientProxy succeeded.");
                result = true;
            }
        }
    }
    PRINT_HILOGD("Getting PrintManagerClientProxy ret[%{public}d].", result);
    return result;
}

void PrintManagerClient::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("OnRemoteSaDied start");
    if (remote == nullptr) {
        PRINT_HILOGE("remote is nullptr");
        return;
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("printServiceProxy_ is null");
        return;
    }
    auto serviceRemote = printServiceProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        PRINT_HILOGD("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        printServiceProxy_ = nullptr;
        deathRecipient_ = nullptr;
        std::unique_lock<std::mutex> lock(conditionMutex_);
        ready_ = false;
    }
}

int32_t PrintManagerClient::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StartPrint start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartPrint(fileList, fdList, taskId);
        PRINT_HILOGD("PrintManagerClient StartPrint out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StopPrint(const std::string &taskId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StopPrint start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StopPrint(taskId);
        PRINT_HILOGD("PrintManagerClient StopPrint out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::ConnectPrinter(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient ConnectPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->ConnectPrinter(printerId);
        PRINT_HILOGD("PrintManagerClient ConnectPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::DisconnectPrinter(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient DisconnectPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->DisconnectPrinter(printerId);
        PRINT_HILOGD("PrintManagerClient DisconnectPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryAllExtension start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAllExtension(extensionInfos);
        PRINT_HILOGD("PrintManagerClient QueryAllExtension out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartDiscoverPrinter(const std::vector<std::string> &extensionList)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StartDiscoverPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartDiscoverPrinter(extensionList);
        PRINT_HILOGD("PrintManagerClient StartDiscoverPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StopDiscoverPrinter()
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StopDiscoverPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StopDiscoverPrinter();
        PRINT_HILOGD("PrintManagerClient StopDiscoverPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartPrintJob(PrintJob &jobinfo)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StartPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartPrintJob(jobinfo);
        PRINT_HILOGD("PrintManagerClient StartPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::CancelPrintJob(const std::string &jobId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient CancelPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->CancelPrintJob(jobId);
        PRINT_HILOGD("PrintManagerClient CancelPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RestartPrintJob(const std::string &jobId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient RestartPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RestartPrintJob(jobId);
        PRINT_HILOGD("PrintManagerClient RestartPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient AddPrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AddPrinters(printerInfos);
        PRINT_HILOGD("PrintManagerClient AddPrinters out ret = [%{public}d].", ret);
    }
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to query printerList");
    }
    return ret;
}

int32_t PrintManagerClient::RemovePrinters(const std::vector<std::string> &printerIds)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient RemovePrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RemovePrinters(printerIds);
        PRINT_HILOGD("PrintManagerClient RemovePrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient UpdatePrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinters(printerInfos);
        PRINT_HILOGD("PrintManagerClient UpdatePrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinterState(const std::string &printerId, uint32_t state)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient UpdatePrinterState start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinterState(printerId, state);
        PRINT_HILOGD("PrintManagerClient UpdatePrinterState out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrintJobStateForNormalApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGI("PrintManagerClient UpdatePrintJobStateForNormalApp start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrintJobStateForNormalApp(jobId, state, subState);
        PRINT_HILOGI("PrintManagerClient UpdatePrintJobStateForNormalApp out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrintJobStateOnlyForSystemApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient UpdatePrintJobStateOnlyForSystemApp start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
        PRINT_HILOGD("PrintManagerClient UpdatePrintJobStateOnlyForSystemApp out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdateExtensionInfo(const std::string &extInfo)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient UpdateExtensionInfo start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdateExtensionInfo(extInfo);
        PRINT_HILOGD("PrintManagerClient UpdateExtensionInfo out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient RequestPreview start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RequestPreview(jobinfo, previewResult);
        PRINT_HILOGD("PrintManagerClient RequestPreview out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterCapability(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryPrinterCapability start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterCapability(printerId);
        PRINT_HILOGD("PrintManagerClient QueryPrinterCapability out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryPrinterInfoByPrinterId start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterInfoByPrinterId(printerId, info);
        PRINT_HILOGD("PrintManagerClient QueryPrinterInfoByPrinterId out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryAddedPrinter(std::vector<std::string> &printerNameList)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryAddedPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAddedPrinter(printerNameList);
        PRINT_HILOGD("PrintManagerClient QueryAddedPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterProperties(const std::string &printerId,
    const std::vector<std::string> &keyList, std::vector<std::string> &valueList)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryPrinterProperties start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterProperties(printerId, keyList, valueList);
        PRINT_HILOGD("PrintManagerClient QueryPrinterProperties out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartNativePrintJob(PrintJob &printJob)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient StartNativePrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartNativePrintJob(printJob);
        PRINT_HILOGD("PrintManagerClient QueryPrinterProperties out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::SetPrinterPreference(
    const std::string &printerId, const PrinterPreferences &printerPreference)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGI("PrintManagerClient SetPrinterPreference start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->SetPrinterPreference(printerId, printerPreference);
        PRINT_HILOGI("PrintManagerClient SetPrinterPreference out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AddPrinterToDiscovery(const PrinterInfo &printerInfo)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient AddPrinterToDiscovery start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AddPrinterToDiscovery(printerInfo);
        PRINT_HILOGD("PrintManagerClient AddPrinterToDiscovery out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinterInDiscovery(const PrinterInfo &printerInfo)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    printerInfo.Dump();

    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinterInDiscovery(printerInfo);
        PRINT_HILOGD("PrintManagerClient UpdatePrinterInDiscovery out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RemovePrinterFromDiscovery(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient RemovePrinterFromDiscovery start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RemovePrinterFromDiscovery(printerId);
        PRINT_HILOGD("PrintManagerClient RemovePrinterFromDiscovery out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinterInSystem(const PrinterInfo &printerInfo)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    printerInfo.Dump();

    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinterInSystem(printerInfo);
        PRINT_HILOGD("PrintManagerClient UpdatePrinterInSystem out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AnalyzePrintEvents(const std::string &printerId, const std::string &type, std::string &detail)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AnalyzePrintEvents(printerId, type, detail);
        PRINT_HILOGI("PrintManagerClient AnalyzePrintEvents out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryAllPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAllPrintJob(printJobs);
        PRINT_HILOGD("PrintManagerClient QueryAllPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}


int32_t PrintManagerClient::QueryAllActivePrintJob(std::vector<PrintJob> &printJobs)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryAllActivePrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAllActivePrintJob(printJobs);
        PRINT_HILOGD("PrintManagerClient QueryAllActivePrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrintJobById(std::string &printJobId, PrintJob &printjob)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryPrintJobById start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrintJobById(printJobId, printjob);
        PRINT_HILOGD("PrintManagerClient QueryPrintJobById out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient AddPrinterToCups start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AddPrinterToCups(printerUri, printerName, printerMake);
        PRINT_HILOGD("PrintManagerClient AddPrinterToCups out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient QueryPrinterCapabilityByUri start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
        PRINT_HILOGD("PrintManagerClient QueryPrinterCapabilityByUri out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::NotifyPrintServiceEvent(std::string &jobId, uint32_t event)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient NotifyPrintServiceEvent start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->NotifyPrintServiceEvent(jobId, event);
        PRINT_HILOGD("PrintManagerClient NotifyPrintServiceEvent out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::SetDefaultPrinter(const std::string &printerId, uint32_t type)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient SetDefaultPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->SetDefaultPrinter(printerId, type);
        PRINT_HILOGD("PrintManagerClient SetDefaultPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::DeletePrinterFromCups(const std::string &printerName)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient DeletePrinterFromCups start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->DeletePrinterFromCups(printerName);
        PRINT_HILOGD("PrintManagerClient DeletePrinterFromCups out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::DiscoverUsbPrinters(std::vector<PrinterInfo> &printers)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient DiscoverUsbPrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->DiscoverUsbPrinters(printers);
        PRINT_HILOGD("PrintManagerClient DiscoverUsbPrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::On(const std::string &taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient On start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->On(taskId, type, listener);
        PRINT_HILOGD("PrintManagerClient On out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::Off(const std::string &taskId, const std::string &type)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient Off start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->Off(taskId, type);
        PRINT_HILOGD("PrintManagerClient Off out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const std::shared_ptr<PrintAttributes> &printAttributes)
{
    std::string taskId = "";
    return Print(printJobName, listener, *printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const std::shared_ptr<PrintAttributes> &printAttributes, void* contextToken)
{
    std::string taskId = "";
    return Print(printJobName, listener, *printAttributes, taskId, contextToken);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes)
{
    std::string taskId = "";
    return Print(printJobName, listener, printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, void* contextToken)
{
    std::string taskId = "";
    return Print(printJobName, listener, printAttributes, taskId, contextToken);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, std::string &taskId)
{
    return Print(printJobName, listener, printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, std::string &taskId, void* uiContent)
{
    if (uiContent == nullptr) {
        PRINT_HILOGE("uiContent is nullptr.");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGI("PrintManagerClient Print start.");
    if (taskId.empty()) {
        taskId = PrintUtils::GetPrintJobId();
        std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
        if (adapterParam == nullptr) {
            PRINT_HILOGE("create adapterParam failed.");
            return E_PRINT_SERVER_FAILURE;
        }
        adapterParam->documentName = printJobName;
        adapterParam->isCheckFdList = false;
        adapterParam->printAttributes = printAttributes;
        AAFwk::Want want;
        SetWantParam(want, taskId);
        PrintUtils::BuildAdapterParam(adapterParam, want);

        OHOS::Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        auto printUiContent = static_cast<OHOS::Ace::UIContent *>(uiContent);
        auto callback = std::make_shared<PrintInnerkitModalUICallback>(printUiContent);
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
        int32_t sessionId = printUiContent->CreateModalUIExtension(want, extensionCallbacks, config);
        PRINT_HILOGI("StartUIExtensionAbility sessionId %{public}d", sessionId);
        if (callback != nullptr) {
            callback->SetSessionId(sessionId);
        }
    }

    auto func = [printJobName, listener, printAttributes, &taskId](sptr<IPrintService> serviceProxy) {
        serviceProxy->On("", PRINT_CALLBACK_ADAPTER, listener);
        return serviceProxy->PrintByAdapter(printJobName, printAttributes, taskId);
    };
    return CALL_COMMON_CLIENT(func);
}

void PrintManagerClient::SetWantParam(AAFwk::Want &want, std::string &taskId)
{
    std::vector<std::string> fileList;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, taskId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string callerPkg = PrintUtils::GetBundleNameForUid(callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    want.SetParam(UI_EXTENSION_TYPE_NAME, PRINT_UI_EXTENSION_TYPE);
    want.SetParam(TOKEN_KEY, true);
}

int32_t PrintManagerClient::StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
    const uint32_t fd)
{
    auto func = [jobId, printAttributes, fd](sptr<IPrintService> serviceProxy) {
        return serviceProxy->StartGetPrintFile(jobId, printAttributes, fd);
    };
    return CALL_COMMON_CLIENT(func);
}

int32_t PrintManagerClient::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient NotifyPrintService start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->NotifyPrintService(jobId, type);
        PRINT_HILOGD("PrintManagerClient NotifyPrintService out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::runBase(const char* callerFunName, std::function<int32_t(sptr<IPrintService>)> func)
{
    PRINT_HILOGI("PrintManagerClient %{public}s start.", callerFunName);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (!LoadServer()) {
        PRINT_HILOGE("LoadServer error");
        return ret;
    }

    if (!GetPrintServiceProxy()) {
        PRINT_HILOGE("GetPrintServiceProxy error");
        return ret;
    }

    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    ret = func(printServiceProxy_);
    PRINT_HILOGI("PrintManagerClient %{public}s end ret = [%{public}d].", callerFunName, ret);
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrintExtCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetExtCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetExtCallback(cb);
    }
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrintJobCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetPrintJobCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetPrintJobCallback(cb);
    }
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrinterCapabilityCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetCapabilityCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetCapabilityCallback(cb);
    }
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrinterCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetPrinterCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetPrinterCallback(cb);
    }
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UnregisterAllExtCallback(const std::string &extensionId)
{
    int32_t ret = E_PRINT_RPC_FAILURE;
    {
        std::lock_guard<std::recursive_mutex> lock(proxyLock_);
        PRINT_HILOGD("PrintManagerClient UnregisterAllExtCallback start.");
        if (LoadServer() && GetPrintServiceProxy()) {
            ret = printServiceProxy_->UnregisterAllExtCallback(extensionId);
            PRINT_HILOGD("PrintManagerClient UnregisterAllExtCallback out ret = [%{public}d].", ret);
        }
    }
    extCallbackMap_.clear();
    return ret;
}

int32_t PrintManagerClient::SetNativePrinterChangeCallback(const std::string &type, NativePrinterChangeCallback cb)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    int32_t ret = E_PRINT_RPC_FAILURE;
    PRINT_HILOGI("PrintManagerClient SetNativePrinterChangeCallback start");
    if (LoadServer() && GetPrintServiceProxy()) {
        if (cb != nullptr) {
            sptr<PrintCallback> callback = new (std::nothrow) PrintCallback;
            if (callback != nullptr) {
                callback->SetNativePrinterChangeCallback(cb);
                ret = printServiceProxy_->RegisterPrinterCallback(type, callback);
            } else {
                ret = E_PRINT_GENERIC_FAILURE;
            }
        } else {
            ret = printServiceProxy_->UnregisterPrinterCallback(type);
        }
    }
    PRINT_HILOGD("PrintManagerClient SetNativePrinterChangeCallback out ret = [%{public}d].", ret);
    return ret;
}

int32_t PrintManagerClient::LoadExtSuccess(const std::string &extensionId)
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGD("PrintManagerClient LoadExtSuccess start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->LoadExtSuccess(extensionId);
        PRINT_HILOGD("PrintManagerClient LoadExtSuccess out ret = [%{public}d].", ret);
    }
    return ret;
}

bool PrintManagerClient::LoadServer()
{
    {
        std::unique_lock<std::mutex> lock(conditionMutex_);
        if (ready_) {
            return true;
        }
    }

    std::lock_guard<std::mutex> lock(loadMutex_);
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        PRINT_HILOGE("GetSystemAbilityManager return null");
        return false;
    }

    sptr<PrintSyncLoadCallback> loadCallback_ = new (std::nothrow) PrintSyncLoadCallback();
    if (loadCallback_ == nullptr) {
        PRINT_HILOGE("new PrintSyncLoadCallback fail");
        return false;
    }

    int32_t result = sm->LoadSystemAbility(PRINT_SERVICE_ID, loadCallback_);
    if (result != ERR_OK) {
        PRINT_HILOGE("LoadSystemAbility %{public}d failed, result: %{public}d", PRINT_SERVICE_ID, result);
        return false;
    }

    {
        std::unique_lock<std::mutex> conditionLock(conditionMutex_);
        auto waitStatus = syncCon_.wait_for(
            conditionLock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS), [this]() { return ready_; });
        if (!waitStatus) {
            PRINT_HILOGE("print server load sa timeout");
            return false;
        }
    }
    return true;
}

void PrintManagerClient::LoadServerSuccess()
{
    std::unique_lock<std::mutex> lock(conditionMutex_);
    ready_ = true;
    syncCon_.notify_one();
    PRINT_HILOGD("load print server success");
}

void PrintManagerClient::LoadServerFail()
{
    std::unique_lock<std::mutex> lock(conditionMutex_);
    ready_ = false;
    PRINT_HILOGE("load print server fail");
}
void PrintManagerClient::SetProxy(const sptr<IRemoteObject> &obj)
{
    if (printServiceProxy_ != nullptr) {
        auto serviceRemote = printServiceProxy_->AsObject();
        if (serviceRemote != nullptr) {
            serviceRemote->RemoveDeathRecipient(deathRecipient_);
            printServiceProxy_ = nullptr;
            deathRecipient_ = nullptr;
        }
    }
    deathRecipient_ = new (std::nothrow) PrintSaDeathRecipient();
    if (deathRecipient_ != nullptr) {
        obj->AddDeathRecipient(deathRecipient_);
        PRINT_HILOGD("Getting PrintManagerClientProxy succeeded.");
    }
    printServiceProxy_ = iface_cast<IPrintService>(obj);
}
void PrintManagerClient::ResetProxy()
{
    printServiceProxy_ = nullptr;
}

int32_t PrintManagerClient::Init()
{
    std::lock_guard<std::recursive_mutex> lock(proxyLock_);
    PRINT_HILOGI("nativePrint Init start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartService();
    }
    PRINT_HILOGD("PrintManagerClient Init out ret = [%{public}d].", ret);
    return ret;
}

int32_t PrintManagerClient::Release()
{
    SetNativePrinterChangeCallback(PRINTER_DISCOVER_EVENT_TYPE, nullptr);
    SetNativePrinterChangeCallback(PRINTER_CHANGE_EVENT_TYPE, nullptr);
    return E_PRINT_NONE;
}
} // namespace OHOS::Print
