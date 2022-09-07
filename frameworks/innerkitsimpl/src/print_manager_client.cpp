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

#include "print_manager_client.h"

#include "iservice_registry.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
std::mutex PrintManagerClient::instanceLock_;
sptr<PrintManagerClient> PrintManagerClient::instance_ = nullptr;

PrintManagerClient::PrintManagerClient() : printServiceProxy_(nullptr), deathRecipient_(nullptr) {}

PrintManagerClient::~PrintManagerClient() {}

sptr<PrintManagerClient> PrintManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new PrintManagerClient;
        }
    }
    return instance_;
}

bool PrintManagerClient::On(
    const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient On succeeded.");
    return true;
}

bool PrintManagerClient::Off(const std::string &type)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient Off succeeded.");
    return printServiceProxy_->Off(type);
}

bool PrintManagerClient::RegisterExtCallback(uint32_t callbackId, PrintExtCallback cb)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }

    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return false;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    auto it = extCallbackMap_.find(callbackId);
    if (it == extCallbackMap_.end()) {
        callbackStub = new PrintExtensionCallbackStub;
        if (callbackStub == nullptr) {
            PRINT_HILOGE("Invalid callback stub object.");
            return false;
        }
        callbackStub->SetExtCallback(cb);
        extCallbackMap_.insert(std::make_pair(callbackId, callbackStub));
    } else {
        callbackStub = it->second;
        callbackStub->SetExtCallback(cb);
    }

    bool ret = printServiceProxy_->RegisterExtCallback(callbackId, callbackStub);
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback %{public}s.", ret ? "success" : "failed");
    return ret;
}

bool PrintManagerClient::RegisterExtCallback(uint32_t callbackId, PrintJobCallback cb)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }

    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return false;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    auto it = extCallbackMap_.find(callbackId);
    if (it == extCallbackMap_.end()) {
        callbackStub = new PrintExtensionCallbackStub;
        if (callbackStub == nullptr) {
            PRINT_HILOGE("Invalid callback stub object.");
            return false;
        }
        callbackStub->SetPrintJobCallback(cb);
        extCallbackMap_.insert(std::make_pair(callbackId, callbackStub));
    } else {
        callbackStub = it->second;
        callbackStub->SetPrintJobCallback(cb);
    }

    bool ret = printServiceProxy_->RegisterExtCallback(callbackId, callbackStub);
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback %{public}s.", ret ? "success" : "failed");
    return ret;
}

bool PrintManagerClient::RegisterExtCallback(uint32_t callbackId, PrinterCapabilityCallback cb)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }

    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return false;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    auto it = extCallbackMap_.find(callbackId);
    if (it == extCallbackMap_.end()) {
        callbackStub = new PrintExtensionCallbackStub;
        if (callbackStub == nullptr) {
            PRINT_HILOGE("Invalid callback stub object.");
            return false;
        }
        callbackStub->SetCapabilityCallback(cb);
        extCallbackMap_.insert(std::make_pair(callbackId, callbackStub));
    } else {
        callbackStub = it->second;
        callbackStub->SetCapabilityCallback(cb);
    }

    bool ret = printServiceProxy_->RegisterExtCallback(callbackId, callbackStub);
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback %{public}s.", ret ? "success" : "failed");
    return ret;
}

bool PrintManagerClient::RegisterExtCallback(uint32_t callbackId, PrinterCallback cb)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }

    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return false;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    auto it = extCallbackMap_.find(callbackId);
    if (it == extCallbackMap_.end()) {
        callbackStub = new PrintExtensionCallbackStub;
        if (callbackStub == nullptr) {
            PRINT_HILOGE("Invalid callback stub object.");
            return false;
        }
        callbackStub->SetPrinterCallback(cb);
        extCallbackMap_.insert(std::make_pair(callbackId, callbackStub));
    } else {
        callbackStub = it->second;
        callbackStub->SetPrinterCallback(cb);
    }

    bool ret = printServiceProxy_->RegisterExtCallback(callbackId, callbackStub);
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback %{public}s.", ret ? "success" : "failed");
    return ret;
}

bool PrintManagerClient::UnregisterAllExtCallback()
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }

    bool ret = printServiceProxy_->UnregisterAllExtCallback();
    PRINT_HILOGD("PrintManagerClient UnregisterAllExtCallback %{public}s.", ret ? "success" : "fail");
    if (ret) {
        extCallbackMap_.clear();
    }
    return ret;
}

sptr<IPrintService> PrintManagerClient::GetPrintServiceProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        PRINT_HILOGE("Getting SystemAbilityManager failed.");
        return nullptr;
    }
    auto systemAbility = systemAbilityManager->GetSystemAbility(PRINT_SERVICE_ID, "");
    if (systemAbility == nullptr) {
        PRINT_HILOGE("Get SystemAbility failed.");
        return nullptr;
    }
    deathRecipient_ = new PrintSaDeathRecipient();
    systemAbility->AddDeathRecipient(deathRecipient_);
    sptr<IPrintService> serviceProxy = iface_cast<IPrintService>(systemAbility);
    if (serviceProxy == nullptr) {
        PRINT_HILOGE("Get PrintManagerClientProxy from SA failed.");
        return nullptr;
    }
    PRINT_HILOGD("Getting PrintManagerClientProxy succeeded.");
    return serviceProxy;
}

void PrintManagerClient::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    printServiceProxy_ = GetPrintServiceProxy();
}

int32_t PrintManagerClient::StartPrint()
{
    PRINT_HILOGD("PrintManagerClient EnqueueTask start.");

    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StartPrint quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient StartPrint succeeded.");
    return printServiceProxy_->StartPrint();
}

bool PrintManagerClient::ConnectPrinter(uint32_t printerId)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("AddPrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient AddPrinters succeeded.");
    return printServiceProxy_->ConnectPrinter(printerId);
}

bool PrintManagerClient::DisconnectPrinter(uint32_t printerId)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("DisconnectPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient DisconnectPrinter succeeded.");
    return printServiceProxy_->DisconnectPrinter(printerId);
}

bool PrintManagerClient::QueryAllExtension(std::vector<PrintExtensionInfo> &arrayExtensionInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("QueryAllExtension quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient QueryAllExtension succeeded.");
    return printServiceProxy_->QueryAllExtension(arrayExtensionInfo);
}

bool PrintManagerClient::StartDiscoverPrinter(std::vector<uint32_t> extensionList)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StartDiscoverPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient StartDiscoverPrinter succeeded.");
    return printServiceProxy_->StartDiscoverPrinter(extensionList);
}

bool PrintManagerClient::StopDiscoverPrinter()
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StopDiscoverPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient StopDiscoverPrint succeeded.");
    return printServiceProxy_->StopDiscoverPrinter();
}

bool PrintManagerClient::StartPrintJob(const PrintJob &jobinfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StartPrintJob quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient StartPrintJob succeeded.");
    return printServiceProxy_->StartPrintJob(jobinfo);
}

bool PrintManagerClient::CancelPrintJob(const PrintJob &jobinfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("CancelPrintJob quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient CancelPrintJob succeeded.");
    return printServiceProxy_->CancelPrintJob(jobinfo);
} 

bool PrintManagerClient::AddPrinters(std::vector<PrinterInfo> arrayPrintInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("AddPrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient AddPrinters succeeded.");
    return printServiceProxy_->AddPrinters(arrayPrintInfo);
}

bool PrintManagerClient::RemovePrinters(std::vector<PrinterInfo> arrayPrintInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("RemovePrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient RemovePrinters succeeded.");
    return printServiceProxy_->RemovePrinters(arrayPrintInfo);
}

bool PrintManagerClient::UpdatePrinterState(uint32_t printerId, uint32_t state)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("UpdatePrinterState quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient UpdatePrinterState succeeded.");
    return printServiceProxy_->UpdatePrinterState(printerId, state);
}

bool PrintManagerClient::UpdatePrinterJobState(uint32_t jobId, uint32_t state)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("UpdatePrinterJobState quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient UpdatePrinterJobState succeeded.");
    return printServiceProxy_->UpdatePrinterJobState(jobId, state);
}

bool PrintManagerClient::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("RequestPreview quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient RequestPreview succeeded.");
    return printServiceProxy_->RequestPreview(jobinfo, previewResult);
}

bool PrintManagerClient::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("QueryPrinterCapability quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient QueryPrinterCapability succeeded.");
    return printServiceProxy_->QueryPrinterCapability(printerId, printerCapability);
}

bool PrintManagerClient::CheckPermission()
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManagerClient CheckPermission succeeded.");
    PRINT_HILOGD("Check Permission enable");
    return printServiceProxy_->CheckPermission();
}

bool PrintManagerClient::LoadServer()
{
    if (ready_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (ready_) {
        return true;
    }

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
    PRINT_HILOGE("load print server success");
}

void PrintManagerClient::LoadServerFail()
{
    ready_ = false;
    PRINT_HILOGE("load print server fail");
}
} // namespace OHOS::Print
