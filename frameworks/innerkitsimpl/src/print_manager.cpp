/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "print_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "log.h"

namespace OHOS::Print {
std::mutex PrintManager::instanceLock_;
sptr<PrintManager> PrintManager::instance_ = nullptr;

PrintManager::PrintManager() : printServiceProxy_(nullptr), deathRecipient_(nullptr) {
}

PrintManager::~PrintManager()
{
}

sptr<PrintManager> PrintManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new PrintManager;
        }
    }
    return instance_;
}

bool PrintManager::On(uint32_t taskId, const std::string &type, const sptr<PrintNotifyInterface> &listener)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager On succeeded.");
    return printServiceProxy_->On(taskId, type, listener);  
}

bool PrintManager::Off(uint32_t taskId, const std::string &type)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager Off succeeded.");
    return printServiceProxy_->Off(taskId, type);   
}

sptr<PrintServiceInterface> PrintManager::GetPrintServiceProxy()
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
    sptr<PrintServiceInterface> serviceProxy = iface_cast<PrintServiceInterface>(systemAbility);
    if (serviceProxy == nullptr) {
        PRINT_HILOGE("Get PrintManagerProxy from SA failed.");
        return nullptr;
    }
    PRINT_HILOGD("Getting PrintManagerProxy succeeded.");
    return serviceProxy;
}

void PrintManager::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    printServiceProxy_ = GetPrintServiceProxy();
}

PrintSaDeathRecipient::PrintSaDeathRecipient()
{
}

void PrintSaDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    PRINT_HILOGE("PrintSaDeathRecipient on remote systemAbility died.");
    PrintManager::GetInstance()->OnRemoteSaDied(object);
}

int32_t PrintManager::Dummy()
{
    return 1;
}

bool PrintManager::ConnectPrinter(uint32_t printerId)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("AddPrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager AddPrinters succeeded.");
    return printServiceProxy_->ConnectPrinter(printerId);
}

bool PrintManager::DisconnectPrinter(uint32_t printerId)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("DisconnectPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager DisconnectPrinter succeeded.");
    return printServiceProxy_->DisconnectPrinter(printerId);
}

bool PrintManager::QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("QueryAllExtension quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager QueryAllExtension succeeded.");
    return printServiceProxy_->QueryAllExtension(arrayExtensionInfo);
}

bool PrintManager::StartDiscoverPrinter(std::vector<uint32_t> extensionList)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StartDiscoverPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager StartDiscoverPrinter succeeded.");
    return printServiceProxy_->StartDiscoverPrinter(extensionList);
}

bool PrintManager::StopDiscoverPrinter()
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StopDiscoverPrinter quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager StopDiscoverPrint succeeded.");
    return printServiceProxy_->StopDiscoverPrinter();
}

bool PrintManager::StartPrintJob(PrintJob jobinfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("StartPrintJob quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager StartPrintJob succeeded.");
    return printServiceProxy_->StartPrintJob(jobinfo);
}

bool PrintManager::CancelPrintJob(PrintJob jobinfo) 
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("CancelPrintJob quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager CancelPrintJob succeeded.");
    return printServiceProxy_->CancelPrintJob(jobinfo);
}////

bool PrintManager::AddPrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("AddPrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager AddPrinters succeeded.");
    return printServiceProxy_->AddPrinters(arrayPrintInfo);
}

bool PrintManager::RemovePrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("RemovePrinters quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager RemovePrinters succeeded.");
    return printServiceProxy_->RemovePrinters(arrayPrintInfo);
}

bool PrintManager::UpdatePrinterState(uint32_t printerId, uint32_t state)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("UpdatePrinterState quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager UpdatePrinterState succeeded.");
    return printServiceProxy_->UpdatePrinterState(printerId, state);
}

bool PrintManager::UpdatePrinterJobState(uint32_t jobId, uint32_t state)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("UpdatePrinterJobState quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager UpdatePrinterJobState succeeded.");
    return printServiceProxy_->UpdatePrinterJobState(jobId, state);
}

bool PrintManager::RequestPreview(PrintJob jobinfo, std::string &previewResult)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("RequestPreview quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager RequestPreview succeeded.");
    return printServiceProxy_->RequestPreview(jobinfo, previewResult);
}

bool PrintManager::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability) 
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("QueryPrinterCapability quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager QueryPrinterCapability succeeded.");
    return printServiceProxy_->QueryPrinterCapability(printerId, printerCapability);
}

bool PrintManager::CheckPermission()
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Resume quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager CheckPermission succeeded.");
    PRINT_HILOGD("Check Permission enable");
    return printServiceProxy_->CheckPermission();
}

bool PrintManager::Print(uint32_t taskId)
{
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGW("Redo GetPrintServiceProxy");
        printServiceProxy_ = GetPrintServiceProxy();
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("Print quit because redoing GetPrintServiceProxy failed.");
        return false;
    }
    PRINT_HILOGD("PrintManager Print succeeded.");
    return true;
}
} // namespace OHOS::Print
