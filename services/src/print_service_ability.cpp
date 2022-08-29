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
#include "print_service_ability.h"

#include <cerrno>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#include "core_service_client.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#include "iservice_registry.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "print_service_manager.h"
#include "print_common.h"
#include "log.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;

static const std::string PRINT_PERMISSION_NAME_INTERNET = "ohos.permission.PRINT";
static const std::string PRINT_PERMISSION_NAME_SESSION = "ohos.permission.PRINT_SESSION_MANAGER";


REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);
const std::int64_t INIT_INTERVAL = 5000L;
std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
}

PrintServiceAbility::~PrintServiceAbility()
{
    PRINT_HILOGE("~PrintServiceAbility state_  is %{public}d.", static_cast<int>(state_));
}

sptr<PrintServiceAbility> PrintServiceAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new PrintServiceAbility(PRINT_SERVICE_ID, true);
            PRINT_HILOGE("PrintServiceAbility instance_ create,addr=%{public}p", instance_.GetRefPtr());
        }
    }
    return instance_;
}

int32_t PrintServiceAbility::Init()
{
    bool ret = Publish(PrintServiceAbility::GetInstance());
    if (!ret) {
        PRINT_HILOGE("PrintServiceAbility Publish failed.");
        return E_PRINT_PUBLISH_FAIL;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    uint32_t threadNum = 4;
    PRINT_HILOGI("Start Print Service Manager with %{public}d threas", threadNum);
    PRINT_HILOGE("state_ is %{public}d.", static_cast<int>(state_));
    PRINT_HILOGI("Init PrintServiceAbility success.");
    return ERR_OK;
}

void PrintServiceAbility::OnStart()
{
    PRINT_HILOGI("PrintServiceAbility::Enter OnStart.");
    if (instance_ == nullptr) {
        instance_ = this;
    }
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        PRINT_HILOGI("PrintServiceAbility is already running.");
        return;
    }
    InitServiceHandler();

    int32_t ret = Init();
    if (ret != ERR_OK) {
        auto callback = [=]() { Init(); };
        serviceHandler_->PostTask(callback, INIT_INTERVAL);
        PRINT_HILOGE("PrintServiceAbility Init failed. Try again 5s la00ter");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    return;
}

void PrintServiceAbility::InitServiceHandler()
{
    PRINT_HILOGI("InitServiceHandler started.");
    if (serviceHandler_ != nullptr) {
        PRINT_HILOGI("InitServiceHandler already init.");
        return;
    }
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("PrintServiceAbility");
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    PRINT_HILOGI("InitServiceHandler succeeded.");
}

void PrintServiceAbility::ManualStart()
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        PRINT_HILOGI("PrintServiceAbility restart.");
        OnStart();
    }
}

void PrintServiceAbility::OnStop()
{
    PRINT_HILOGI("OnStop started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return;
    }
    serviceHandler_ = nullptr;
    state_ = ServiceRunningState::STATE_NOT_START;
    PRINT_HILOGI("OnStop end.");
}

int32_t PrintServiceAbility::Dummy()
{
    ManualStart();
    int32_t taskId = -1;
    return taskId;
}

bool PrintServiceAbility::ConnectPrinter(uint32_t printerId)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("PrintServiceAbility ConnectPrinter started.");
    return instance->ConnectPrinter(printerId);
}

bool PrintServiceAbility::DisconnectPrinter(uint32_t printerId)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("DisconnectPrinter ConnectPrinter started.");
    return instance->DisconnectPrinter(printerId);
}

bool PrintServiceAbility::StartDiscoverPrinter(std::vector<uint32_t> extensionList)
{
     ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("StartDiscoverPrinter ConnectPrinter started.");
    return instance->StartDiscoverPrinter(extensionList);
}

bool PrintServiceAbility::StopDiscoverPrinter()
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("StopDiscoverPrinter ConnectPrinter started.");
    return instance->StopDiscoverPrinter();
}

bool PrintServiceAbility::QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("QueryAllExtension ConnectPrinter started.");
    return instance->QueryExtensionAbilityInfos(arrayExtensionInfo);
}

bool PrintServiceAbility::StartPrintJob(PrintJob jobinfo) 
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("StartPrintJob ConnectPrinter started.");
    return instance->StartPrintJob(jobinfo);
}

bool PrintServiceAbility::CancelPrintJob(PrintJob jobinfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob ConnectPrinter started.");
    return instance->CancelPrintJob(jobinfo);
}

bool PrintServiceAbility::AddPrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob ConnectPrinter started.");
    return instance->AddPrinters(arrayPrintInfo);
}

bool PrintServiceAbility::RemovePrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob ConnectPrinter started.");
    return instance->RemovePrinters(arrayPrintInfo);
}

bool PrintServiceAbility::UpdatePrinterState(uint32_t printerId, uint32_t state)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob ConnectPrinter started.");
    return instance->UpdatePrinterState(printerId, state);
}

bool PrintServiceAbility::UpdatePrinterJobState(uint32_t jobId, uint32_t state)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob ConnectPrinter started.");
    return instance->UpdatePrinterJobState(jobId, state);
}

bool PrintServiceAbility::RequestPreview(PrintJob jobinfo, std::string &previewResult)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob RequestPreview started.");
    return instance->RequestPreview(jobinfo, previewResult);
}

bool PrintServiceAbility::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("CancelPrintJob RequestPreview started.");
    return instance->QueryPrinterCapability(printerId, printerCapability);
}

bool PrintServiceAbility::CheckPermission()
{
    return true;
}

bool PrintServiceAbility::On(uint32_t taskId, const std::string &type, const sptr<PrintNotifyInterface> &listener)
{
    std::string combineType = type + "-" + std::to_string(taskId);
    PRINT_HILOGI("PrintServiceAbility::On started. type=%{public}s", combineType.c_str());
    auto iter = registeredListeners_.find(combineType);
    if (iter == registeredListeners_.end()) {
        std::lock_guard<std::mutex> lck(listenerMapMutex_);
        std::pair<std::string, sptr<PrintNotifyInterface>> newObj(combineType, listener);
        const auto temp = registeredListeners_.insert(newObj);
        if (!temp.second) {
            PRINT_HILOGE("PrintServiceAbility::On insert type=%{public}s object fail.", combineType.c_str());
            return false;
        }
    } else {
        std::lock_guard<std::mutex> lck(listenerMapMutex_);
        PRINT_HILOGI("PrintServiceAbility::On Replace listener.");
        registeredListeners_[combineType] = listener;
    }
    PRINT_HILOGI("PrintServiceAbility::On end.");
    return true;
}

bool PrintServiceAbility::Off(uint32_t taskId, const std::string &type)
{
    std::string combineType = type + "-" + std::to_string(taskId);
    PRINT_HILOGI("PrintServiceAbility::Off started.");
    auto iter = registeredListeners_.find(combineType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGE("PrintServiceAbility::Off delete type=%{public}s object message.", combineType.c_str());
        std::lock_guard<std::mutex> lck(listenerMapMutex_);
        registeredListeners_.erase(iter);
        return true;
    }
    return false;
}

void PrintServiceAbility::NotifyHandler(const std::string& type, uint32_t taskId, uint32_t argv1, uint32_t argv2)
{
    std::string combineType = type + "-" + std::to_string(taskId);
    PRINT_HILOGI("PrintServiceAbility::NotifyHandler started %{public}s [%{public}d, %{public}d].",
                    combineType.c_str(), argv1, argv2);
    auto iter = PrintServiceAbility::GetInstance()->registeredListeners_.find(combineType);
    if (iter != PrintServiceAbility::GetInstance()->registeredListeners_.end()) {
        PRINT_HILOGE("PrintServiceAbility::NotifyHandler type=%{public}s object message.", combineType.c_str());
        MessageParcel data;
        data.WriteUint32(argv1);
        data.WriteUint32(argv2);
        iter->second->OnCallBack(data);
    }
}
} // namespace OHOS::Request::Print
