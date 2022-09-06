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
#include "print_service_ability.h"

#include <cerrno>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "core_service_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "print_common.h"
#include "print_log.h"
#include "print_service_manager.h"
#include "printer_info.h"
#include "system_ability.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;

static const std::string PRINT_PERMISSION_NAME_INTERNET = "ohos.permission.PRINT";
static const std::string PRINT_PERMISSION_NAME_SESSION = "ohos.permission.PRINT_SESSION_MANAGER";
static const std::string PRINTEXT_BUNDLE_NAME = "com.open.harmony.packagemag";
static const std::string PRINTEXT_ABILITY_NAME = "com.open.harmony.packagemag.ServiceAbility2";
const uint32_t MAX_RETRY_TIMES = 10;
const uint32_t START_ABILITY_INTERVAL = 6;

REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);
const std::int64_t INIT_INTERVAL = 5000L;
std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START), currentTaskId_(0)
{}

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

int32_t PrintServiceAbility::GetTaskId()
{
    std::lock_guard<std::mutex> autoLock(instanceLock_);
    return currentTaskId_++;
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

int32_t PrintServiceAbility::StartPrint()
{
    ManualStart();
    AAFwk::Want want;
    want.SetElementName(PRINTEXT_BUNDLE_NAME, PRINTEXT_ABILITY_NAME);
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        PRINT_HILOGD("PrintServiceAbility::StartAbility");
        if (AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want) == 0) {
            break;
        }
        break;
        std::this_thread::sleep_for(std::chrono::seconds(START_ABILITY_INTERVAL));
        PRINT_HILOGD("PrintServiceAbility::StartAbility %{public}d", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceAbility::StartAbility --> failed ");
        return -1;
    }

    int32_t taskId = GetTaskId();
    PRINT_HILOGI("PrintServiceAbility Allocatejjjjjj Task[%{public}d] started.", taskId);
    return taskId;
}

bool PrintServiceAbility::ConnectPrinter(uint32_t printerId)
{
    ManualStart();
    PRINT_HILOGD("ConnectPrinter started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_CONNECT_PRINTER);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback(printerId);
    }
    PRINT_HILOGW("ConnectPrinter Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::DisconnectPrinter(uint32_t printerId)
{
    ManualStart();
    PRINT_HILOGD("DisconnectPrinter started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_DISCONNECT_PRINTER);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback(printerId);
    }
    PRINT_HILOGW("DisconnectPrinter Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::StartDiscoverPrinter(const std::vector<uint32_t> &extensionList)
{
    ManualStart();
    PRINT_HILOGD("StartDiscoverPrinter started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_START_DISCOVERY);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback();
    }
    PRINT_HILOGW("StartDiscoverPrinter Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::StopDiscoverPrinter()
{
    ManualStart();
    PRINT_HILOGD("StopDiscoverPrinter started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_STOP_DISCOVERY);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback();
    }
    PRINT_HILOGW("StopDiscoverPrinter Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("QueryAllExtension started.");
    return instance->QueryExtensionAbilityInfos(arrayExtensionInfo);
}

bool PrintServiceAbility::StartPrintJob(const PrintJob &jobinfo)
{
    ManualStart();
    PRINT_HILOGD("StartPrintJob started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_START_PRINT);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback(jobinfo);
    }
    PRINT_HILOGW("StartPrintJob Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::CancelPrintJob(const PrintJob &jobinfo)
{
    ManualStart();
    PRINT_HILOGD("CancelPrintJob started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_CANCEL_PRINT);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback(jobinfo);
    }
    PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::AddPrinters(const std::vector<PrinterInfo> &arrayPrintInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("AddPrinters started.");
    return instance->AddPrinters(arrayPrintInfo);
}

bool PrintServiceAbility::RemovePrinters(const std::vector<PrinterInfo> &arrayPrintInfo)
{
    ManualStart();
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }
    PRINT_HILOGE("RemovePrinters started.");
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
    PRINT_HILOGE("UpdatePrinterState started.");
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
    PRINT_HILOGE("UpdatePrinterJobState started.");
    return instance->UpdatePrinterJobState(jobId, state);
}

bool PrintServiceAbility::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    ManualStart();
    PRINT_HILOGD("RequestPreview started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_REQUEST_PREVIEW);
    if (it != extCallbackMap_.end()) {
        return it->second->OnCallback(jobinfo);
    }
    PRINT_HILOGW("RequestPreview Not Register Yet!!!");
    return false;
}

bool PrintServiceAbility::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability)
{
    ManualStart();
    PRINT_HILOGD("QueryPrinterCapability started.");
    auto it = extCallbackMap_.find(PRINT_EXTCB_REQUEST_CAP);
    bool result = false;
    MessageParcel reply;
    if (it != extCallbackMap_.end()) {
        result = it->second->OnCallback(printerId, reply);
        printerCapability.BuildFromParcel(reply);
    }
    PRINT_HILOGW("QueryPrinterCapability Not Register Yet!!!");
    return result;
}

bool PrintServiceAbility::CheckPermission()
{
    return true;
}

bool PrintServiceAbility::RegisterExtCallback(uint32_t callbackId, const sptr<IPrintExtensionCallback> &listener)
{
    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback started. callbackId=%{public}d", callbackId);
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id");
        return false;
    }
    auto it = extCallbackMap_.find(callbackId);
    if (it == extCallbackMap_.end()) {
        std::lock_guard<std::mutex> lock(listenerMapMutex_);
        extCallbackMap_.insert(std::make_pair(callbackId, listener));
    } else {
        std::lock_guard<std::mutex> lock(listenerMapMutex_);
        PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback Replace listener.");
        extCallbackMap_[callbackId] = listener;
    }
    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback end.");
    return true;
}

bool PrintServiceAbility::UnregisterAllExtCallback()
{
    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback started.");
    std::lock_guard<std::mutex> lock(listenerMapMutex_);
    extCallbackMap_.clear();
    PRINT_HILOGD("PrintServiceAbility::UnregisterAllExtCallback end.");
    return true;
}

bool PrintServiceAbility::On(
    const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener)
{
    std::string combineType = type + "-";
    PRINT_HILOGI("PrintServiceAbility::On started. type=%{public}s", combineType.c_str());
    /*auto iter = registeredListeners_.find(combineType);
    if (iter == registeredListeners_.end()) {
        std::lock_guard<std::mutex> lck(listenerMapMutex_);
        std::pair<std::string, sptr<IPrintCallback>> newObj(combineType, listener);
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
    PRINT_HILOGI("PrintServiceAbility::On end.");*/
    return true;
}

bool PrintServiceAbility::Off(const std::string &type)
{
    std::string combineType = type + "-";
    PRINT_HILOGI("PrintServiceAbility::Off started.type=%{public}s", combineType.c_str());
    /*auto iter = registeredListeners_.find(combineType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGE("PrintServiceAbility::Off delete type=%{public}s object message.", combineType.c_str());
        std::lock_guard<std::mutex> lck(listenerMapMutex_);
        registeredListeners_.erase(iter);
        return true;
    }*/
    return false;
}

void PrintServiceAbility::DataWriteInfo(PrinterInfo info, MessageParcel &data)
{
    /*
        data.WriteString("PrinterInfo");
        data.WriteUint32(info.GetPrintId());
        data.WriteString(info.GetPrinterName());
        data.WriteUint32(info.GetPrinterIcon());
        data.WriteUint32(info.GetPrinterState());
        data.WriteString(info.GetDescription());
        info.Dump();
        uint32_t pageSizeLength = info.GetCapability().GetPageSize().size();
        uint32_t resolutionLength = info.GetCapability().GetResolution().size();
        data.WriteUint32(pageSizeLength);
        data.WriteUint32(resolutionLength);
        data.WriteUint32(info.GetCapability().GetMinMargin().GetTop());
        data.WriteUint32(info.GetCapability().GetMinMargin().GetBottom());
        data.WriteUint32(info.GetCapability().GetMinMargin().GetLeft());
        data.WriteUint32(info.GetCapability().GetMinMargin().GetRight());
        info.GetCapability().GetMinMargin().Dump();
        for(uint32_t i = 0; i < pageSizeLength; i++)
        {
            data.WriteUint32(info.GetCapability().GetPageSize()[i].GetId());
            data.WriteString(info.GetCapability().GetPageSize()[i].GetName());
            data.WriteUint32(info.GetCapability().GetPageSize()[i].GetWidth());
            data.WriteUint32(info.GetCapability().GetPageSize()[i].GetHeight());
            info.GetCapability().GetPageSize()[i].Dump();
        }
        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            data.WriteUint32(info.GetCapability().GetResolution()[i].GetId());
            data.WriteUint32(info.GetCapability().GetResolution()[i].GetHorizontalDpi());
            data.WriteUint32(info.GetCapability().GetResolution()[i].GetVerticalDpi());
            info.GetCapability().GetResolution()[i].Dump();
        }
        data.WriteUint32(info.GetCapability().GetColorMode());
        data.WriteUint32(info.GetCapability().GetDuplexMode());
        info.GetCapability().Dump();
    */
}

void PrintServiceAbility::NotifyPrintStateHandler(const std::string &type, uint32_t state, PrinterInfo info)
{
    std::string combineType = type;
    PRINT_HILOGI("PrintServiceAbility::NotifyHandler combineType %{public}s [%{public}d.", combineType.c_str(), state);
    /*auto iter = registeredListeners_.find(combineType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGE("PrintServiceAbility::NotifyHandler type=%{public}s object message.", combineType.c_str());
        MessageParcel data;
        DataWrite(info, data);
        iter->second->OnCallBack(data);
    }
    if (type == "blocked") {
        std::string notifyType = "notify-block";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWrite(info, data);
            iter2->second->OnCallBack(data);
        }
    }
    if (type == "success") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWrite(info, data);
            iter2->second->OnCallBack(data);
        }
    }
     if (type == "failed") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWrite(info, data);
            iter2->second->OnCallBack(data);
        }
    }
     if (type == "cancelled") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWrite(info, data);
            iter2->second->OnCallBack(data);
        }
    }*/
}

void PrintServiceAbility::DataWriteJob(PrintJob job, MessageParcel &data)
{
    /*
        data.WriteString("PrintJob");
        uint32_t fileLength = job.GetFiles().size();
        data.WriteUint32(fileLength);
        for(uint32_t i = 0; i < fileLength; i++)
        {
            data.WriteString(job.GetFiles()[i]);

        }
        data.WriteUint32(job.GetJobId());
        data.WriteUint32(job.GetPrinterId());
        data.WriteUint32(job.GetJobState());
        data.WriteUint32(job.GetCopyNumber());

        data.WriteUint32(job.GetPageRange().GetStartPage());
        data.WriteUint32(job.GetPageRange().GetEndPage());
        uint32_t pageLength = job.GetPageRange().GetPages().size();
        data.WriteUint32(pageLength);
        for(uint32_t i = 0; i < pageLength; i++)
        {
             data.WriteUint32(job.GetPageRange().GetPages()[i]);
        }

        data.WriteUint32(job.GetIsSequential());

        data.WriteUint32(job.GetPageSize().GetId());
        data.WriteString(job.GetPageSize().GetName());
        data.WriteUint32(job.GetPageSize().GetWidth());
        data.WriteUint32(job.GetPageSize().GetHeight());

        data.WriteUint32(job.GetIsLandscape());
        data.WriteUint32(job.GetColorMode());
        data.WriteUint32(job.GetDuplexMode());

        data.WriteUint32(job.GetMargin().GetTop());
        data.WriteUint32(job.GetMargin().GetBottom());
        data.WriteUint32(job.GetMargin().GetLeft());
        data.WriteUint32(job.GetMargin().GetRight());

        data.WriteString(job.GetPreview().GetResult());
        data.WriteUint32(job.GetPreview().GetPreviewRange().GetStartPage());
        data.WriteUint32(job.GetPreview().GetPreviewRange().GetEndPage());
        uint32_t previewPageLength = job.GetPreview().GetPreviewRange().GetPages().size();
        data.WriteUint32(previewPageLength);
        for(uint32_t i = 0; i < previewPageLength; i++)
        {
             data.WriteUint32(job.GetPreview().GetPreviewRange().GetPages()[i]);
        }
    */
}

void PrintServiceAbility::NotifyJobStateHandler(const std::string &type, uint32_t state, PrintJob job)
{
    std::string combineType = type;
    PRINT_HILOGI("PrintServiceAbility::NotifyHandler combineType %{public}s [%{public}d.", combineType.c_str(), state);
    /*auto iter = registeredListeners_.find(combineType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGE("PrintServiceAbility::NotifyHandler type=%{public}s object message.", combineType.c_str());
        MessageParcel data;
        DataWriteJob(job, data);
        iter->second->OnCallBack(data);
    }
    if (type == "blocked") {
        std::string notifyType = "notify-block";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWriteJob(job, data);
            iter2->second->OnCallBack(data);
        }
    }
    if (type == "success") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWriteJob(job, data);
            iter2->second->OnCallBack(data);
        }
    }
     if (type == "failed") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWriteJob(job, data);
            iter2->second->OnCallBack(data);
        }
    }
     if (type == "cancelled") {
        std::string notifyType = "notify-success";
        auto iter2 = registeredListeners_.find(notifyType);
        if (iter2 != registeredListeners_.end()) {
            MessageParcel data;
            DataWriteJob(job, data);
            iter2->second->OnCallBack(data);
        }
    }*/
}
} // namespace OHOS::Print
