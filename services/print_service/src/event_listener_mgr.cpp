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

#include <unistd.h>
#include "event_listener_mgr.h"
#include "ipc_skeleton.h"
#include "print_log.h"
#include "print_common_death_recipient.h"

namespace OHOS {
namespace Print {
namespace {
const int32_t MAX_LISTENERS_COUNT = 1000;
}  // namespace

EventListenerMgr::EventListenerMgr()
    : eventListenerDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(new(std::nothrow) PrintCommonDeathRecipient(
          std::bind(&EventListenerMgr::OnRemoteListenerDied, this, std::placeholders::_1))))
{}

EventListenerMgr::~EventListenerMgr()
{
    ClearAllListeners();
}

std::shared_ptr<BaseEventCallback> EventListenerMgr::FindCallback(
    int32_t userId, pid_t pid, CallbackEventType eventType)
{
    auto userIt = registeredListeners_.find(userId);
    if (userIt == registeredListeners_.end()) {
        return nullptr;
    }
    auto &eventMap = userIt->second;
    auto eventIt = eventMap.find(eventType);
    if (eventIt == eventMap.end()) {
        return nullptr;
    }
    for (auto &callback : eventIt->second) {
        if (callback && callback->GetPid() == pid) {
            return callback;
        }
    }
    return nullptr;
}

bool EventListenerMgr::RegisterPrinterListener(const CallbackEventType &eventType, const sptr<IPrintCallback> &listener)
{
    if (!listener) {
        PRINT_HILOGE("listener is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t userId = IPCSkeleton::GetCallingUid() / 200000;
    pid_t pid = IPCSkeleton::GetCallingPid();

    auto existingCallback = FindCallback(userId, pid, eventType);
    if (existingCallback) {
        auto printerCallback = std::static_pointer_cast<PrinterEventCallback>(existingCallback);
        if (printerCallback) {
            printerCallback->SetListener(listener);
            return true;
        }
        return false;
    }

    if (counter_ >= MAX_LISTENERS_COUNT) {
        PRINT_HILOGE("Exceeded the maximum number of registration.");
        return false;
    }

    auto callback =
        std::make_shared<PrinterEventCallback>(userId, pid, eventType, listener, eventListenerDeathRecipient_);
    registeredListeners_[userId][eventType].emplace_back(callback);
    counter_++;
    PRINT_HILOGI("RegisterPrinterListener type=%{public}d, counter=%{public}d, pid=%{public}d, userId=%{public}d",
        eventType,
        counter_,
        pid,
        userId);
    return true;
}

bool EventListenerMgr::RegisterExtensionListener(
    const CallbackEventType &eventType, const std::string &extensionId, const sptr<IPrintExtensionCallback> &listener)
{
    if (!listener) {
        PRINT_HILOGE("listener is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t userId = IPCSkeleton::GetCallingUid() / 200000;
    pid_t pid = IPCSkeleton::GetCallingPid();

    auto existingCallback = FindCallback(userId, pid, eventType);
    if (existingCallback) {
        auto extCallback = std::static_pointer_cast<ExtensionEventCallback>(existingCallback);
        if (extCallback) {
            extCallback->SetListener(listener);
            extCallback->SetExtensionId(extensionId);
            return true;
        }
        return false;
    }

    if (counter_ >= MAX_LISTENERS_COUNT) {
        PRINT_HILOGE("Exceeded the maximum number of registration.");
        return false;
    }

    auto callback =
        std::make_shared<ExtensionEventCallback>(userId, pid, eventType, listener, eventListenerDeathRecipient_);
    callback->SetExtensionId(extensionId);
    registeredListeners_[userId][eventType].emplace_back(callback);
    counter_++;
    PRINT_HILOGI("RegisterExtensionListener type=%{public}d, counter=%{public}d, pid=%{public}d, userId=%{public}d",
        eventType,
        counter_,
        pid,
        userId);
    return true;
}

bool EventListenerMgr::RegisterPrintJobListener(
    const CallbackEventType &eventType, const std::string &jobId, const sptr<IPrintCallback> &listener)
{
    if (!listener) {
        PRINT_HILOGE("listener is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t userId = IPCSkeleton::GetCallingUid() / 200000;
    pid_t pid = IPCSkeleton::GetCallingPid();

    counter_++;
    if (counter_ >= MAX_LISTENERS_COUNT) {
        PRINT_HILOGE("Exceeded the maximum number of registration.");
        return false;
    }

    auto existingCallback = FindCallback(userId, pid, eventType);
    if (existingCallback) {
        auto jobCallback = std::static_pointer_cast<PrintJobEventCallback>(existingCallback);
        if (jobCallback) {
            counter_ -= jobCallback->SetListener(listener, jobId);
            return true;
        }
        return false;
    }

    auto callback = std::make_shared<PrintJobEventCallback>(userId, pid, eventType, eventListenerDeathRecipient_);
    callback->SetListener(listener, jobId);
    registeredListeners_[userId][eventType].emplace_back(callback);
    PRINT_HILOGI("RegisterPrintJobListener type=%{public}d, counter=%{public}d, pid=%{public}d, userId=%{public}d",
        eventType,
        counter_,
        pid,
        userId);
    return true;
}

bool EventListenerMgr::UnRegisterPrinterListener(const CallbackEventType &eventType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t userId = IPCSkeleton::GetCallingUid() / 200000;
    pid_t pid = IPCSkeleton::GetCallingPid();

    auto callback = FindCallback(userId, pid, eventType);
    if (!callback) {
        PRINT_HILOGW("listener not registered, type=%{public}d", eventType);
        return false;
    }

    auto &callbacks = registeredListeners_[userId][eventType];
    auto it = std::find(callbacks.begin(), callbacks.end(), callback);
    if (it != callbacks.end()) {
        counter_ -= callback->Clear();
        callbacks.erase(it);
        PRINT_HILOGI("UnRegisterPrinterListener type=%{public}d, counter=%{public}d, pid=%{public}d, userId=%{public}d",
            eventType,
            counter_,
            pid,
            userId);
        return true;
    }
}

bool EventListenerMgr::TryDeletePrintJobListenerFromCallback(const std::shared_ptr<BaseEventCallback> &callback,
    CallbackEventType eventType, const std::string &jobId)
{
    auto jobCallback = std::static_pointer_cast<PrintJobEventCallback>(callback);
    if (jobCallback && jobCallback->DeleteListener(jobId)) {
        counter_--;
        PRINT_HILOGI("UnRegisterPrintJobListener type=%{public}d, counter=%{public}d", eventType, counter_);
        return true;
    }
    return false;
}

bool EventListenerMgr::DeletePrintJobListener(CallbackEventType eventType, const std::string &jobId)
{
    for (auto &[_, eventMap] : registeredListeners_) {
        auto eventIt = eventMap.find(eventType);
        if (eventIt == eventMap.end()) {
            continue;
        }
        for (auto &cb : eventIt->second) {
            if (TryDeletePrintJobListenerFromCallback(cb, eventType, jobId)) {
                return true;
            }
        }
    }
    return false;
}

bool EventListenerMgr::UnRegisterPrintJobListener(const CallbackEventType &eventType, const std::string &jobId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t userId = IPCSkeleton::GetCallingUid() / 200000;
    pid_t pid = IPCSkeleton::GetCallingPid();

    auto callback = FindCallback(userId, pid, eventType);
    if (callback) {
        return TryDeletePrintJobListenerFromCallback(callback, eventType, jobId);
    } else if (pid == getpid()) {
        return DeletePrintJobListener(eventType, jobId);
    }
    return false;
}

bool EventListenerMgr::IsPrinterListenerEmpty(const CallbackEventType &eventType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[_, eventMap] : registeredListeners_) {
        auto eventIt = eventMap.find(eventType);
        if (eventIt != eventMap.end() && !eventIt->second.empty()) {
            return false;
        }
    }
    return true;
}

bool EventListenerMgr::IsExtensionListenerEmpty(
    const CallbackEventType &eventType, const std::string &extensionId, int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto userIt = registeredListeners_.find(userId);
    if (userIt == registeredListeners_.end()) {
        return true;
    }
    auto eventIt = userIt->second.find(eventType);
    if (eventIt == userIt->second.end()) {
        return true;
    }
    for (const auto &callback : eventIt->second) {
        auto extCallback = std::static_pointer_cast<ExtensionEventCallback>(callback);
        if (extCallback && extCallback->GetExtensionId() == extensionId) {
            return false;
        }
    }
    return true;
}

bool EventListenerMgr::IsPrintJobListenerEmpty(const CallbackEventType &eventType, const std::string &jobId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[_, eventMap] : registeredListeners_) {
        auto eventIt = eventMap.find(eventType);
        if (eventIt == eventMap.end()) {
            continue;
        }
        for (const auto &callback : eventIt->second) {
            auto jobCallback = std::static_pointer_cast<PrintJobEventCallback>(callback);
            if (jobCallback && jobCallback->HasJobId(jobId)) {
                return false;
            }
        }
    }
    return true;
}

bool EventListenerMgr::RemoveDiedListener(std::vector<std::shared_ptr<BaseEventCallback>> &callbacks,
    CallbackEventType eventType, const sptr<IRemoteObject> &listener)
{
    for (auto it = callbacks.begin(); it != callbacks.end() && (*it) != nullptr;) {
        auto callback = *it;
        if (callback->IsRemoteDied(listener)) {
            counter_ -= callback->Clear();
            callbacks.erase(it);
            PRINT_HILOGI("listener removed, type = %{public}d, all counter_ is %{public}d", eventType, counter_);
            return true;
        }
        ++it;
    }
    return false;
}

void EventListenerMgr::OnRemoteListenerDied(const sptr<IRemoteObject> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGW("remote listener null");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &[userId, eventMap] : registeredListeners_) {
        for (auto &[eventType, callbacks] : eventMap) {
            if (RemoveDiedListener(callbacks, eventType, listener)) {
                return;
            }
        }
    }
}

void EventListenerMgr::ClearListenersForUser(
    std::unordered_map<CallbackEventType, std::vector<std::shared_ptr<BaseEventCallback>>> &eventMap)
{
    for (auto &[eventType, callbacks] : eventMap) {
        for (auto &callback : callbacks) {
            if (callback) {
                callback->Clear();
            }
        }
        callbacks.clear();
    }
}

void EventListenerMgr::ClearAllListeners()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &[userId, eventMap] : registeredListeners_) {
        ClearListenersForUser(eventMap);
    }
    counter_ = 0;
}

bool EventListenerMgr::Execute(const CallbackInfo &callbackInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CallbackEventType type = callbackInfo.cbEventType;
    auto userIt = registeredListeners_.find(callbackInfo.userId);
    if (userIt != registeredListeners_.end()) {
        return ExecuteForUser(userIt->second, type, callbackInfo);
    }
    return ExecuteForAllUsers(type, callbackInfo);
}

bool EventListenerMgr::ExecuteForUser(
    const std::unordered_map<CallbackEventType, std::vector<std::shared_ptr<BaseEventCallback>>> &eventMap,
    CallbackEventType type, const CallbackInfo &callbackInfo)
{
    auto eventIt = eventMap.find(type);
    if (eventIt == eventMap.end()) {
        PRINT_HILOGW("listener not exist, type = %{public}d", type);
        return true;
    }

    bool result = true;
    for (auto &callback : eventIt->second) {
        if (callback && !callback->Execute(callbackInfo)) {
            result = false;
        }
    }
    return result;
}

bool EventListenerMgr::ExecuteForAllUsers(CallbackEventType type, const CallbackInfo &callbackInfo)
{
    bool result = true;
    for (const auto &[_, eventMap] : registeredListeners_) {
        auto eventIt = eventMap.find(type);
        if (eventIt == eventMap.end()) {
            continue;
        }
        for (auto &callback : eventIt->second) {
            if (callback && !callback->Execute(callbackInfo)) {
                result = false;
            }
        }
    }
    return result;
}
}  // namespace Print
}  // namespace OHOS