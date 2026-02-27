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

#include "event_listener_mgr.h"
#include "print_log.h"
#include "print_common_death_recipient.h"

namespace OHOS {
namespace Print {
const int32_t MAX_LISTENERS_COUNT = 1000;

EventListenerMgr::EventListenerMgr() : eventListenerDeathRecipient_(
    sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) PrintCommonDeathRecipient(
        std::bind(&EventListenerMgr::OnRemoteListenerDied, this, std::placeholders::_1))))
{
}

EventListenerMgr::~EventListenerMgr()
{
    ClearAllListeners();
}

bool EventListenerMgr::RegisterEventListener(const std::string &eventType, const sptr<IPrintCallback> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGE("listener is null");
        return false;
    }
    std::lock_guard<std::mutex> autoLock(mutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter == registeredListeners_.end()) {
        if (registeredListeners_.size() > MAX_LISTENERS_COUNT) {
            PRINT_HILOGE("Exceeded the maximum number of registration.");
            return false;
        }
        PRINT_HILOGD("insert listener");
        registeredListeners_.insert(std::make_pair(eventType, listener));
    } else {
        PRINT_HILOGD("replace listener");
        RemoveDeathRecipient(iter->second);
        iter->second = listener;
    }
    AddDeathRecipient(listener);
    PRINT_HILOGI("RegisterEventListener type = %{public}s, size = %{public}zu", eventType.c_str(),
        registeredListeners_.size());
    return true;
}

bool EventListenerMgr::UnRegisterEventListener(const std::string &eventType)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter == registeredListeners_.end()) {
        PRINT_HILOGW("listener not registered, type = %{public}s", eventType.c_str());
        return false;
    }
    RemoveDeathRecipient(iter->second);
    registeredListeners_.erase(iter);
    PRINT_HILOGI("UnRegisterEventListener type = %{public}s, size = %{public}zu", eventType.c_str(),
        registeredListeners_.size());
    return true;
}

sptr<IPrintCallback> EventListenerMgr::FindEventListener(const std::string &eventType)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGD("listener found, type = %{public}s", eventType.c_str());
        return iter->second;
    }
    return nullptr;
}

std::vector<sptr<IPrintCallback>> EventListenerMgr::FindEventListeners(std::function<bool(const std::string &)> comp)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    std::vector<sptr<IPrintCallback>> list;
    for (auto &listenerItem : registeredListeners_) {
        if (comp(listenerItem.first)) {
            list.push_back(listenerItem.second);
        }
    }
    return list;
}

std::vector<std::string> EventListenerMgr::FindEventTypes(std::function<bool(const std::string &)> comp)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    std::vector<std::string> list;
    for (auto &listenerItem : registeredListeners_) {
        if (comp(listenerItem.first)) {
            list.push_back(listenerItem.first);
        }
    }
    return list;
}

void EventListenerMgr::OnRemoteListenerDied(const sptr<IRemoteObject> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGW("remote listener null");
        return;
    }
    std::lock_guard<std::mutex> autoLock(mutex_);
    for (auto &listenerItem : registeredListeners_) {
        if (listenerItem.second == nullptr || listenerItem.second->AsObject() != listener) {
            continue;
        }
        RemoveDeathRecipient(listenerItem.second);
        registeredListeners_.erase(listenerItem.first);
        PRINT_HILOGI("listener removed, type = %{public}s, size = %{public}zu", listenerItem.first.c_str(),
            registeredListeners_.size());
        break;
    }
}

void EventListenerMgr::ClearAllListeners()
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    for (auto &listenerItem : registeredListeners_) {
        RemoveDeathRecipient(listenerItem.second);
    }
    registeredListeners_.clear();
}

bool EventListenerMgr::RemoveDeathRecipient(sptr<IPrintCallback> listener)
{
    if (listener == nullptr) {
        PRINT_HILOGW("listener is null");
        return false;
    }
    auto remoteObject = listener->AsObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGW("remoteObject is null");
        return false;
    }
    remoteObject->RemoveDeathRecipient(eventListenerDeathRecipient_);
    return true;
}

bool EventListenerMgr::AddDeathRecipient(sptr<IPrintCallback> listener)
{
    if (listener == nullptr) {
        PRINT_HILOGW("listener is null");
        return false;
    }
    auto remoteObject = listener->AsObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGW("remoteObject is null");
        return false;
    }
    remoteObject->AddDeathRecipient(eventListenerDeathRecipient_);
    return true;
}
}  // namespace Print
}  // namespace OHOS
