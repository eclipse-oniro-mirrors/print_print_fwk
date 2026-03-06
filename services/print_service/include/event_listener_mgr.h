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

#ifndef EVENT_LISTENER_MGR_H
#define EVENT_LISTENER_MGR_H

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include "printer_event_callback.h"
#include "extension_event_callback.h"
#include "print_job_event_callback.h"
#include "singleton.h"

namespace OHOS {
namespace Print {
class EventListenerMgr : public DelayedSingleton<EventListenerMgr> {
public:
    EventListenerMgr();
    virtual ~EventListenerMgr();
    bool RegisterPrinterListener(const CallbackEventType &eventType, const sptr<IPrintCallback> &listener);
    bool RegisterExtensionListener(const CallbackEventType &eventType, const std::string &extensionId,
        const sptr<IPrintExtensionCallback> &listener);
    bool RegisterPrintJobListener(
        const CallbackEventType &eventType, const std::string &jobId, const sptr<IPrintCallback> &listener);
    bool UnRegisterPrinterListener(const CallbackEventType &eventType);
    bool UnRegisterPrintJobListener(const CallbackEventType &eventType, const std::string &jobId);
    bool Execute(const CallbackInfo &callbackInfo);
    void OnRemoteListenerDied(const sptr<IRemoteObject> &listener);
    bool IsPrinterListenerEmpty(const CallbackEventType &eventType);
    bool IsExtensionListenerEmpty(const CallbackEventType &eventType, const std::string &extensionId, int32_t userId);
    bool IsPrintJobListenerEmpty(const CallbackEventType &eventType, const std::string &jobId);

private:
    std::shared_ptr<BaseEventCallback> FindCallback(int32_t userId, pid_t pid, CallbackEventType eventType);
    void ClearAllListeners();
    bool RemoveDiedListener(std::vector<std::shared_ptr<BaseEventCallback>> &callbacks, CallbackEventType eventType,
        const sptr<IRemoteObject> &listener);
    bool TryDeletePrintJobListenerFromCallback(const std::shared_ptr<BaseEventCallback> &callback,
        CallbackEventType eventType, const std::string &jobId);
    bool DeletePrintJobListener(CallbackEventType eventType, const std::string &jobId);
    bool ExecuteForUser(
        const std::unordered_map<CallbackEventType, std::vector<std::shared_ptr<BaseEventCallback>>> &eventMap,
        CallbackEventType type, const CallbackInfo &callbackInfo);
    bool ExecuteForAllUsers(CallbackEventType type, const CallbackInfo &callbackInfo);
    void ClearListenersForUser(
        std::unordered_map<CallbackEventType, std::vector<std::shared_ptr<BaseEventCallback>>> &eventMap);

    std::mutex mutex_;
    std::unordered_map<int32_t, std::unordered_map<CallbackEventType, std::vector<std::shared_ptr<BaseEventCallback>>>>
        registeredListeners_;
    sptr<IRemoteObject::DeathRecipient> eventListenerDeathRecipient_ = nullptr;
    uint32_t counter_ = 0;
};
}  // namespace Print
}  // namespace OHOS
#endif  // EVENT_LISTENER_MGR_H
