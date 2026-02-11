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
#include "iprint_callback.h"
#include "singleton.h"

namespace OHOS {
namespace Print {
class EventListenerMgr : public DelayedSingleton<EventListenerMgr> {
public:
    EventListenerMgr();
    virtual ~EventListenerMgr();
    bool RegisterEventListener(const std::string &eventType, const sptr<IPrintCallback> &listener);
    bool UnRegisterEventListener(const std::string &eventType);
    sptr<IPrintCallback> FindEventListener(const std::string &eventType);
    std::vector<sptr<IPrintCallback>> FindEventListeners(std::function<bool(const std::string &)> comp);
    std::vector<std::string> FindEventTypes(std::function<bool(const std::string &)> comp);
    void OnRemoteListenerDied(const sptr<IRemoteObject> &listener);

private:
    void ClearAllListeners();
    bool RemoveDeathRecipient(sptr<IPrintCallback> listener);
    bool AddDeathRecipient(sptr<IPrintCallback> listener);

    std::mutex mutex_;
    std::map<std::string, sptr<IPrintCallback>> registeredListeners_;
    sptr<IRemoteObject::DeathRecipient> eventListenerDeathRecipient_;
};
} // namespace Print
} // namespace OHOS
#endif
