/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "print_event_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "print_log.h"
#include "print_service_ability.h"

namespace OHOS {
namespace Print {
PrintEventSubscriber::PrintEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

PrintEventSubscriber::~PrintEventSubscriber()
{}

void PrintEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        PRINT_HILOGI("user switched, current userId: %{public}d", userId);
        PrintServiceAbility::GetInstance()->NotifyCurrentUserChanged(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = data.GetCode();
        PRINT_HILOGI("user removed, removed userId: %{public}d", userId);
        PrintServiceAbility::GetInstance()->CancelUserPrintJobs(userId);
    }
}

}  // namespace Print
}  // namespace OHOS