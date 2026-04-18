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

#include <set>
#include <algorithm>
#include "print_failure_ai_notifier.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_notification_builder.h"
#include "hisys_event_util.h"

namespace OHOS::Print {
static constexpr uint32_t PRINT_JOB_SUBSTATE_BASE = 100;

PrintFailureAiNotifier::PrintFailureAiNotifier() {}

PrintFailureAiNotifier& PrintFailureAiNotifier::GetInstance()
{
    static PrintFailureAiNotifier instance;
    return instance;
}

void PrintFailureAiNotifier::HandleJobBlocked(const std::string& jobId, uint32_t subState,
    const std::string& printerName)
{
    std::lock_guard<std::mutex> lock(jobStateMutex_);
    std::set<uint32_t> newStates = SplitSubState(subState);
    auto iter = jobStateMap_.find(jobId);
    if (iter == jobStateMap_.end()) {
        jobStateMap_[jobId] = newStates;
        for (uint32_t state : newStates) {
            PrintNotificationBuilder::CreateNotification(state, printerName);
            const std::string resourceKey = PrintNotificationBuilder::GetFaultKey(state);
            HisysEventUtil::ReportFailureEvent(HisysEventParams{
                .eventType = HisysEventType::PRINT_FAILURE,
                .resourceKey = resourceKey,
                .subState = state
            });
        }
    } else {
        std::set<uint32_t> oldStates = iter->second;
        std::set<uint32_t> newStatesToNotify;
        std::set_difference(newStates.begin(), newStates.end(),
            oldStates.begin(), oldStates.end(),
            std::inserter(newStatesToNotify, newStatesToNotify.begin()));
        for (uint32_t state : newStatesToNotify) {
            PrintNotificationBuilder::CreateNotification(state, printerName);
            const std::string resourceKey = PrintNotificationBuilder::GetFaultKey(state);
            HisysEventUtil::ReportFailureEvent(HisysEventParams{
                .eventType = HisysEventType::PRINT_FAILURE,
                .resourceKey = resourceKey,
                .subState = state
            });
        }
        jobStateMap_[jobId] = newStates;
    }
}

std::set<uint32_t> PrintFailureAiNotifier::SplitSubState(uint32_t subState)
{
    std::set<uint32_t> uniqueStates;

    while (subState > 0) {
        uint32_t remainder = subState % PRINT_JOB_SUBSTATE_BASE;
        if (remainder != 0) {
            uniqueStates.insert(remainder);
        }
        subState = subState / PRINT_JOB_SUBSTATE_BASE;
    }

    return uniqueStates;
}

} // namespace OHOS::Print
