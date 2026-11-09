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

#include "print_failure_ai_notifier_impl.h"

#include <algorithm>
#include <set>

#include "hisysevent.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_notification_builder.h"

namespace OHOS::Print {

namespace {
constexpr uint32_t PRINT_JOB_SUBSTATE_BASE = 100;

static constexpr char PRINT_DOMAIN[] = "PRINT";
constexpr const char *PRINT_EXCEPTION_FAULT_EVENT = "PRINT_EXCEPTION";
constexpr const char *MSG_KEY = "MSG";
constexpr const char *FAULT_CODE_KEY = "FAULT_CODE";

static void ReportPrintFailureEvent(const std::string &resourceKey, uint32_t subState)
{
    if (resourceKey.empty()) {
        return;
    }
    HiSysEventWrite(
        PRINT_DOMAIN,
        PRINT_EXCEPTION_FAULT_EVENT,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        MSG_KEY, resourceKey,
        FAULT_CODE_KEY, static_cast<int32_t>(subState));
}
}

PrintFailureAiNotifierImpl::PrintFailureAiNotifierImpl() {}

void *PrintFailureAiNotifierImpl::QueryInterface(PrintFeatureIid iid)
{
    if (iid == PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER) {
        return static_cast<IPrintFailureAiNotifier *>(this);
    }
    return nullptr;
}

void PrintFailureAiNotifierImpl::HandleJobBlocked(const std::string &jobId, uint32_t subState,
    const std::string &printerName)
{
    std::lock_guard<std::mutex> lock(jobStateMutex_);
    std::set<uint32_t> newStates = SplitSubState(subState);
    auto iter = jobStateMap_.find(jobId);
    if (iter == jobStateMap_.end()) {
        jobStateMap_[jobId] = newStates;
        for (uint32_t state : newStates) {
            ReportFailure(state, printerName);
        }
        return;
    }

    std::set<uint32_t> oldStates = iter->second;
    std::set<uint32_t> newStatesToNotify;
    std::set_difference(newStates.begin(), newStates.end(),
        oldStates.begin(), oldStates.end(),
        std::inserter(newStatesToNotify, newStatesToNotify.begin()));
    for (uint32_t state : newStatesToNotify) {
        ReportFailure(state, printerName);
    }
    jobStateMap_[jobId] = newStates;
}

void PrintFailureAiNotifierImpl::ReportFailure(uint32_t state, const std::string &printerName)
{
    if (state != PRINT_JOB_BLOCKED_AUTHENTICATION) {
        PrintNotificationBuilder::CreateNotification(state, printerName);
    }
    const std::string resourceKey = PrintNotificationBuilder::GetFaultKey(state);
    ReportPrintFailureEvent(resourceKey, state);
}

std::set<uint32_t> PrintFailureAiNotifierImpl::SplitSubState(uint32_t subState)
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

void PrintFailureAiNotifierImpl::ClearJobState(const std::string &jobId)
{
    std::lock_guard<std::mutex> lock(jobStateMutex_);
    jobStateMap_.erase(jobId);
}

extern "C" __attribute__((visibility("default"))) OHOS::Print::IPrintFeature *CreatePrintFailureAiNotifier()
{
    return new OHOS::Print::PrintFailureAiNotifierImpl();
}

extern "C" __attribute__((visibility("default"))) void DestroyPrintFailureAiNotifier(
    OHOS::Print::IPrintFeature *feature)
{
    delete feature;
}

} // namespace OHOS::Print
