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

#include "ai_notifier_host_stubs.h"
#include "print_log.h"
#include "print_notification_builder.h"
#include "print_failure_ai_notifier.h"

namespace OHOS::Print {
UdmfDataGuard::UdmfDataGuard() = default;
UdmfDataGuard::~UdmfDataGuard() = default;
bool UdmfDataGuard::CreatePlainText(const std::string &) { return true; }
std::string UdmfDataGuard::Serialize() { return "test-udmf-key"; }
}

// Generated from the selected revision, without changing the production function bodies.
#include "production.inc"

using namespace OHOS::Print;

int main()
{
    int failures = 0;
    auto check = [&](const char *name, bool passed) {
        std::cout << (passed ? "PASS " : "FAIL ") << name << '\n';
        failures += !passed;
    };
    auto job = std::make_shared<PrintJob>();
    PrintServiceAbility service;
    auto reset = [&]() {
        PrintFailureAiNotifier::GetInstance().ClearJobState(job->jobId);
        HostTest::foregroundUser = 100;
        HostTest::accountQueryFails = false;
        HostTest::switchDuringButton = false;
        HostTest::switchAtPublish = false;
        HostTest::publishFails = false;
        HostTest::buttonUser = -1;
        HostTest::receivers.clear();
        HostTest::faults.clear();
        service.currentUserId_ = 100;
        service.userJobMap_[job->jobId] = 100;
        service.historyWrites = 0;
    };
    reset();
    // Matches enterprise user-switch ordering: OS is B, but RefreshPrinterStatusOnSwitchUser
    // interrupts A's queued job before NotifyCurrentUserChanged updates the service cache.
    HostTest::foregroundUser = 101;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_INTERRUPT);
    check("OS user B with cached user A: no interruption notification", HostTest::receivers.empty());
    check("Background interruption still reported", HostTest::faults[PRINT_JOB_BLOCKED_INTERRUPT] == 1);
    check("Background task history still updated", service.historyWrites == 1);
    service.currentUserId_ = 101;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("OS and cached user B: no paper notification", HostTest::receivers.empty());
    check("Background paper fault still reported", HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);
    HostTest::foregroundUser = 100;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Return to A despite stale cache B: deferred notification", HostTest::receivers.size() == 1);
    check("Notification receiver is task owner A", HostTest::receivers == std::vector<int32_t>{100});
    check("AI button belongs to task owner A", HostTest::buttonUser == 100);
    check("Deferred notification does not duplicate fault report", HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Repeated fault does not duplicate notification", HostTest::receivers.size() == 1);
    HostTest::foregroundUser = 101;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_JAMMED);
    check("New fault after switching away does not notify", HostTest::receivers.size() == 1);
    check("New background fault still reported", HostTest::faults[PRINT_JOB_BLOCKED_JAMMED] == 1);
    HostTest::foregroundUser = 100;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Recovered then recurring fault can notify again", HostTest::receivers.size() == 2);

    reset();
    HostTest::switchDuringButton = true;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Switch while building notification: skip publication", HostTest::receivers.empty());
    HostTest::switchDuringButton = false;
    HostTest::foregroundUser = 100;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Skipped publication can be retried for A", HostTest::receivers == std::vector<int32_t>{100});
    reset();
    HostTest::switchAtPublish = true;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Switch at publish boundary: request remains bound to A", HostTest::receivers == std::vector<int32_t>{100});

    reset();
    const uint32_t combinedFaults = PRINT_JOB_BLOCKED_JAMMED * 100 + PRINT_JOB_BLOCKED_OUT_OF_PAPER;
    HostTest::switchAtPublish = true;
    service.HandleJobBlockedState(job, combinedFaults);
    check("Compound fault: switch after first notification suppresses the second", HostTest::receivers.size() == 1);
    HostTest::switchAtPublish = false;
    HostTest::foregroundUser = 100;
    service.HandleJobBlockedState(job, combinedFaults);
    check("Compound fault: return to A only publishes the skipped reason", HostTest::receivers.size() == 2);
    check("Compound fault: deferred reason does not duplicate reports",
        HostTest::faults[PRINT_JOB_BLOCKED_JAMMED] == 1 && HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);

    reset();
    HostTest::accountQueryFails = true;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Account query failure: no notification", HostTest::receivers.empty());
    check("Account query failure: fault still reported", HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);
    reset();
    service.userJobMap_.clear();
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Unknown task owner: no notification", HostTest::receivers.empty());
    check("Unknown task owner: fault still reported", HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);
    reset();
    HostTest::foregroundUser = -1;
    service.userJobMap_[job->jobId] = -1;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Invalid owner and foreground user: no notification", HostTest::receivers.empty());

    reset();
    HostTest::publishFails = true;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    HostTest::publishFails = false;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Failed publication can be retried", HostTest::receivers == std::vector<int32_t>{100});
    check("Publication retry does not duplicate fault report", HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 1);
    PrintFailureAiNotifier::GetInstance().ClearJobState(job->jobId);
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Job cleanup clears both deduplication states",
        HostTest::receivers.size() == 2 && HostTest::faults[PRINT_JOB_BLOCKED_OUT_OF_PAPER] == 2);
    reset();
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_AUTHENTICATION);
    check("Authentication remains excluded from AI notifications", HostTest::receivers.empty());
    check("Authentication still reported", HostTest::faults[PRINT_JOB_BLOCKED_AUTHENTICATION] == 1);
    reset();
    job->printerId = "eprint";
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Eprint remains excluded", HostTest::receivers.empty() && HostTest::faults.empty());
    job->printerId = "printer";
    service.printSystemData_.exists = false;
    service.HandleJobBlockedState(job, PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    check("Missing printer remains excluded", HostTest::receivers.empty() && HostTest::faults.empty());
    return failures == 0 ? 0 : 1;
}
