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

#include "print_security_guard_manager.h"

namespace OHOS::Print {
static int64_t EVENT_ID = 1011015004;
static std::string VERSION = "1.0";

void PrintSecurityGuardManager::receiveBaseInfo(const std::string jobId, const std::string callPkg,
    const std::vector<std::string> &fileList)
{
    PRINT_HILOGI("receiveBaseInfo start jobId:%{public}s, callPkg:%{public}s", jobId.c_str(), callPkg.c_str());
    auto securityGuard = std::make_shared<PrintSecurityGuardInfo>(callPkg, fileList);
    securityMap_.insert(std::make_pair(jobId, securityGuard));
}

void PrintSecurityGuardManager::receiveJobStateUpdate(const std::string jobId, const PrinterInfo &printerInfo,
    const PrintJob &printJob)
{
    PRINT_HILOGI("receiveJobStateUpdate jobId:%{public}s, state:%{public}d", jobId.c_str(), printJob.GetJobState());
    auto it = securityMap_.find(jobId);
    if (it != securityMap_.end() && it -> second !=nullptr) {
        auto securityGuard = it -> second;
        securityGuard ->setPrintTypeInfo(printerInfo, printJob);

        ReportSecurityInfo(EVENT_ID, VERSION, securityGuard -> ToJsonStr());
    } else {
        PRINT_HILOGI("find PrintSecurityGuardInfo empty");
    }

    clearSecurityMap(jobId);
}

void PrintSecurityGuardManager::clearSecurityMap(const std::string jobId)
{
    securityMap_.erase(jobId);
}

void PrintSecurityGuardManager::ReportSecurityInfo(const int32_t eventId, const std::string version,
    const std::string content)
{
#ifdef SECURITY_GUARDE_ENABLE
    PRINT_HILOGI("start to push data to security_guard service, eventId:%{public}d, content:%{public}s",
        eventId, content.c_str());
    auto eventInfo = std::make_shared<Security::SecurityGuard::EventInfo>(eventId, version, content);
    int res = OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    PRINT_HILOGI("end to push data to security_guard service status:%{public}d", res);
#endif
}
} // namespace OHOS::Print
