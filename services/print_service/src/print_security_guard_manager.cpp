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
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    auto securityGuard = std::make_shared<PrintSecurityGuardInfo>(callPkg, fileList);
    securityMap_.insert(std::make_pair(jobId, securityGuard));
}

void PrintSecurityGuardManager::receiveJobStateUpdate(const std::string jobId, const PrinterInfo &printerInfo,
    const PrintJob &printJob)
{
    PRINT_HILOGI("receiveJobStateUpdate jobId:%{public}s, state:%{public}d", jobId.c_str(), printJob.GetJobState());
    std::string securityInfo;
    {
        std::lock_guard<std::mutex> lock(securityMapMutex_);
        auto it = securityMap_.find(jobId);
        if (it != securityMap_.end() && it->second != nullptr) {
            PRINT_HILOGI("find PrintSecurityGuardInfo");
            auto securityGuard = it->second;
            securityGuard->SetPrintTypeInfo(printerInfo, printJob);
            securityInfo = securityGuard->ToJsonStr();
        } else {
            PRINT_HILOGI("find PrintSecurityGuardInfo empty");
            std::vector<std::string> fileList;
            auto securityGuard = std::make_shared<PrintSecurityGuardInfo>("", fileList);
            securityGuard->SetPrintTypeInfo(printerInfo, printJob);
            securityInfo = securityGuard->ToJsonStr();
        }
        if (printJob.GetJobState() == PRINT_JOB_COMPLETED) {
            securityMap_.erase(jobId);
        }
    }
    ReportSecurityInfo(EVENT_ID, VERSION, securityInfo);
}

void PrintSecurityGuardManager::receiveAuditInfo(const std::string jobId,
    const PrinterInfo &printerInfo, const PrintJob &printJob,
    const std::vector<std::string> &fileInfos)
{
    PRINT_HILOGI("receiveAuditInfo jobId:%{public}s, fileCount:%{public}zu",
        jobId.c_str(), fileInfos.size());
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    auto it = securityMap_.find(jobId);
    if (it != securityMap_.end() && it->second != nullptr) {
        it->second->SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    } else {
        PRINT_HILOGW("receiveAuditInfo jobId:%{public}s not found in securityMap", jobId.c_str());
        auto securityGuard = std::make_shared<PrintSecurityGuardInfo>("", std::vector<std::string>{});
        securityGuard->SetPrintAuditInfo(printerInfo, printJob, fileInfos);
        securityMap_[jobId] = securityGuard;
    }
}

void PrintSecurityGuardManager::clearSecurityMap(const std::string jobId)
{
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    securityMap_.erase(jobId);
}

void PrintSecurityGuardManager::clearAll()
{
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    securityMap_.clear();
}

std::vector<std::string> PrintSecurityGuardManager::GetFileList(const std::string &jobId) const
{
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    auto it = securityMap_.find(jobId);
    if (it != securityMap_.end() && it->second != nullptr) {
        return it->second->GetFileList();
    }
    return {};
}

void PrintSecurityGuardManager::SetFileAuditInfo(const std::string &jobId,
    const std::vector<std::string> &fileInfos)
{
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    auto it = securityMap_.find(jobId);
    if (it != securityMap_.end() && it->second != nullptr) {
        it->second->SetFileAuditInfo(fileInfos);
    }
}

std::vector<std::string> PrintSecurityGuardManager::GetFileAuditInfo(const std::string &jobId) const
{
    std::lock_guard<std::mutex> lock(securityMapMutex_);
    auto it = securityMap_.find(jobId);
    if (it != securityMap_.end() && it->second != nullptr) {
        return it->second->GetFileAuditInfo();
    }
    return {};
}

void PrintSecurityGuardManager::CalculateFileAuditInfo(const std::string &jobId)
{
    std::vector<std::string> fileList = GetFileList(jobId);
    if (fileList.empty()) {
        PRINT_HILOGW("CalculateFileAuditInfo empty fileList, jobId: %{public}s", jobId.c_str());
        return;
    }
    std::vector<std::string> fileNames;
    for (const auto &fileName : fileList) {
        if (!PrintSecurityGuardUtil::IsPrintableFile(fileName)) {
            PRINT_HILOGW("Skip non-printable file: %{public}s", fileName.c_str());
            continue;
        }
        fileNames.push_back(fileName);
    }
    if (!fileNames.empty()) {
        SetFileAuditInfo(jobId, fileNames);
        PRINT_HILOGI("Calculated file audit info for jobId: %{public}s, count: %{public}zu",
            jobId.c_str(), fileNames.size());
    } else {
        PRINT_HILOGW("CalculateFileAuditInfo empty result, jobId: %{public}s", jobId.c_str());
    }
}

void PrintSecurityGuardManager::SendJobAuditInfo(const std::string &jobId,
    const PrinterInfo &printerInfo, const PrintJob &printJob)
{
    auto fileInfos = GetFileAuditInfo(jobId);
    receiveAuditInfo(jobId, printerInfo, printJob, fileInfos);
}

void PrintSecurityGuardManager::InjectFileListIntoOption(const std::string &jobId, std::string &option)
{
    std::vector<std::string> fileList = GetFileList(jobId);
    if (fileList.empty()) {
        return;
    }
    Json::Value optionJson;
    if (!PrintJsonUtil::Parse(option, optionJson)) {
        return;
    }
    Json::Value fileListJson(Json::arrayValue);
    for (const auto &file : fileList) {
        fileListJson.append(file);
    }
    optionJson["fileList"] = fileListJson;
    option = PrintJsonUtil::WriteString(optionJson);
}

void PrintSecurityGuardManager::ReportSecurityInfo(const int32_t eventId, const std::string version,
    const std::string content)
{
    PRINT_HILOGI("ReportSecurityInfo called, eventId:%{public}d", eventId);
#ifdef SECURITY_GUARDE_ENABLE
    PRINT_HILOGI("start to push data to security_guard service, eventId:%{public}d, content:%{private}s",
        eventId, content.c_str());
    auto eventInfo = std::make_shared<Security::SecurityGuard::EventInfo>(eventId, version, content);
    int res = OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    PRINT_HILOGI("end to push data to security_guard service status:%{public}d", res);
#else
    PRINT_HILOGW("SECURITY_GUARDE_ENABLE not defined, report skipped");
#endif
}
} // namespace OHOS::Print
