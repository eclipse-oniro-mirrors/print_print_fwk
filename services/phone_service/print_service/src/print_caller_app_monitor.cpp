/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <thread>

#include "app_mgr_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "print_caller_app_monitor.h"
#include "print_bms_helper.h"
#include "print_constant.h"

namespace OHOS::Print {
static constexpr uint32_t CHECK_CALLER_APP_INTERVAL = 60;
static const std::string PRINT_EXTENSION_SUFFIX = ":print";

PrintCallerAppMonitor& PrintCallerAppMonitor::GetInstance()
{
    static PrintCallerAppMonitor instance;
    return instance;
}

void PrintCallerAppMonitor::StartCallerAppMonitor(std::function<bool()> unloadTask)
{
    if (isMonitoring_.load()) {
        PRINT_HILOGW("The monitoring thread is running");
        return;
    }
    isMonitoring_.store(true);
    std::thread printCallerAppMonitorThread(&PrintCallerAppMonitor::MonitorCallerApps, this, unloadTask);
    printCallerAppMonitorThread.detach();
}

void PrintCallerAppMonitor::AddCallerAppToMap()
{
    int32_t userId = GetCurrentUserId();
    if (userId == AppExecFwk::Constants::INVALID_USERID) {
        PRINT_HILOGE("Invalid user id.");
        return;
    }
    std::string bundleName = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::vector<AppExecFwk::RunningProcessInfo> processInfos = GetRunningProcessInformation(bundleName, userId);
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    if (IsProcessForeground(callerPid)) {
        delayUnload_.store(true);
    }
    for (auto &processInfo : processInfos) {
        PRINT_HILOGD("processName: %{public}s, processId: %{public}d, callerPid: %{public}d",
            processInfo.processName_.c_str(),
            processInfo.pid_,
            callerPid);
        if (processInfo.pid_ != 0 && !bundleName.empty() && callerPid == processInfo.pid_ &&
            processInfo.processName_.find(PRINT_EXTENSION_SUFFIX) == std::string::npos) {
            if (!CheckCallerAppInMap(callerPid, bundleName)) {
                auto callerAppInfo = std::make_shared<PrintCallerAppInfo>(callerPid, userId, bundleName);
                std::lock_guard<std::mutex> lock(callerMapMutex_);
                callerMap_[callerPid] = callerAppInfo;
                PRINT_HILOGI("add callerPid: %{public}d", callerPid);
            }
        }
    }
}

void PrintCallerAppMonitor::RemoveCallerAppFromMap()
{
    PRINT_HILOGI("RemoveCallerAppFromMap enter");
    std::string bundleName = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    auto iter = callerMap_.find(callerPid);
    if (iter == callerMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid pid");
        return;
    }
    if (iter->second->bundleName_ == bundleName) {
        counter_.Decrement(iter->second->counter_.Value());
        callerMap_.erase(callerPid);
        PRINT_HILOGI("remove callerPid: %{public}d", callerPid);
    }
}

void PrintCallerAppMonitor::MonitorCallerApps(std::function<bool()> unloadTask)
{
    if (!unloadTask) {
        PRINT_HILOGE("unloadTask is nullptr");
        return;
    }
    std::this_thread::sleep_for(std::chrono::seconds(CHECK_CALLER_APP_INTERVAL));
    PRINT_HILOGI("start monitor caller apps");
    do {
        {
            std::lock_guard<std::mutex> lock(callerMapMutex_);
            for (auto iter = callerMap_.begin(); iter != callerMap_.end();) {
                if (iter->second == nullptr) {
                    iter = callerMap_.erase(iter);
                    continue;
                }
                PRINT_HILOGI(
                    "check caller process, pid: %{public}d, bundleName: %{public}s",
                    iter->first, iter->second->bundleName_.c_str());
                if (IsAppAlive(iter->second)) {
                    PRINT_HILOGI("app still alive");
                    iter++;
                    continue;
                }
                int value = iter->second->counter_.Value();
                if (value) {
                    counter_.Decrement(value);
                }
                PRINT_HILOGI("app not alive, erase it");
                iter = callerMap_.erase(iter);
            }
            PRINT_HILOGI("callerMap size: %{public}lu", callerMap_.size());
        }
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_CALLER_APP_INTERVAL));

        if (delayUnload_.load()) {
            PRINT_HILOGW("delay unload print SA");
            delayUnload_.store(false);
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(callerMapMutex_);
            if ((callerMap_.empty() || counter_.Value() == 0) && unloadTask()) {
                isMonitoring_.store(false);
            }
        }
    } while (isMonitoring_.load());
}

sptr<AppExecFwk::IAppMgr> PrintCallerAppMonitor::GetAppManager()
{
    auto sysAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysAbilityMgr == nullptr) {
        PRINT_HILOGE("GetSystemAbilityManager fail");
        return nullptr;
    }
    auto remoteObject = sysAbilityMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        PRINT_HILOGE("GetSystemAbility fail");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(remoteObject);
}

std::vector<AppExecFwk::RunningProcessInfo> PrintCallerAppMonitor::GetRunningProcessInformation(
    const std::string &bundleName, int32_t userId)
{
    std::vector<AppExecFwk::RunningProcessInfo> processInfos;
    auto appManager = GetAppManager();
    if (appManager == nullptr) {
        PRINT_HILOGE("appManager is nullptr");
        return processInfos;
    }
    int32_t ret = appManager->GetRunningProcessInformation(bundleName, userId, processInfos);
    if (ret != ERR_OK) {
        PRINT_HILOGE("GetRunningProcessInformation fail");
        return processInfos;
    }
    return processInfos;
}

bool PrintCallerAppMonitor::GetRunningProcessInfoByPid(const pid_t pid, AppExecFwk::RunningProcessInfo &processInfo)
{
    auto appManager = GetAppManager();
    if (appManager == nullptr) {
        PRINT_HILOGE("appManager is nullptr");
        return false;
    }
    int32_t ret = appManager->GetRunningProcessInfoByPid(pid, processInfo);
    if (ret != ERR_OK) {
        PRINT_HILOGE("GetRunningProcessInfoByPid fail");
        return false;
    }
    return true;
}

bool PrintCallerAppMonitor::IsProcessForeground(const pid_t pid)
{
    PRINT_HILOGI("pid: %{public}d", pid);
    AppExecFwk::RunningProcessInfo processInfo;
    if (!GetRunningProcessInfoByPid(pid, processInfo)) {
        PRINT_HILOGE("GetRunningProcessInfoByPid fail");
        return false;
    }
    AppExecFwk::AppProcessState state = processInfo.state_;
    PRINT_HILOGI("state: %{public}d", state);
    if (state < AppExecFwk::AppProcessState::APP_STATE_FOREGROUND ||
        state > AppExecFwk::AppProcessState::APP_STATE_BACKGROUND) {
        PRINT_HILOGW("Process background");
        return false;
    }
    PRINT_HILOGD("Process foreground");
    return true;
}

bool PrintCallerAppMonitor::IsAppAlive(std::shared_ptr<PrintCallerAppInfo> callerAppInfo)
{
    std::vector<AppExecFwk::RunningProcessInfo> processInfos =
        GetRunningProcessInformation(callerAppInfo->bundleName_, callerAppInfo->userId_);
    for (auto &processInfo : processInfos) {
        PRINT_HILOGD("processName: %{public}s, pid: %{public}d", processInfo.processName_.c_str(), processInfo.pid_);
        if (processInfo.pid_ == callerAppInfo->pid_ &&
            processInfo.processName_.find(PRINT_EXTENSION_SUFFIX) == std::string::npos) {
            return true;
        }
    }
    return false;
}

int32_t PrintCallerAppMonitor::GetCurrentUserId()
{
    constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
    int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (userId <= 0) {
        PRINT_HILOGD("print sa calling, use current active userId");
        std::vector<int32_t> userIds;
        AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            PRINT_HILOGE("get current active userId failed");
            userId = AppExecFwk::Constants::INVALID_USERID;
        } else {
            userId = userIds[0];
        }
    }
    PRINT_HILOGD("Current userId = %{private}d.", userId);
    return userId;
}

void PrintCallerAppMonitor::IncrementPrintCounter(const std::string &jobId)
{
    PRINT_HILOGI("IncrementPrintCounter enter");
    if (!jobId.empty()) {
        std::lock_guard<std::mutex> lock(printJobMapMutex_);
        printJobMap_[jobId] = true;
    }
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    counter_.Increment();
}

void PrintCallerAppMonitor::DecrementPrintCounter(const std::string &jobId)
{
    PRINT_HILOGI("DecrementPrintCounter enter");
    if (!jobId.empty()) {
        std::lock_guard<std::mutex> lock(printJobMapMutex_);
        auto jobIter = printJobMap_.find(jobId);
        if (jobIter == printJobMap_.end() || jobIter->second == false) {
            PRINT_HILOGE("skip this job");
            return;
        }
        printJobMap_[jobId] = false;
    }
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    counter_.Decrement();
}

void PrintCallerAppMonitor::IncrementCallerAppCounter()
{
    PRINT_HILOGI("IncrementCallerAppCounter enter");
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    auto callerIter = callerMap_.find(callerPid);
    if (callerIter == callerMap_.end() || callerIter->second == nullptr) {
        PRINT_HILOGE("Invalid pid");
        return;
    }
    callerIter->second->counter_.Increment();
}

void PrintCallerAppMonitor::RemovePrintJobFromMap(const std::string &jobId)
{
    if (!jobId.empty()) {
        std::lock_guard<std::mutex> lock(printJobMapMutex_);
        auto jobIter = printJobMap_.find(jobId);
        if (jobIter != printJobMap_.end()) {
            printJobMap_.erase(jobIter);
        }
    }
}

bool PrintCallerAppMonitor::CheckCallerAppInMap(int32_t callerPid, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    auto iter = callerMap_.find(callerPid);
    if (iter == callerMap_.end() || iter->second == nullptr) {
        PRINT_HILOGW("not in caller map");
        return false;
    }
    if (bundleName != iter->second->bundleName_) {
        return false;
    }
    return true;
}
} // namespace OHOS::Print
