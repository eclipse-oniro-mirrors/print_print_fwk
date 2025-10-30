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
    std::string bundleName = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::vector<AppExecFwk::RunningProcessInfo> processInfos = GetRunningProcessInformation(bundleName);
    for (auto &processInfo : processInfos) {
        PRINT_HILOGD("processName: %{public}s, processId: %{public}d, callerPid: %{public}d",
            processInfo.processName_.c_str(),
            processInfo.pid_,
            callerPid);
        if (processInfo.pid_ != 0 && !bundleName.empty() && callerPid == processInfo.pid_ &&
            processInfo.processName_.find(PRINT_EXTENSION_SUFFIX) == std::string::npos) {
            {
                auto callerAppInfo = std::make_shared<PrintCallerAppInfo>(callerPid, bundleName);
                std::lock_guard<std::mutex> lock(callerMapMutex_);
                callerMap_[callerPid] = callerAppInfo;
            }
            PRINT_HILOGI("add callerPid: %{public}d", callerPid);
        }
    }
}

void PrintCallerAppMonitor::RemoveCallerAppFromMap()
{
    std::string bundleName = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::lock_guard<std::mutex> lock(callerMapMutex_);
    auto iter = callerMap_.find(callerPid);
    if (iter == callerMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid pid");
        return;
    }
    if (iter->second->bundleName_ == bundleName) {
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
    PRINT_HILOGI("start monitor caller apps");
    while (isMonitoring_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_CALLER_APP_INTERVAL));
        {
            std::lock_guard<std::mutex> lock(callerMapMutex_);
            for (auto iter = callerMap_.begin(); iter != callerMap_.end();) {
                PRINT_HILOGI(
                    "check caller process, pid: %{public}d, bundleName: %{public}s",
                    iter->first, iter->second->bundleName_.c_str());
                if (IsAppAlive(iter->second)) {
                    PRINT_HILOGI("app still alive");
                    iter++;
                    continue;
                } else {
                    PRINT_HILOGI("app not alive, erase it");
                    iter = callerMap_.erase(iter);
                }
            }
            PRINT_HILOGI("callerMap size: %{public}lu", callerMap_.size());

            if ((callerMap_.empty() || counter_.Value() == 0) && unloadTask()) {
                isMonitoring_.store(false);
            }
        }
    }
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
    const std::string &bundleName)
{
    std::vector<AppExecFwk::RunningProcessInfo> processInfos;
    auto appManager = GetAppManager();
    if (appManager == nullptr) {
        PRINT_HILOGE("appManager is nullptr");
        return processInfos;
    }
    int32_t userId = GetCurrentUserId();
    if (userId == AppExecFwk::Constants::INVALID_USERID) {
        PRINT_HILOGE("Invalid user id.");
        return processInfos;
    }
    int32_t ret = appManager->GetRunningProcessInformation(bundleName, userId, processInfos);
    if (ret != ERR_OK) {
        PRINT_HILOGE("GetRunningProcessInformation fail");
        return processInfos;
    }
    return processInfos;
}

bool PrintCallerAppMonitor::IsAppAlive(std::shared_ptr<PrintCallerAppInfo> callerAppInfo)
{
    std::vector<AppExecFwk::RunningProcessInfo> processInfos = GetRunningProcessInformation(callerAppInfo->bundleName_);
    for (auto &processInfo : processInfos) {
        PRINT_HILOGD("processName: %{public}s, pid: %{public}d", processInfo.processName_.c_str(), processInfo.pid_);
        if (processInfo.pid_ == callerAppInfo->pid_ && processInfo.processName_.find(PRINT_EXTENSION_SUFFIX) == std::string::npos) {
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
    PRINT_HILOGD("Current userId = %{public}d.", userId);
    return userId;
}

void PrintCallerAppMonitor::IncrementPrintCounter()
{
    counter_.Increment();
}

void PrintCallerAppMonitor::DecrementPrintCounter()
{
    counter_.Decrement();
}
} // namespace OHOS::Print
