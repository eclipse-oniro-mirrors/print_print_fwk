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
#include "scan_log.h"
#include "scan_constant.h"
#include "caller_app_monitor.h"

namespace OHOS::Scan {
static constexpr uint32_t CHECK_CALLER_APP_INTERVAL = 60;

CallerAppMonitor& CallerAppMonitor::GetInstance()
{
    static CallerAppMonitor instance;
    return instance;
}

void CallerAppMonitor::QueryCallerAppAndSave()
{
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string bundleName = QueryCallerBundleName(callerPid);
    if (!bundleName.empty()) {
        std::lock_guard<std::mutex> autoLock(callerMapMutex_);
        auto info = std::make_shared<CallerAppInfo>(callerPid, bundleName);
        callerMap_[callerPid] = info;
    }
}

std::string CallerAppMonitor::QueryCallerBundleName(const int32_t callerPid)
{
    std::string bundleName;
    
    int32_t uid = 0;
    AppExecFwk::AppMgrClient appMgrClient;
    int32_t ret = appMgrClient.GetBundleNameByPid(callerPid, bundleName, uid);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("GetBundleNameByPid fail, ret = %{public}d", ret);
        return "";
    }
    SCAN_HILOGD("bundleName: %{private}s", bundleName.c_str());
    return bundleName;
}

void CallerAppMonitor::StartCallerAppMonitor(std::function<void()> unloadTask)
{
    if (isMonitoring_.load()) {
        SCAN_HILOGD("The monitoring thread is running");
        return;
    }
    isMonitoring_.store(true);
    std::thread callerAppMonitorThread(&CallerAppMonitor::MonitorCallerAppIsRunnig, this, unloadTask);
    callerAppMonitorThread.detach();
}

void CallerAppMonitor::MonitorCallerAppIsRunnig(std::function<void()> unloadTask)
{
    if (!unloadTask) {
        SCAN_HILOGE("unloadTask is nullptr");
        return;
    }
    while (isMonitoring_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_CALLER_APP_INTERVAL));
        {
            std::lock_guard<std::mutex> autoLock(callerMapMutex_);
            for (auto iter = callerMap_.begin(); iter != callerMap_.end();) {
                if (IsAppAlive(iter->second)) {
                    SCAN_HILOGI("app still alive");
                    iter++;
                    continue;
                } else {
                    SCAN_HILOGI("app not alive");
                    iter = callerMap_.erase(iter);
                }
            }
            if (callerMap_.empty()) {
                SCAN_HILOGI("No apps use, start uninstalling scan_service");
                isMonitoring_.store(false);
                unloadTask();
            }
        }
    }
}

bool CallerAppMonitor::IsAppAlive(std::shared_ptr<CallerAppInfo> info)
{
    if (info == nullptr) {
        SCAN_HILOGW("info is a nullptr");
        return false;
    }
    AppExecFwk::AppMgrClient appMgrClient;
    AppExecFwk::RunningProcessInfo runningInfo;
    SCAN_HILOGI("Check app alive: bundleName=%{private}s, pid=%{public}d", info->bundleName_.c_str(), info->pid_);
    int32_t ret = appMgrClient.GetRunningProcessInfoByPid(info->pid_, runningInfo);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGW("GetRunningProcessInfoByPid fail, ret = %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace OHOS::Scan
