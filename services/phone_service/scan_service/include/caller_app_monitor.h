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

#ifndef CALLER_APP_MONITOR
#define CALLER_APP_MONITOR

#include <string>
#include <map>
#include <mutex>
#include <functional>
#include "scanner_info.h"
#include "app_mgr_interface.h"

namespace OHOS::Scan {
class CallerAppInfo {
public:
    int32_t pid_;
    std::string bundleName_;
    CallerAppInfo(int32_t pid, std::string bundleName) : pid_(pid),
        bundleName_(bundleName) {};
};

class CallerAppMonitor {
public:
    static CallerAppMonitor& GetInstance();
    void QueryCallerAppAndSave();
    void StartCallerAppMonitor(std::function<void()> unloadTask);

private:
    CallerAppMonitor() = default;
    ~CallerAppMonitor() = default;

    std::string QueryCallerBundleName(const int32_t callerPid);
    void MonitorCallerAppIsRunnig(std::function<void()> unloadTask);
    bool IsAppAlive(std::shared_ptr<CallerAppInfo> info);
    std::map<int32_t, std::shared_ptr<CallerAppInfo>> callerMap_;
    std::mutex callerMapMutex_;
    std::atomic<bool> isMonitoring_{false};
};

} // namespace OHOS::Scan
#endif // CALLER_APP_MONITOR