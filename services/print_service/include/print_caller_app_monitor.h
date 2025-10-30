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

#ifndef PRINT_CALLER_APP_MONITOR
#define PRINT_CALLER_APP_MONITOR

#include <string>
#include <map>
#include <mutex>
#include <functional>
#include "app_mgr_interface.h"

#include "print_log.h"

namespace OHOS::Print {
class PrintCallerAppInfo {
public:
    int32_t pid_;
    std::string bundleName_;
    PrintCallerAppInfo(int32_t pid, std::string bundleName) : pid_(pid),
        bundleName_(bundleName) {};
};

class PrintCounter {
private:
    std::atomic<int> count_{0};
public:
    void Increment() {
        count_.fetch_add(1, std::memory_order_relaxed);
        Value();
    }
    void Decrement() {
        int expected;
        do {
            expected = count_.load(std::memory_order_relaxed);
            if (expected == 0) {
                return;
            }
        } while (!count_.compare_exchange_weak(
            expected, expected - 1, std::memory_order_relaxed, std::memory_order_relaxed));
        Value();
    }
    int Value() const {
        int value = count_.load(std::memory_order_relaxed);
        PRINT_HILOGI("PrintCounter value: %{public}d", value);
        return value;
    }
};

class PrintCallerAppMonitor {
public:
    static PrintCallerAppMonitor& GetInstance();
    void AddCallerAppToMap();
    void RemoveCallerAppFromMap();
    void StartCallerAppMonitor(std::function<bool()> unloadTask);
    void IncrementPrintCounter();
    void DecrementPrintCounter();

private:
    PrintCallerAppMonitor() = default;
    ~PrintCallerAppMonitor() = default;

    void MonitorCallerApps(std::function<bool()> unloadTask);
    sptr<AppExecFwk::IAppMgr> GetAppManager();
    bool IsAppAlive(std::shared_ptr<PrintCallerAppInfo> callerAppInfo);
    std::vector<AppExecFwk::RunningProcessInfo> GetRunningProcessInformation(const std::string &bundleName);
    int32_t GetCurrentUserId();

    std::map<int32_t, std::shared_ptr<PrintCallerAppInfo>> callerMap_;
    std::mutex callerMapMutex_;
    std::atomic<bool> isMonitoring_{false};
    PrintCounter counter_;
};

} // namespace OHOS::Print
#endif // PRINT_CALLER_APP_MONITOR