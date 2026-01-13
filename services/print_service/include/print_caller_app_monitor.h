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
class PrintCounter {
private:
    std::atomic<int> count_{0};
public:
    void Increment()
    {
        count_.fetch_add(1, std::memory_order_relaxed);
        Value();
    }
    void Decrement(int num = 1)
    {
        int value = count_.load(std::memory_order_relaxed);
        if (value > 0) {
            count_.fetch_add(-num, std::memory_order_relaxed);
        }
        Value();
    }
    int Value() const
    {
        int value = count_.load(std::memory_order_relaxed);
        PRINT_HILOGI("PrintCounter value: %{public}d", value);
        return value;
    }
    PrintCounter() = default;
    PrintCounter(const PrintCounter &right) : count_(right.count_.load(std::memory_order_relaxed)) {}
    PrintCounter& operator=(const PrintCounter &right)
    {
        if (this != &right) {
            count_.store(right.count_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }
    ~PrintCounter() = default;
};

class PrintCallerAppInfo {
public:
    int32_t pid_;
    int32_t userId_;
    std::string bundleName_;
    PrintCounter counter_;
    PrintCallerAppInfo(int32_t pid, int32_t userId, std::string bundleName) : pid_(pid), userId_(userId),
        bundleName_(bundleName), counter_() {
    };
    PrintCallerAppInfo(const PrintCallerAppInfo &right)
        : pid_(right.pid_), 
        userId_(right.userId_), 
        bundleName_(right.bundleName_), 
        counter_(right.counter_)
    {
    }
    PrintCallerAppInfo& operator=(const PrintCallerAppInfo &right)
    {
        if (this != &right) {
            pid_ = right.pid_;
            userId_ = right.userId_;
            bundleName_ = right.bundleName_;
            counter_ = right.counter_;
        }
        return *this;
    }
    ~PrintCallerAppInfo() = default;
};

class PrintCallerAppMonitorBase {
public:
    virtual bool IsProcessForeground(const pid_t pid) = 0;
    virtual bool GetRunningProcessInfoByPid(const pid_t pid, AppExecFwk::RunningProcessInfo &processInfo) = 0;
};

class PrintCallerAppMonitor : public PrintCallerAppMonitorBase {
public:
    static PrintCallerAppMonitor& GetInstance();
    void AddCallerAppToMap();
    void RemoveCallerAppFromMap();
    void StartCallerAppMonitor(std::function<bool()> unloadTask);
    void IncrementPrintCounter(const std::string &jobId);
    void DecrementPrintCounter(const std::string &jobId);
    void IncrementCallerAppCounter();
    void RemovePrintJobFromMap(const std::string &jobId);
    bool IsAppAlive(std::shared_ptr<PrintCallerAppInfo> callerAppInfo);
    bool IsProcessForeground(const pid_t pid) override;
    bool GetRunningProcessInfoByPid(const pid_t pid, AppExecFwk::RunningProcessInfo &processInfo) override;

private:
    PrintCallerAppMonitor() = default;
    ~PrintCallerAppMonitor() = default;

    void MonitorCallerApps(std::function<bool()> unloadTask);
    sptr<AppExecFwk::IAppMgr> GetAppManager();
    std::vector<AppExecFwk::RunningProcessInfo> GetRunningProcessInformation(
        const std::string &bundleName, int32_t userId);
    int32_t GetCurrentUserId();
    bool CheckCallerAppInMap(int32_t callerPid, const std::string &bundleName);

    std::map<int32_t, std::shared_ptr<PrintCallerAppInfo>> callerMap_;
    std::map<std::string, bool> printJobMap_;
    std::mutex callerMapMutex_;
    std::mutex printJobMapMutex_;
    std::atomic<bool> isMonitoring_{false};
    PrintCounter counter_;
    std::atomic<bool> delayUnload_{false};
};

} // namespace OHOS::Print
#endif // PRINT_CALLER_APP_MONITOR