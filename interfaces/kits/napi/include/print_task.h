/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_TASK_H
#define PRINT_TASK_H

#include <map>
#include <mutex>
#include <string>

#include "napi/native_api.h"

static constexpr const char *EVENT_BLOCK = "blocked";
static constexpr const char *EVENT_SUCCESS = "success";
static constexpr const char *EVENT_FAIL = "failed";
static constexpr const char *EVENT_CANCEL = "cancelled";

static constexpr const char *PRINTER_STATE_ADD = "PRINTER_ADDED";
static constexpr const char *PRINTER_STATE_REMOVED = "PRINTER_REMOVED";
static constexpr const char *PRINTER_STATE_IDLE = "PRINTER_IDLE";
static constexpr const char *PRINTER_STATE_PRINTING = "PRINTER_PRINTING";
static constexpr const char *PRINTER_STATE_BLOCKED = "PRINTER_BLOCKED";
static constexpr const char *PRINTER_STATE_BUSY = "PRINTER_BUSY";
static constexpr const char *PRINTER_STATE_FAILED = "PRINTER_FAILED";

static constexpr const char *PRINTJOB_STATE_CREATED = "PRINT_JOB_CREATED";
static constexpr const char *PRINTJOB_STATE_QUEUED = "PRINT_JOB_QUEUED";
static constexpr const char *PRINTJOB_STATE_PRINTING = "PRINT_JOB_PRINTING";
static constexpr const char *PRINTJOB_STATE_BLOCKED = "PRINT_JOB_BLOCKED";
static constexpr const char *PRINTJOB_STATE_SUCCESS = "PRINT_JOB_SUCCESS";
static constexpr const char *PRINTJOB_STATE_FAILED = "PRINT_JOB_FAILED";
static constexpr const char *PRINTJOB_STATE_cancelled = "PRINT_JOB_cancelled";

namespace OHOS::Print {
class PrintTask {
public:
    explicit PrintTask(uint32_t taskId);
    ~PrintTask();

    uint32_t GetId() const;
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    //bool AddListener(const std::string &type, sptr<PrintNotifyInterface> listener);
    //void RemoveListener(const std::string &type, sptr<PrintNotifyInterface> listener);
    //void RemoveListener(const std::string &type);

    bool IsSupportType(const std::string &type);
    bool IsSupportPrinterStateType(const std::string &type);
    bool IsSupportJobStateType(const std::string &type);
private:
    int taskId_;
    std::mutex mutex_;
    //std::map<std::string, sptr<PrintNotifyInterface>> listenerMap_;
    std::map<std::string, bool> supportEvents_;
    std::map<std::string, bool> supportPrinterState_;
    std::map<std::string, bool> supportJobState_;
};
} // namespace OHOS::Print
#endif // PRINT_TASK_H
