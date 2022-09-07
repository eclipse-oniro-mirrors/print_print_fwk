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

#include "print_task.h"

#include "async_call.h"
#include "print_log.h"

namespace OHOS::Print {
PrintTask::PrintTask(uint32_t taskId) : taskId_(taskId)
{
    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;

    supportPrinterState_[PRINTER_STATE_ADD] = true;
    supportPrinterState_[PRINTER_STATE_REMOVED] = true;
    supportPrinterState_[PRINTER_STATE_IDLE] = true;
    supportPrinterState_[PRINTER_STATE_PRINTING] = true;
    supportPrinterState_[PRINTER_STATE_BLOCKED] = true;
    supportPrinterState_[PRINTER_STATE_BUSY] = true;
    supportPrinterState_[PRINTER_STATE_FAILED] = true;

    supportJobState_[PRINTJOB_STATE_CREATED] = true;
    supportJobState_[PRINTJOB_STATE_QUEUED] = true;
    supportJobState_[PRINTJOB_STATE_PRINTING] = true;
    supportJobState_[PRINTJOB_STATE_BLOCKED] = true;
    supportJobState_[PRINTJOB_STATE_SUCCESS] = true;
    supportJobState_[PRINTJOB_STATE_FAILED] = true;
    supportJobState_[PRINTJOB_STATE_cancelled] = true;
}

PrintTask::~PrintTask()
{
    supportEvents_.clear();
}

uint32_t PrintTask::GetId() const
{
    return taskId_;
}

napi_value PrintTask::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    return nullptr;
}

napi_value PrintTask::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    return nullptr;
}

bool PrintTask::IsSupportType(const std::string &type)
{
    return supportEvents_.find(type) != supportEvents_.end();
}

bool PrintTask::IsSupportPrinterStateType(const std::string &type)
{
    return supportPrinterState_.find(type) != supportPrinterState_.end();
}

bool PrintTask::IsSupportJobStateType(const std::string &type)
{
    PRINT_HILOGD("Enter IsSupportJobStateType.");
    return supportJobState_.find(type) != supportJobState_.end();
}
} // namespace OHOS::Print
