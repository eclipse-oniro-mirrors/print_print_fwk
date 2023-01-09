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
#include "napi/native_common.h"
#include "napi_print_utils.h"
#include "print_callback.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS::Print {

const std::string EVENT_BLOCK = "blocked";
const std::string EVENT_SUCCESS = "success";
const std::string EVENT_FAIL = "failed";
const std::string EVENT_CANCEL = "cancelled";
PrintTask::PrintTask(const std::vector<std::string> &fileList) : taskId_("")
{
    fileList_.assign(fileList.begin(), fileList.end());
    isNormalFilePath_ = true;
    if (fileList_.size() > 0) {
        if (fileList_.begin()->find("datashare://") == 0) {
            isNormalFilePath_ = false;
        }
    }
    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;
}

PrintTask::~PrintTask()
{
    supportEvents_.clear();
    Stop();
}

uint32_t PrintTask::Start()
{
    if (fileList_.empty()) {
        PRINT_HILOGE("file list is empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::vector<uint32_t> fdList;
    if (isNormalFilePath_) {
        for (auto file : fileList_) {
            int32_t fd = NapiPrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{public}s] is invalid", file.c_str());
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList.emplace_back(fd);
        }
    }
    return PrintManagerClient::GetInstance()->StartPrint(fileList_, fdList, taskId_);
}

void PrintTask::Stop()
{
    PrintManagerClient::GetInstance()->StopPrint(taskId_);
    taskId_ = "";
}

const std::string &PrintTask::GetId() const
{
    return taskId_;
}

napi_value PrintTask::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_TWO, "need 2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    valuetype = napi_undefined;
    napi_typeof(env, argv[1], &valuetype);
    PRINT_ASSERT(env, valuetype == napi_function, "callback is not a function");

    PrintTask *task;
    PRINT_CALL(env, napi_unwrap(env, thisVal, reinterpret_cast<void **>(&task)));
    if (task == nullptr || !task->IsSupportType(type)) {
        PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
        return nullptr;
    }

    napi_ref callbackRef = NapiPrintUtils::CreateReference(env, argv[1]);
    sptr<IPrintCallback> callback = new (std::nothrow) PrintCallback(env, callbackRef);
    if (callback == nullptr) {
        PRINT_HILOGE("create print callback object fail");
        return nullptr;
    }
    int32_t ret = PrintManagerClient::GetInstance()->On(task->taskId_, type, callback);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to register event");
        return nullptr;
    }
    return nullptr;
}

napi_value PrintTask::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<TaskEventContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, "need 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "type is not a string", napi_string_expected);
        std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        PrintTask *task;
        PRINT_CALL_BASE(env, napi_unwrap(env, self, reinterpret_cast<void **>(&task)), napi_invalid_arg);
        if (task == nullptr || !task->IsSupportType(type)) {
            PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }

        context->type = type;
        context->taskId = task->taskId_;
        PRINT_HILOGD("event type : %{public}s", context->type.c_str());
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("context->result = %{public}d, result = %{public}p", context->result, result);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->Off(context->taskId, context->type);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to unregistered event");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

bool PrintTask::IsSupportType(const std::string &type) const
{
    return supportEvents_.find(type) != supportEvents_.end();
}
} // namespace OHOS::Print
