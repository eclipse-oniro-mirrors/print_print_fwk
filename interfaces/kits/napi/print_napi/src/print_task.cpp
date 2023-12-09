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
#include "print_utils.h"

namespace OHOS::Print {
const std::string EVENT_BLOCK = "block";
const std::string EVENT_SUCCESS = "succeed";
const std::string EVENT_FAIL = "fail";
const std::string EVENT_CANCEL = "cancel";

PrintTask::PrintTask(const std::vector<std::string> &innerList, const sptr<IRemoteObject> &innerCallerToken_)
    : taskId_("")
{
    if (innerList.begin()->find("fd://") == 0) {
        PRINT_HILOGD("list type: fdlist");
        for (auto fdPath : innerList) {
            pathType_ = FD_PATH;
            uint32_t fd = PrintUtils::GetIdFromFdPath(fdPath);
            fdList_.emplace_back(fd);
        }
    } else {
        PRINT_HILOGD("list type: filelist");
        fileList_.assign(innerList.begin(), innerList.end());
        pathType_ = FILE_PATH_ABSOLUTED;
        if (fileList_.size() > 0) {
            if (fileList_.begin()->find("file://") == 0) {
                pathType_ = FILE_PATH;
            }
        }
    }

    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;
    callerToken_ = innerCallerToken_;
}

PrintTask::PrintTask(const std::string &innerPrintJobName_, const sptr<IPrintCallback> &innerPrintAdapterCallback_,
    const std::shared_ptr<PrintAttributes> &innerPrintAttributes_, const sptr<IRemoteObject> &innerCallerToken_)
    : taskId_("")
{
    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;
    printJobName_ = innerPrintJobName_;
    printAdapterCallback_ = innerPrintAdapterCallback_;
    printAttributes_ = innerPrintAttributes_;
    callerToken_ = innerCallerToken_;
}

PrintTask::~PrintTask()
{
    supportEvents_.clear();
    Stop();
}

uint32_t PrintTask::Start()
{
    if (fileList_.empty() && fdList_.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    if (pathType_ == FILE_PATH_ABSOLUTED) {
        for (auto file : fileList_) {
            int32_t fd = PrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList_.emplace_back(fd);
        }
    }
    if (callerToken_ != nullptr && NEW_PRINT_INTERFACE_SWITCH) {
        PRINT_HILOGI("call client's new StartPrint interface.");
        return PrintManagerClient::GetInstance()->StartPrint(fileList_, fdList_, taskId_, callerToken_);
    } else {
        PRINT_HILOGI("call client's old StartPrint interface.");
        return PrintManagerClient::GetInstance()->StartPrint(fileList_, fdList_, taskId_);
    }
}

uint32_t PrintTask::StartPrintAdapter()
{
    if (printAdapterCallback_ != nullptr && printAttributes_ != nullptr) {
        PRINT_HILOGI("call client's StartPrintAdapter interface.");
        return PrintManagerClient::GetInstance()->Print(
            printJobName_, printAdapterCallback_, *printAttributes_, taskId_, static_cast<void*>(callerToken_));
    }
    return E_PRINT_INVALID_PARAMETER;
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
        PRINT_HILOGD("context->result = %{public}d", context->result);
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
