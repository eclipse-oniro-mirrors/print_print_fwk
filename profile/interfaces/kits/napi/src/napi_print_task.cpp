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

#include "napi_print_task.h"

#include <mutex>
#include "napi_print_utils.h"
#include "print_async_call.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_task.h"

static constexpr const char *FUNCTION_ON = "on";
static constexpr const char *FUNCTION_OFF = "off";

namespace OHOS::Print {
__thread napi_ref NapiPrintTask::globalCtor = nullptr;
std::mutex printTaskMutex_;

struct PrintTaskContext : public PrintAsyncCall::Context {
    napi_ref ref = nullptr;
    PrintTaskContext() : Context(nullptr, nullptr) {}
    PrintTaskContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)) {};
    virtual ~PrintTaskContext() {}
};

napi_value NapiPrintTask::Print(napi_env env, napi_callback_info info) // PrintTask
{
    PRINT_HILOGD("Enter print JsMain.");
    auto context = std::make_shared<PrintTaskContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PRINT_HILOGD("print parser to native params %{public}d!", static_cast<int>(argc));
        NAPI_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, "need 1 parameter!", napi_invalid_arg);
        bool isFileArray = false;
        napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isFileArray);
        NAPI_ASSERT_BASE(env, isFileArray == true, "files isn't list", napi_invalid_arg);

        uint32_t len = 0;
        NAPI_CALL_BASE(env, napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len), napi_invalid_arg);

        if (!isFileArray || len == 0) {
            context->SetErrorIndex(ERROR_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        
        napi_value proxy = nullptr;
        napi_status status = napi_new_instance(env, GetCtor(env), argc, argv, &proxy);
        if ((proxy == nullptr) || (status != napi_ok)) {
            PRINT_HILOGE("Failed to create print task");
            context->SetErrorIndex(ERROR_GENERIC_FAIL);
            return napi_generic_failure;
        }

        PrintTask *task;
        NAPI_CALL_BASE(env, napi_unwrap(env, proxy, reinterpret_cast<void **>(&task)), napi_invalid_arg);
        uint32_t ret = ERROR_GENERIC_FAIL;
        if (task != nullptr) {
            ret = task->Start();
        }
        if (ret != ERROR_NONE) {
            PRINT_HILOGE("Failed to start print task");
            context->SetErrorIndex(ret);
            return napi_generic_failure;
        }
        napi_create_reference(env, proxy, 1, &(context->ref));
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        if (context->ref == nullptr) {
            *result = NapiPrintUtils::GetUndefined(env);
            return napi_generic_failure;
        }
        napi_status status = napi_get_reference_value(env, context->ref, result);
        napi_delete_reference(env, context->ref);
        return status;
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env);    
}

napi_value NapiPrintTask::GetCtor(napi_env env)
{
    std::lock_guard<std::mutex> lock(printTaskMutex_);
    napi_value cons;
    if (globalCtor != nullptr) {
        NAPI_CALL(env, napi_get_reference_value(env, globalCtor, &cons));
        return cons;
    }

    napi_property_descriptor clzDes[] = {
        { FUNCTION_ON, 0, PrintTask::On, 0, 0, 0, napi_default, 0 },
        { FUNCTION_OFF, 0, PrintTask::Off, 0, 0, 0, napi_default, 0 },
    };
    NAPI_CALL(env, napi_define_class(env, "NapiPrintTask", NAPI_AUTO_LENGTH, Initialize, nullptr,
                       sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &globalCtor));
    return cons;
}

napi_value NapiPrintTask::Initialize(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("constructor print task!");
    napi_value self = nullptr;
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));

    std::vector<std::string> printfiles;
    uint32_t arrayReLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &arrayReLength));
    for (uint32_t index = 0; index < arrayReLength; index++) {
        napi_value filesValue;
        napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &filesValue);
        std::string files = NapiPrintUtils::GetStringFromValueUtf8(env, filesValue);
        PRINT_HILOGD("file[%{public}d] %{public}s", index, files.c_str());
        printfiles.emplace_back(files);
    }

    auto task = new PrintTask(printfiles);
    if (task == nullptr) {
        PRINT_HILOGE("print task fail");
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        PRINT_HILOGD("destructed print task");
        PrintTask *task = reinterpret_cast<PrintTask *>(data);
        delete task;
    };
    if (napi_wrap(env, self, task, finalize, nullptr, nullptr) != napi_ok) {
        finalize(env, task, nullptr);
        return nullptr;
    }
    PRINT_HILOGD("Succeed to allocate print task");
    return self;
}
} // namespace OHOS::Print
