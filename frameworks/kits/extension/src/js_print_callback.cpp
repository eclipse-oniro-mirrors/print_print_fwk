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

#include "js_print_callback.h"

#include "ability_info.h"
#include "iprint_extension_callback.h"
#include "js_print_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_print_utils.h"
#include "napi_remote_object.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;

JsPrintCallback::JsPrintCallback(JsRuntime &jsRuntime) : jsRuntime_(jsRuntime), jsWorker_(nullptr) {}  

uv_loop_s* JsPrintCallback::GetJsLoop(JsRuntime &jsRuntime)
{
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(reinterpret_cast<napi_env>(nativeEngine), &loop);
    if (loop == nullptr) {
        return nullptr;
    }
    return loop;
}

bool JsPrintCallback::BuildJsWorker(NativeValue *jsObj, const std::string &name,
    NativeValue *const *argv, size_t argc, bool isSync)
{
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(jsObj);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return false;
    }

    NativeValue *method = obj->GetProperty(name.c_str());
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get '%{public}s' from PrintExtension object", name.c_str());
        return false;
    }

    jsWorker_ = new (std::nothrow) uv_work_t;
    if (jsWorker_ == nullptr) {
        PRINT_HILOGE("Failed to create uv work");
        return false;
    }

    jsParam_.self = shared_from_this();
    jsParam_.nativeEngine = &jsRuntime_.GetNativeEngine();
    jsParam_.jsObj = jsObj;
    jsParam_.jsMethod = method;
    jsParam_.argv = argv;
    jsParam_.argc = argc;
    jsParam_.jsResult = nullptr;
    jsParam_.isSync = isSync;
    jsParam_.isCompleted = false;
    jsWorker_->data = &jsParam_;
    return true;
}

NativeValue *JsPrintCallback::Exec(
    NativeValue *jsObj, const std::string &name, NativeValue *const *argv, size_t argc, bool isSync)
{
    PRINT_HILOGD("%{public}s callback in", name.c_str());
    HandleScope handleScope(jsRuntime_);
    uv_loop_s *loop = GetJsLoop(jsRuntime_);
    if (loop == nullptr) {
        PRINT_HILOGE("Failed to acquire js event loop");
        return nullptr;
    }
    if (!BuildJsWorker(jsObj, name, argv, argc, isSync)) {
        PRINT_HILOGE("Failed to build JS worker");
        return nullptr;
    }
    uv_queue_work(
        loop, jsWorker_, [](uv_work_t *work) {},
        [](uv_work_t *work, int statusInt) {
            auto jsWorkParam = reinterpret_cast<JsPrintCallback::JsWorkParam*>(work->data);
            if (jsWorkParam != nullptr) {
                jsWorkParam->jsResult = jsWorkParam->nativeEngine->CallFunction(
                    jsWorkParam->jsObj, jsWorkParam->jsMethod, jsWorkParam->argv, jsWorkParam->argc);
                jsWorkParam->isCompleted = true;
                if (jsWorkParam->isSync) {
                    jsWorkParam->self = nullptr;
                } else {
                    std::unique_lock<std::mutex> lock(jsWorkParam->self->conditionMutex_);
                    jsWorkParam->self->syncCon_.notify_one();
                }
            }
        });
    if (isSync) {
        std::unique_lock<std::mutex> conditionLock(conditionMutex_);
        auto waitStatus = syncCon_.wait_for(
            conditionLock, std::chrono::milliseconds(SYNC_TIME_OUT), [this]() { return jsParam_.isCompleted; });
        if (!waitStatus) {
            PRINT_HILOGE("print server load sa timeout");
            return nullptr;
        }
        return jsParam_.jsResult;
    }
    return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS
