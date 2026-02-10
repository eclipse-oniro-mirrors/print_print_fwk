/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "watermark_callback.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
WatermarkCallback::WatermarkCallback(napi_env env, napi_ref ref)
    : env_(env), ref_(ref), mutex_(std::make_shared<std::mutex>())
{
}

WatermarkCallback::~WatermarkCallback()
{
    auto mutexPtr = mutex_;
    std::lock_guard<std::mutex> autoLock(*mutexPtr);
    struct Param {
        napi_env env;
        napi_ref callbackRef;
    };

    Param *param = new (std::nothrow) Param;
    if (param == nullptr) {
        return;
    }
    param->env = env_;
    param->callbackRef = ref_;

    auto task = [param]() {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            PRINT_HILOGE("scope is a nullptr");
            delete param;
            return;
        }
        napi_ref callbackRef_ = param->callbackRef;
        NapiPrintUtils::DeleteReference(param->env, callbackRef_);
        napi_close_handle_scope(param->env, scope);
        delete param;
    };

    napi_status ret = napi_send_event(env_, task, napi_eprio_immediate);
    if (ret != napi_ok) {
        PRINT_HILOGE("napi_send_event fail");
        delete param;
    }
}

void WatermarkCallback::ExecuteCallback(WatermarkCallbackParam *param)
{
    if (param == nullptr) {
        PRINT_HILOGE("param is a nullptr");
        return;
    }
    std::lock_guard<std::mutex> autoLock(*param->mutexPtr);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(param->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("fail to open scope");
        close(param->fd);
        delete param;
        return;
    }

    napi_value callbackFunc = NapiPrintUtils::GetReference(param->env, param->ref);
    if (callbackFunc == nullptr) {
        PRINT_HILOGE("WatermarkCallback get reference failed");
        close(param->fd);
        napi_close_handle_scope(param->env, scope);
        delete param;
        return;
    }

    napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
    callbackValues[0] = NapiPrintUtils::CreateStringUtf8(param->env, param->jobId);
    callbackValues[1] = NapiPrintUtils::CreateUint32(param->env, param->fd);

    napi_value result = nullptr;
    napi_status status = napi_call_function(param->env, nullptr, callbackFunc,
        NapiPrintUtils::ARGC_TWO, callbackValues, &result);
    if (status == napi_ok) {
        PRINT_HILOGI("WatermarkCallback call JS function success");
    } else {
        PRINT_HILOGE("WatermarkCallback call JS function failed, status:%{public}d", status);
        close(param->fd);
    }

    napi_close_handle_scope(param->env, scope);
    delete param;
}

void WatermarkCallback::OnCallback(const std::string &jobId, uint32_t fd)
{
    PRINT_HILOGI("WatermarkCallback OnCallback jobId:%{public}s, fd:%{public}u",
        jobId.c_str(), fd);

    WatermarkCallbackParam *param = new (std::nothrow) WatermarkCallbackParam;
    if (param == nullptr) {
        PRINT_HILOGE("Failed to create watermark callback parameter");
        close(fd);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(*mutex_);
        param->env = env_;
        param->ref = ref_;
        param->mutexPtr = mutex_;
        param->jobId = jobId;
        param->fd = fd;
    }

    auto task = [param]() { ExecuteCallback(param); };

    napi_status ret = napi_send_event(env_, task, napi_eprio_immediate);
    if (ret != napi_ok) {
        PRINT_HILOGE("napi_send_event fail");
        close(fd);
        delete param;
    }
}
} // namespace OHOS::Print
