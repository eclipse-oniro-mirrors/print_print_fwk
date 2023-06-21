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

#include "print_callback.h"

namespace OHOS::Print {
PrintCallback::PrintCallback(napi_env env, napi_ref ref) : env_(env), ref_(ref)
{
}

PrintCallback::~PrintCallback()
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    PRINT_HILOGD("callback has been destroyed");
    NapiPrintUtils::DeleteReference(env_, ref_);
    ref_ = nullptr;
}

static bool InitUvWorkCallbackEnv(uv_work_t *work, napi_handle_scope &scope)
{
    bool result = false;
    if (work != nullptr && work->data != nullptr) {
        auto cbParam = static_cast<CallbackParam *>(work->data);
        if (cbParam != nullptr) {
            napi_open_handle_scope(cbParam->env, &scope);
            if (scope != nullptr) {
                result = true;
            }
        }
    }
    return result;
}

static void PrintTaskAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintTaskAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (InitUvWorkCallbackEnv(work, scope)) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
            napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
            napi_value callbackResult = nullptr;
            napi_value callbackValues[NapiPrintUtils::ARGC_ONE] = { 0 };
            callbackValues[0] = NapiPrintUtils::GetUndefined(cbParam->env);
            napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_ZERO,
                callbackValues, &callbackResult);
            napi_close_handle_scope(cbParam->env, scope);
            PRINT_HILOGI("OnCallback end run PrintTaskAfterCallFun success");
        }
    }
    if (work != nullptr) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            delete cbParam;
            work->data = nullptr;
        }
        delete work;
        work = nullptr;
    }
    PRINT_HILOGI("OnCallback run PrintTaskAfterCallFun end");
}

static void PrinterAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrinterAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (InitUvWorkCallbackEnv(work, scope)) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
            napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
            napi_value callbackResult = nullptr;
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
            callbackValues[1] = cbParam->printerInfo.ToJsObject(cbParam->env);
            napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_TWO,
                callbackValues, &callbackResult);
            napi_close_handle_scope(cbParam->env, scope);
            PRINT_HILOGI("OnCallback end run PrinterAfterCallFun success");
        }
    }
    if (work != nullptr) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            delete cbParam;
            work->data = nullptr;
        }
        delete work;
        work = nullptr;
    }
    PRINT_HILOGI("OnCallback run PrinterAfterCallFun end");
}

static void PrintJobAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintJobAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (InitUvWorkCallbackEnv(work, scope)) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
            napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
            napi_value callbackResult = nullptr;
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
            callbackValues[1] = cbParam->jobInfo.ToJsObject(cbParam->env);
            napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_TWO,
                callbackValues, &callbackResult);
            napi_close_handle_scope(cbParam->env, scope);
            PRINT_HILOGI("OnCallback end run PrintJobAfterCallFun success");
        }
    }
    if (work != nullptr) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            delete cbParam;
            work->data = nullptr;
        }
        delete work;
        work = nullptr;
    }
    PRINT_HILOGI("OnCallback run PrintJobAfterCallFun end");
}

static void ExtensionAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run ExtensionAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (InitUvWorkCallbackEnv(work, scope)) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
            napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
            napi_value callbackResult = nullptr;
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] =
                NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->extensionId);
            callbackValues[1] =
                NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->info);
            napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_TWO,
                callbackValues, &callbackResult);
            napi_close_handle_scope(cbParam->env, scope);
            PRINT_HILOGI("OnCallback end run ExtensionAfterCallFun success");
        }
    }
    if (work != nullptr) {
        auto cbParam = static_cast<CallbackParam*>(work->data);
        if (cbParam != nullptr) {
            delete cbParam;
            work->data = nullptr;
        }
        delete work;
        work = nullptr;
    }
    PRINT_HILOGI("OnCallback run ExtensionAfterCallFun end");
}

bool PrintCallback::onBaseCallback(std::function<void(CallbackParam*)> paramFun, uv_after_work_cb after_work_cb)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    bool result = false;
    if (loop != nullptr) {
        uv_work_t *work = new (std::nothrow) uv_work_t;
        if (work != nullptr) {
            CallbackParam *param = new (std::nothrow) CallbackParam;
            if (param != nullptr) {
                std::lock_guard<std::mutex> lock(mutex_);
                param->env = env_;
                param->ref = ref_;
                param->mutexPtr = &mutex_;

                paramFun(param);
            }
            work->data = param;
            uv_queue_work(loop, work, [](uv_work_t *work) {}, after_work_cb);
            result = true;
        }
    }
    return result;
}

bool PrintCallback::OnCallback()
{
    PRINT_HILOGI("PrintTask Notification in");
    return onBaseCallback([](CallbackParam* param) {}, PrintTaskAfterCallFun);
}

bool PrintCallback::OnCallback(uint32_t state, const PrinterInfo &info)
{
    PRINT_HILOGI("Printer Notification in");
    return onBaseCallback(
        [state, info](CallbackParam* param) {
            param->state = state;
            param->printerInfo = info;
        }, PrinterAfterCallFun);
}

bool PrintCallback::OnCallback(uint32_t state, const PrintJob &info)
{
    PRINT_HILOGI("PrintJob Notification in");
    return onBaseCallback(
        [state, info](CallbackParam* param) {
            param->state = state;
            param->jobInfo = info;
        }, PrintJobAfterCallFun);
}

bool PrintCallback::OnCallback(const std::string &extensionId, const std::string &info)
{
    PRINT_HILOGI("ExtensionInfo Notification in");
    return onBaseCallback(
        [extensionId, info](CallbackParam* param) {
            param->extensionId = extensionId;
            param->info = info;
        }, ExtensionAfterCallFun);
}
} // namespace OHOS::Print
