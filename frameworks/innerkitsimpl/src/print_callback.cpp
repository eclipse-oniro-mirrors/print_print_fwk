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
#include "napi_print_utils.h"
#include "print_job_helper.h"
#include "printer_info_helper.h"
#include "print_attributes_helper.h"
#include "print_log.h"

namespace OHOS::Print {
PrintCallback::PrintCallback(napi_env env, napi_ref ref) : env_(env), ref_(ref)
{
}

PrintCallback::PrintCallback(PrintDocumentAdapter* adapter) :adapter_(adapter)
{
}

PrintCallback::~PrintCallback()
{
    if (adapter_ != nullptr) {
        adapter_ = nullptr;
    } else {
        std::lock_guard<std::mutex> autoLock(mutex_);
        PRINT_HILOGD("callback has been destroyed");

        uv_loop_s *loop = nullptr;
        napi_get_uv_event_loop(env_, &loop);
        Param *param = new (std::nothrow) Param;
        if (param == nullptr) {
            return;
        }
        param->env = env_;
        param->callbackRef = ref_;
        uv_work_t *work = new (std::nothrow) uv_work_t;
        if (work == nullptr) {
            delete param;
            return;
        }
        work->data = reinterpret_cast<void*>(param);
        uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int _status) {
            PRINT_HILOGD("uv_queue_work PrintCallback DeleteReference");
            Param *param_ = reinterpret_cast<Param*>(work->data);
            if (param_ == nullptr) {
                delete work;
                return;
            }
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(param_->env, &scope);
            if (scope == nullptr) {
                delete param_;
                delete work;
                return;
            }
            napi_ref callbackRef_ = param_->callbackRef;
            NapiPrintUtils::DeleteReference(param_->env, callbackRef_);
            napi_close_handle_scope(param_->env, scope);
            delete param_;
            delete work;
        });
    }
}

static bool InitUvWorkCallbackEnv(uv_work_t *work, napi_handle_scope &scope)
{
    if (work == nullptr) {
        PRINT_HILOGE("work is nullptr");
        return false;
    }
    if (work->data == nullptr) {
        PRINT_HILOGE("data is nullptr");
        return false;
    }
    CallbackParam *cbParam = reinterpret_cast<CallbackParam *>(work->data);
    napi_open_handle_scope(cbParam->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("fail to open scope");
        delete cbParam;
        work->data = nullptr;
        return false;
    }
    return true;
}

static void PrintTaskAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintTaskAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
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
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void PrinterAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrinterAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
    if (cbParam != nullptr) {
        std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
        napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
        napi_value callbackResult = nullptr;
        napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
        callbackValues[1] = PrinterInfoHelper::MakeJsObject(cbParam->env, cbParam->printerInfo);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_TWO,
            callbackValues, &callbackResult);
        napi_close_handle_scope(cbParam->env, scope);
        PRINT_HILOGI("OnCallback end run PrinterAfterCallFun success");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void PrintJobAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintJobAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
    if (cbParam != nullptr) {
        std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
        napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
        napi_value callbackResult = nullptr;
        napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
        callbackValues[1] = cbParam->jobInfo.GetPrinterId().length() == 0
            ? PrintJobHelper::MakeJsSimpleObject(cbParam->env, cbParam->jobInfo)
            : PrintJobHelper::MakeJsObject(cbParam->env, cbParam->jobInfo);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiPrintUtils::ARGC_TWO,
            callbackValues, &callbackResult);
        napi_close_handle_scope(cbParam->env, scope);
        PRINT_HILOGI("OnCallback end run PrintJobAfterCallFun success");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void ExtensionAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run ExtensionAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
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
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void PrintAdapterAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintAdapterAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
    if (cbParam != nullptr) {
        std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
        napi_value adapterObj = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);

        napi_value layoutWriteFunc = NapiPrintUtils::GetNamedProperty(cbParam->env, adapterObj, "onStartLayoutWrite");
        auto successCallback = [](napi_env env, napi_callback_info info) -> napi_value {
            PRINT_HILOGI("parse from js callback data start");
            size_t argc = NapiPrintUtils::ARGC_TWO;
            napi_value args[NapiPrintUtils::ARGC_TWO] = {nullptr};

            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, args[0]);
            uint32_t replyState = NapiPrintUtils::GetUint32FromValue(env, args[1]);

            PrintManagerClient::GetInstance()->UpdatePrintJobState(jobId, PRINT_JOB_CREATE_FILE_COMPLETED, replyState);
            PRINT_HILOGI("from js return jobId:%{public}s, replyState:%{public}d", jobId.c_str(), replyState);
            return nullptr;
        };

        napi_value callbackResult = nullptr;
        napi_value callbackValues[NapiPrintUtils::ARGC_FIVE] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->jobId);
        callbackValues[1] = PrintAttributesHelper::MakeJsObject(cbParam->env, cbParam->oldAttrs);
        callbackValues[NapiPrintUtils::ARGC_TWO] =
            PrintAttributesHelper::MakeJsObject(cbParam->env, cbParam->newAttrs);
        callbackValues[NapiPrintUtils::ARGC_THREE] =
            NapiPrintUtils::CreateUint32(cbParam->env, cbParam->fd);
        callbackValues[NapiPrintUtils::ARGC_FOUR] =
            NapiPrintUtils::CreateFunction(cbParam->env, "writeResultCallback", successCallback, nullptr);

        napi_call_function(cbParam->env, adapterObj, layoutWriteFunc, NapiPrintUtils::ARGC_FIVE,
            callbackValues, &callbackResult);

        napi_close_handle_scope(cbParam->env, scope);
        PRINT_HILOGI("OnCallback end run PrintAdapterAfterCallFun success");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void PrintAdapterJobStateChangedAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintAdapterJobStateChangedAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
    if (cbParam != nullptr) {
        std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
        napi_value adapterObj = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);

        napi_value jobStateChangedFunc = NapiPrintUtils::GetNamedProperty(cbParam->env, adapterObj,
            "onJobStateChanged");

        napi_value callbackResult = nullptr;
        napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->jobId);
        callbackValues[1] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);

        napi_call_function(cbParam->env, adapterObj, jobStateChangedFunc, NapiPrintUtils::ARGC_TWO,
            callbackValues, &callbackResult);

        napi_close_handle_scope(cbParam->env, scope);
        PRINT_HILOGI("OnCallback end run PrintAdapterJobStateChangedAfterCallFun success");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

static void PrintAdapterGetFileAfterCallFun(uv_work_t *work, int status)
{
    PRINT_HILOGI("OnCallback start run PrintAdapterGetFileAfterCallFun");
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    CallbackParam *cbParam = static_cast<CallbackParam*>(work->data);
    if (cbParam != nullptr) {
        std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
        napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
        napi_value callbackResult = nullptr;
        napi_value callbackValues[1] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
        napi_call_function(cbParam->env, nullptr, callbackFunc, 1,
            callbackValues, &callbackResult);
        napi_close_handle_scope(cbParam->env, scope);
        PRINT_HILOGI("OnCallback end run PrintAdapterGetFileAfterCallFun success");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        delete cbParam;
        cbParam = nullptr;
    }
}

bool PrintCallback::onBaseCallback(std::function<void(CallbackParam*)> paramFun, uv_after_work_cb after_work_cb)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        PRINT_HILOGE("Failed to get uv event loop");
        return false;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        PRINT_HILOGE("Failed to create uv work");
        return false;
    }
    CallbackParam *param = new (std::nothrow) CallbackParam;
    if (param == nullptr) {
        PRINT_HILOGE("Failed to create callback parameter");
        return false;
    } else {
        std::lock_guard<std::mutex> lock(mutex_);

        param->env = env_;
        param->ref = ref_;
        param->mutexPtr = &mutex_;

        paramFun(param);
    }

    work->data = param;
    uv_queue_work(loop, work, [](uv_work_t *work) {}, after_work_cb);
    return true;
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

bool PrintCallback::OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd)
{
    PRINT_HILOGI("PrintCallback OnCallbackAdapterLayout Notification in, jobId:%{public}s newAttrs copyNum:%{public}d",
        jobId.c_str(), newAttrs.GetCopyNumber());
    if (adapter_ != nullptr) {
        PRINT_HILOGI("OnCallbackAdapterLayout run c++");
        adapter_->onStartLayoutWrite(jobId, oldAttrs, newAttrs, fd, [](std::string jobId, uint32_t state) {
            PRINT_HILOGI("onStartLayoutWrite write over, jobId:%{public}s state: %{public}d", jobId.c_str(), state);
            PrintManagerClient::GetInstance()->UpdatePrintJobState(jobId, PRINT_JOB_CREATE_FILE_COMPLETED, state);
        });
        return true;
    } else {
        PRINT_HILOGI("OnCallbackAdapterLayout run ets");
        return onBaseCallback(
            [jobId, oldAttrs, newAttrs, fd](CallbackParam* param) {
                param->jobId = jobId;
                param->oldAttrs = oldAttrs;
                param->newAttrs = newAttrs;
                param->fd = fd;
            }, PrintAdapterAfterCallFun);
    }
}

bool PrintCallback::onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    PRINT_HILOGI("PrintCallback onCallbackAdapterJobStateChanged Notification in, jobId:%{public}s subState:%{public}d",
        jobId.c_str(), subState);
    if (adapter_ != nullptr) {
        PRINT_HILOGI("onCallbackAdapterJobStateChanged run c++");
        adapter_->onJobStateChanged(jobId, subState);
        return true;
    } else {
        PRINT_HILOGI("onCallbackAdapterJobStateChanged run ets");
        return onBaseCallback(
            [jobId, subState](CallbackParam* param) {
                param->jobId = jobId;
                param->state = subState;
            }, PrintAdapterJobStateChangedAfterCallFun);
    }
}

bool PrintCallback::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("OnCallbackAdapterGetFile in");
    return onBaseCallback(
        [state](CallbackParam* param) {
            param->state = state;
        }, PrintAdapterGetFileAfterCallFun);
}
}  // namespace OHOS::Print
