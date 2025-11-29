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
PrintCallback::PrintCallback(napi_env env, napi_ref ref)
    : env_(env), ref_(ref), adapter_(nullptr), printState_(nullptr) {}

PrintCallback::PrintCallback(PrintDocumentAdapter *adapter)
    : env_(nullptr), ref_(nullptr), adapter_(adapter), printState_(nullptr) {}

PrintCallback::PrintCallback(PrintState *printState)
    : env_(nullptr), ref_(nullptr), adapter_(nullptr), printState_(printState) {}

PrintCallback::~PrintCallback()
{
    if (printState_ = nullptr) {
        delete printState_;
        printState_ = nullptr;
    }
    if (adapter_ != nullptr) {
        delete adapter_;
        adapter_ = nullptr;
    } else if (nativePrinterChange_cb != nullptr) {
        nativePrinterChange_cb = nullptr;
    } else {
        std::lock_guard<std::mutex> autoLock(mutex_);
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
}

static void NapiCallFunction(CallbackParam* cbParam, size_t argcCount, napi_value* callbackValues)
{
    if (cbParam == nullptr) {
        PRINT_HILOGE("cbParam is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cbParam->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("fail to open scope");
        return;
    }

    napi_value callbackFunc = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
    if (callbackFunc != nullptr) {
        napi_call_function(cbParam->env, nullptr, callbackFunc, argcCount,
            callbackValues, nullptr);
        PRINT_HILOGI("NapiCallFunction run napi_call_function success");
    } else {
        PRINT_HILOGE("NapiCallFunction get reference failed");
    }
    napi_close_handle_scope(cbParam->env, scope);
}

static void PrintAdapterWorkCb(CallbackParam *cbParam)
{
    PRINT_HILOGI("OnCallback start run PrintAdapterWorkCb");
    if (cbParam == nullptr) {
        PRINT_HILOGE("cbParam is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cbParam->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("fail to open scope");
        close(cbParam->fd);
        return;
    }
    napi_value adapterObj = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
    if (adapterObj != nullptr) {
        napi_value layoutWriteFunc =
            NapiPrintUtils::GetNamedProperty(cbParam->env, adapterObj, "onStartLayoutWrite");
        auto successCallback = [](napi_env env, napi_callback_info info) -> napi_value {
            PRINT_HILOGI("parse from js callback data start");
            size_t argc = NapiPrintUtils::ARGC_TWO;
            napi_value args[NapiPrintUtils::ARGC_TWO] = {nullptr};

            napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, args[0]);
            uint32_t replyState = NapiPrintUtils::GetUint32FromValue(env, args[1]);

            PrintManagerClient::GetInstance()->UpdatePrintJobStateForNormalApp(
                jobId, PRINT_JOB_CREATE_FILE_COMPLETED, replyState);
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
        PRINT_HILOGI("OnCallback end run PrintAdapterWorkCb success");
    }
    if (napi_close_handle_scope(cbParam->env, scope) != napi_ok) {
        close(cbParam->fd);
    }
}

static void PrintAdapterJobStateChangedAfterCallFun(CallbackParam *cbParam)
{
    PRINT_HILOGI("OnCallback start run PrintAdapterJobStateChangedAfterCallFun");
    if (cbParam == nullptr) {
        PRINT_HILOGE("cbParam is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cbParam->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("fail to open scope");
        close(cbParam->fd);
        return;
    }
    napi_value adapterObj = NapiPrintUtils::GetReference(cbParam->env, cbParam->ref);
    if (adapterObj != nullptr) {
        napi_value jobStateChangedFunc = NapiPrintUtils::GetNamedProperty(cbParam->env, adapterObj,
            "onJobStateChanged");

        napi_value callbackResult = nullptr;
        napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
        callbackValues[0] = NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->jobId);
        callbackValues[1] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);

        napi_call_function(cbParam->env, adapterObj, jobStateChangedFunc, NapiPrintUtils::ARGC_TWO,
            callbackValues, &callbackResult);
        PRINT_HILOGI("OnCallback end run PrintAdapterJobStateChangedAfterCallFun success");
    } else {
        PRINT_HILOGE("PrintAdapterJobStateChangedAfterCallFun get reference failed");
    }
    napi_close_handle_scope(cbParam->env, scope);
}

bool PrintCallback::OnBaseCallback(std::function<void(CallbackParam*)> paramFun,
    std::function<void(CallbackParam*)> workCb)
{
    CallbackParam *param = new (std::nothrow) CallbackParam;
    if (param == nullptr) {
        PRINT_HILOGE("Failed to create callback parameter");
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        param->env = env_;
        param->ref = ref_;
        param->mutexPtr = &mutex_;
        paramFun(param);
    }

    auto task = [param, workCb]() {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");
            return;
        }
        std::lock_guard<std::mutex> autoLock(*param->mutexPtr);
        workCb(param);
        delete param;
    };

    napi_status ret = napi_send_event(env_, task, napi_eprio_immediate);
    if (ret != napi_ok) {
        PRINT_HILOGE("napi_send_event fail");
        delete param;
        return false;
    }
    return true;
}

bool PrintCallback::OnCallback()
{
    PRINT_HILOGI("PrintTask Notification in");
    return OnBaseCallback([](CallbackParam* param) {},
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run OnCallback");
            napi_value callbackValues[NapiPrintUtils::ARGC_ONE] = { 0 };
            callbackValues[0] = NapiPrintUtils::GetUndefined(cbParam->env);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_ZERO, callbackValues);
        });
}

bool PrintCallback::OnCallback(uint32_t state, const PrinterInfo &info)
{
    PRINT_HILOGI("Printer Notification in");
    if (nativePrinterChange_cb != nullptr) {
        return nativePrinterChange_cb(state, info);
    }
    return OnBaseCallback(
        [state, info](CallbackParam* param) {
            param->state = state;
            param->printerInfo = info;
        },
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run PrinterInfoWorkCb");
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
            callbackValues[1] = PrinterInfoHelper::MakeJsObject(cbParam->env, cbParam->printerInfo);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_TWO, callbackValues);
        });
}

bool PrintCallback::OnCallback(uint32_t state, const PrintJob &info)
{
    PRINT_HILOGI("PrintJob Notification in");
    return OnBaseCallback(
        [state, info](CallbackParam* param) {
            param->state = state;
            param->jobInfo = info;
        },
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run PrinterInfoWorkCb");
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
            callbackValues[1] = cbParam->jobInfo.GetPrinterId().length() == 0
                ? PrintJobHelper::MakeJsSimpleObject(cbParam->env, cbParam->jobInfo)
                : PrintJobHelper::MakeJsObject(cbParam->env, cbParam->jobInfo);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_TWO, callbackValues);
        });
}

bool PrintCallback::OnCallback(const std::string &extensionId, const std::string &info)
{
    PRINT_HILOGI("ExtensionInfo Notification in");
    return OnBaseCallback(
        [extensionId, info](CallbackParam* param) {
            param->extensionId = extensionId;
            param->info = info;
        },
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run PrinterInfoWorkCb");
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] =
                NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->extensionId);
            callbackValues[1] =
                NapiPrintUtils::CreateStringUtf8(cbParam->env, cbParam->info);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_TWO, callbackValues);
        });
}

bool PrintCallback::OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds)
{
    PRINT_HILOGI("QueryPrinterInfo Notification in");
    return OnBaseCallback(
        [info, ppds](CallbackParam* param) {
            param->printerInfo = info;
            param->ppds = ppds;
        },
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run QueryPrinterInfoWorkCb");
            napi_value callbackValues[NapiPrintUtils::ARGC_TWO] = { 0 };
            callbackValues[0] =
                PrinterInfoHelper::MakeJsObject(cbParam->env, cbParam->printerInfo);
            callbackValues[1] =
                NapiPrintUtils::CreatePpdInfoVectorUtf8(cbParam->env, cbParam->ppds);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_TWO, callbackValues);
        });
}

bool PrintCallback::OnCallbackJobStateChanged(const std::string jobId, const uint32_t state)
{
    PRINT_HILOGI("PrintCallback OnCallbackJobStateChanged Notification in, jobId: %{public}s state:%{public}d",
        jobId.c_str(), state);
    if (printState_ != nullptr) {
        PRINT_HILOGI("OnCallbackJobStateChanged run c++");
        printState_->onJobStateChanged(jobId, state);
        return true;
    }
    return false;
}

bool PrintCallback::OnCallbackAdapterLayout(
    const std::string &jobId, const PrintAttributes &oldAttrs, const PrintAttributes &newAttrs, uint32_t fd)
{
    PRINT_HILOGI("PrintCallback OnCallbackAdapterLayout Notification in, jobId:%{public}s newAttrs copyNum:%{public}d",
        jobId.c_str(),
        newAttrs.GetCopyNumber());
    if (adapter_ != nullptr) {
        PRINT_HILOGI("OnCallbackAdapterLayout run c++");
        adapter_->onStartLayoutWrite(jobId, oldAttrs, newAttrs, fd, [](std::string jobId, uint32_t state) {
            PRINT_HILOGI("onStartLayoutWrite write over, jobId:%{public}s state: %{public}d", jobId.c_str(), state);
            PrintManagerClient::GetInstance()->UpdatePrintJobStateForNormalApp(
                jobId, PRINT_JOB_CREATE_FILE_COMPLETED, state);
        });
        return true;
    } else {
        PRINT_HILOGI("OnCallbackAdapterLayout run ets");
        return OnBaseCallback(
            [jobId, oldAttrs, newAttrs, fd](CallbackParam *param) {
                param->jobId = jobId;
                param->oldAttrs = oldAttrs;
                param->newAttrs = newAttrs;
                param->fd = fd;
            },
            PrintAdapterWorkCb);
    }
}

bool PrintCallback::OnCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    PRINT_HILOGI("PrintCallback OnCallbackAdapterJobStateChanged Notification in, jobId:%{public}s subState:%{public}d",
        jobId.c_str(), subState);
    if (adapter_ != nullptr) {
        PRINT_HILOGI("OnCallbackAdapterJobStateChanged run c++");
        adapter_->onJobStateChanged(jobId, subState);
        return true;
    } else {
        PRINT_HILOGI("OnCallbackAdapterJobStateChanged run ets");
        return OnBaseCallback(
            [jobId, subState](CallbackParam* param) {
                param->jobId = jobId;
                param->state = subState;
            }, PrintAdapterJobStateChangedAfterCallFun);
    }
}

bool PrintCallback::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("OnCallbackAdapterGetFile in");
    return OnBaseCallback(
        [state](CallbackParam* param) {
            param->state = state;
        },
        [](CallbackParam *cbParam) {
            PRINT_HILOGI("OnCallback start run PrinterInfoWorkCb");
            napi_value callbackValues[1] = { 0 };
            callbackValues[0] = NapiPrintUtils::CreateUint32(cbParam->env, cbParam->state);
            NapiCallFunction(cbParam, NapiPrintUtils::ARGC_ONE, callbackValues);
        });
}
} // namespace OHOS::Print