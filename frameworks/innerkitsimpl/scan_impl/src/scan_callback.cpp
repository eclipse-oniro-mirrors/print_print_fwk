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

#include <uv.h>
#include <functional>
#include "scan_callback.h"
#include "napi_scan_utils.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanCallback::ScanCallback(napi_env env, napi_ref ref) : env_(env), ref_(ref)
{
}

ScanCallback::ScanCallback(std::function<void(std::vector<ScanDeviceInfo> &infos)>
    callbackFunction) : callbackFunction_(callbackFunction)
{
}

ScanCallback::~ScanCallback()
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    SCAN_HILOGI("callback has been destroyed");

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
    int retVal = uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int _status) {
        SCAN_HILOGI("uv_queue_work ScanCallback DeleteReference");
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
        NapiScanUtils::DeleteReference(param_->env, callbackRef_);
        napi_close_handle_scope(param_->env, scope);
        delete param_;
        delete work;
    });
    if (retVal != 0) {
        SCAN_HILOGE("Failed to get uv_queue_work.");
        delete param;
        delete work;
        return;
    }
}

void CallbackParam::InitialCallbackParam(napi_env &env_, napi_ref &ref_, std::mutex &mutex_)
{
    std::lock_guard<std::mutex> lock(mutex_);
    this->env = env_;
    this->ref = ref_;
    this->mutexPtr = &mutex_;
}

void CallbackParam::SetCallbackParam(uint32_t &state, const ScanDeviceInfoTCP &deviceInfoTCP)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->state = state;
    this->deviceInfoTCP = deviceInfoTCP;
}

void CallbackParam::SetCallbackParam(uint32_t &state, const ScanDeviceInfo &deviceInfo)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->state = state;
    this->deviceInfo = deviceInfo;
}

void CallbackParam::SetCallbackSyncParam(uint32_t &state, const ScanDeviceInfoSync &deviceInfoSync)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->state = state;
    this->deviceInfoSync = deviceInfoSync;
}

void CallbackParam::SetCallbackParam(bool &isGetSucc, int32_t &sizeRead)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->isGetSucc = isGetSucc;
    this->sizeRead = sizeRead;
}

void CallbackParam::SetCallbackParam(int32_t &scanVersion)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->scanVersion = scanVersion;
}

void CallbackParam::SetCallbackParam(std::string &message)
{
    std::lock_guard<std::mutex> lock(*mutexPtr);
    this->message = message;
}

void CallbackContext::SetCallbackContext(CallbackParam* &callBackParam,
    uv_work_function &uvWorkLambda, std::mutex &mutex_)
{
    std::lock_guard<std::mutex> lock(mutex_);
    this->callBackParam = callBackParam;
    this->uvWorkLambda = uvWorkLambda;
}

void ScanCallback::CreateCallbackParam(uv_work_t *&work, CallbackParam *&param, CallbackContext *&context, bool &flag)
{
    work = new (std::nothrow) uv_work_t;
    CHECK_AND_CREATE(work, "Failed to create uv_work_t work", flag);
    param = new (std::nothrow) CallbackParam;
    CHECK_AND_CREATE(param, "Failed to create CallbackParam param", flag);
    context = new (std::nothrow) CallbackContext;
    CHECK_AND_CREATE(context, "Failed to create CallbackContext context", flag);
    if (!flag) {
        DELETE_AND_NULLIFY(work);
        DELETE_AND_NULLIFY(param);
        DELETE_AND_NULLIFY(context);
    }
}

bool ScanCallback::ExecuteUvQueueWork(CallbackContext* &context, uv_work_t* &work, uv_loop_s *&loop)
{
    work->data = context;
    int32_t retVal = uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int statusInt) {
            CallbackContext *context = static_cast<CallbackContext*>(work->data);
            CallbackParam *cbParam = context->callBackParam;
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(cbParam->env, &scope);
            if (scope != nullptr) {
                auto uvWorkLambda = context->uvWorkLambda;
                std::lock_guard<std::mutex> autoLock(*cbParam->mutexPtr);
                napi_value callbackFunc = NapiScanUtils::GetReference(cbParam->env, cbParam->ref);
                napi_value callbackResult = nullptr;
                uvWorkLambda(cbParam, callbackFunc, callbackResult);
                SCAN_HILOGD("run napi call deviceInfo callback fun success");
                napi_close_handle_scope(cbParam->env, scope);
            }
            DELETE_AND_NULLIFY(work);
            DELETE_AND_NULLIFY(cbParam);
            DELETE_AND_NULLIFY(context);
        });
    if (retVal != 0) {
        SCAN_HILOGE("failed to get uv_queue_work.");
        DELETE_AND_NULLIFY(work);
        DELETE_AND_NULLIFY(context->callBackParam);
        DELETE_AND_NULLIFY(context);
        return false;
    }
    return true;
}

bool ScanCallback::OnCallback(uint32_t state, const ScanDeviceInfoTCP &info)
{
    SCAN_HILOGD("Enter OnCallback::ScanDeviceInfoTCP");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback ScanDeviceInfoTCP error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = ScannerInfoHelperTCP::MakeJsObject(cbParam->env, cbParam->deviceInfoTCP);
        napi_call_function(cbParam->env, nullptr, callbackFunc,
            NapiScanUtils::ARGC_ONE, callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(state, info);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnCallback(uint32_t state, const ScanDeviceInfo &info)
{
    SCAN_HILOGD("Enter OnCallback::ScanDeviceInfo");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback ScanDeviceInfo error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = ScannerInfoHelper::MakeJsObject(cbParam->env, cbParam->deviceInfo);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiScanUtils::ARGC_ONE,
            callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(state, info);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info)
{
    SCAN_HILOGD("Enter OnCallback::ScanDeviceInfo");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback ScanDeviceInfo error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = ScannerInfoSyncHelper::MakeJsObject(cbParam->env, cbParam->deviceInfoSync);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiScanUtils::ARGC_ONE,
            callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackSyncParam(state, info);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnGetFrameResCallback(bool isGetSucc, int32_t sizeRead)
{
    SCAN_HILOGD("Enter OnCallback::OnGetFrameResCallback");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback OnGetFrameResCallback error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_TWO] = { 0 };
        callbackValues[0] = NapiScanUtils::CreateBoolean(cbParam->env, cbParam->isGetSucc);
        callbackValues[1] = NapiScanUtils::CreateInt32(cbParam->env, cbParam->sizeRead);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiScanUtils::ARGC_TWO,
            callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(isGetSucc, sizeRead);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnScanInitCallback(int32_t &scanVersion)
{
    SCAN_HILOGD("Enter OnCallback::OnScanInitCallback");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback OnScanInitCallback error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = NapiScanUtils::CreateInt32(cbParam->env, cbParam->scanVersion);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiScanUtils::ARGC_ONE,
            callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(scanVersion);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnSendSearchMessage(std::string &message)
{
    SCAN_HILOGD("Enter OnCallback::OnSendSearchMessage");

    INIT_CALLBACK_PARAMS;

    if (!flag) {
        SCAN_HILOGE("ScanCallback::OnCallback OnSendSearchMessage error exit");
        return false;
    }

    uv_work_function uvWorkLambda = [](CallbackParam* &cbParam, napi_value &callbackFunc, napi_value &callbackResult) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = NapiScanUtils::CreateStringUtf8(cbParam->env, cbParam->message);
        napi_call_function(cbParam->env, nullptr, callbackFunc, NapiScanUtils::ARGC_ONE,
            callbackValues, &callbackResult);
    };
    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(message);
    context->SetCallbackContext(param, uvWorkLambda, mutex_);

    return ExecuteUvQueueWork(context, work, loop);
}

bool ScanCallback::OnGetDevicesList(std::vector<ScanDeviceInfo> &infos)
{
    SCAN_HILOGI("Enter OnGetDevicesList");
    if (callbackFunction_ == nullptr) {
        SCAN_HILOGE("callbackFunction_ is a nullptr");
        return false;
    }
    callbackFunction_(infos);
    return true;
}
} // namespace OHOS::Scan
