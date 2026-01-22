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

#include "scan_callback.h"
#include "napi/native_node_api.h"
#include "napi_scan_utils.h"
#include "scan_log.h"
#include "scanner_info_helper.h"

namespace OHOS::Scan {
ScanCallback::ScanCallback(napi_env env, napi_ref ref) : env_(env), ref_(ref), callbackFunction_(nullptr)
{
}

ScanCallback::ScanCallback(std::function<void(std::vector<ScanDeviceInfo> &infos)>
    callbackFunction) : env_(nullptr), ref_(nullptr), callbackFunction_(callbackFunction)
{
}

ScanCallback::~ScanCallback()
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    if (env_ == nullptr || ref_ == nullptr) {
        return;
    }
    SCAN_HILOGI("callback has been destroyed");
    Param *param = new (std::nothrow) Param;
    if (param == nullptr) {
        return;
    }
    param->env = env_;
    param->callbackRef = ref_;
    auto task = [param]() {
        SCAN_HILOGI("napi_send_event ScanCallback DeleteReference");
        if (param == nullptr) {
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            delete param;
            return;
        }
        napi_ref callbackRef = param->callbackRef;
        NapiScanUtils::DeleteReference(param->env, callbackRef);
        napi_close_handle_scope(param->env, scope);
        delete param;
    };
    if (napi_send_event(env_, task, napi_eprio_low) != napi_ok) {
        SCAN_HILOGE("Failed to send event");
        delete param;
    }
}

void CallbackParam::InitialCallbackParam(napi_env &env_, napi_ref &ref_, std::mutex &mutex_)
{
    std::lock_guard<std::mutex> lock(mutex_);
    this->env = env_;
    this->ref = ref_;
    this->mutexPtr = &mutex_;
}

void CallbackParam::SetCallbackParam(uint32_t &state, const ScanDeviceInfo &deviceInfo)
{
    this->state = state;
    this->deviceInfo = deviceInfo;
}

void CallbackParam::SetCallbackSyncParam(uint32_t &state, const ScanDeviceInfoSync &deviceInfoSync)
{
    this->state = state;
    this->deviceInfoSync = deviceInfoSync;
}

bool ScanCallback::ExecuteNapiEventWork(CallbackParam* param, std::function<void(CallbackParam*)> workFunc)
{
    auto task = [param, workFunc]() {
        if (param == nullptr) {
            SCAN_HILOGE("param is a nullptr");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            delete param;
            return;
        }
        std::lock_guard<std::mutex> autoLock(*param->mutexPtr);
        napi_value callbackFunc = NapiScanUtils::GetReference(param->env, param->ref);
        if (callbackFunc != nullptr) {
            workFunc(param);
            SCAN_HILOGI("run napi call deviceInfo callback fun success");
        } else {
            SCAN_HILOGE("get reference failed");
        }
        napi_close_handle_scope(param->env, scope);
        delete param;
    };

    napi_status ret = napi_send_event(env_, task, napi_eprio_immediate);
    if (ret != napi_ok) {
        SCAN_HILOGE("napi_send_event fail");
        delete param;
        return false;
    }
    return true;
}

void ScanCallback::NapiCallFunction(CallbackParam* cbParam, size_t argcCount, napi_value* callbackValues)
{
    if (cbParam == nullptr) {
        SCAN_HILOGE("cbParam is a nullptr");
        return;
    }
    napi_value callbackFunc = NapiScanUtils::GetReference(cbParam->env, cbParam->ref);
    if (callbackFunc != nullptr) {
        napi_call_function(cbParam->env, nullptr, callbackFunc,
            argcCount, callbackValues, nullptr);
    }
}

bool ScanCallback::OnCallback(uint32_t state, const ScanDeviceInfo &info)
{
    SCAN_HILOGI("Enter OnCallback::ScanDeviceInfo");

    CallbackParam *param = new (std::nothrow) CallbackParam;
    if (param == nullptr) {
        SCAN_HILOGE("Failed to create callback parameter");
        return false;
    }

    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackParam(state, info);

    auto workFunc = [this](CallbackParam* cbParam) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = ScannerInfoHelper::MakeJsObject(cbParam->env, cbParam->deviceInfo);
        NapiCallFunction(cbParam, NapiScanUtils::ARGC_ONE, callbackValues);
    };

    return ExecuteNapiEventWork(param, workFunc);
}

bool ScanCallback::OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info)
{
    SCAN_HILOGD("Enter OnCallback::ScanDeviceInfo");

    CallbackParam *param = new (std::nothrow) CallbackParam;
    if (param == nullptr) {
        SCAN_HILOGE("Failed to create callback parameter");
        return false;
    }

    param->InitialCallbackParam(env_, ref_, mutex_);
    param->SetCallbackSyncParam(state, info);

    auto workFunc = [this](CallbackParam* cbParam) {
        napi_value callbackValues[NapiScanUtils::ARGC_ONE] = { 0 };
        callbackValues[0] = ScannerInfoSyncHelper::MakeJsObject(cbParam->env, cbParam->deviceInfoSync);
        NapiCallFunction(cbParam, NapiScanUtils::ARGC_ONE, callbackValues);
    };

    return ExecuteNapiEventWork(param, workFunc);
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
