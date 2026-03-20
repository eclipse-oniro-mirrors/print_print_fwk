/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ani.h>
#include <array>
#include <iostream>
#include <vector>
#include "refbase.h"
#include "scan_log.h"
#include "scan_constant.h"
#include "scan_manager_client.h"
#include "scan_callback.h"
#include "print_base_ani_util.h"
#include "print_callback_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_scan_parameter_helper.h"
#include "ani_scan_option_value_helper.h"
#include "ani_scan_progress_helper.h"
#include "ani_scanner_device_helper.h"
#include "ani_scanner_sync_device_helper.h"
#include "scan_ani_callback.h"
#include "napi_scan_helper.h"

using namespace OHOS::Scan;
using namespace OHOS::Print;

static void InitScanNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter InitScanNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    int32_t ret = ScanManagerClient::GetInstance()->InitScan();
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void ExitScanNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter ExitScanNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    int32_t ret = ScanManagerClient::GetInstance()->ExitScan();
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void StartScannerDiscoveryNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter StartScannerDiscoveryNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    int32_t ret = ScanManagerClient::GetInstance()->GetScannerList();
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void OpenScannerNative(ani_env *env, ani_string scannerIdAni, ani_object callback)
{
    SCAN_HILOGI("enter OpenScannerNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string scannerId;
    if (!GetStdString(env, scannerIdAni, scannerId)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s", scannerId.c_str());
    int32_t ret = ScanManagerClient::GetInstance()->OpenScanner(scannerId);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void CloseScannerNative(ani_env *env, ani_string scannerId, ani_object callback)
{
    SCAN_HILOGI("enter CloseScannerNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s", id.c_str());
    int32_t ret = ScanManagerClient::GetInstance()->CloseScanner(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetScannerParameterNative(ani_env *env, ani_string scannerId, ani_object callback)
{
    SCAN_HILOGI("enter GetScannerParameterNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallbackArray(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s", id.c_str());
    std::vector<ScanOptionDescriptor> parameters;
    int32_t ret = NapiScanHelper::GetScannerAllPara(id, parameters);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode,
        AniScanParameterHelper::CreateScanParameterArray(env, parameters));
}

static void SetScannerParameterNative(ani_env *env, ani_string scannerId, ani_int optionIndex,
    ani_object value, ani_object callback)
{
    SCAN_HILOGI("enter SetScannerParameterNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s, Option Index: %{public}d", id.c_str(), optionIndex);
    ScanOptionValue optionValue = AniScanOptionValueHelper::ParseScanOptionValue(env, value);
    int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(id, optionIndex,
        SCAN_ACTION_SET_VALUE, optionValue);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void SetScanAutoOptionNative(ani_env *env, ani_string scannerId, ani_int optionIndex,
    ani_object callback)
{
    SCAN_HILOGI("enter SetScanAutoOptionNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s, Option Index: %{public}d", id.c_str(), optionIndex);
    ScanOptionValue optionValue;
    int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(id, optionIndex,
        SCAN_ACTION_SET_AUTO, optionValue);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetScannerCurrentSettingNative(ani_env *env, ani_string scannerId, ani_int optionIndex,
    ani_object callback)
{
    SCAN_HILOGI("enter GetScannerCurrentSettingNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s, Option Index: %{public}d", id.c_str(), optionIndex);
    ScanOptionValue optionValue;
    int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(id, optionIndex,
        SCAN_ACTION_GET_VALUE, optionValue);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniScanOptionValueHelper::CreateScanOptionValue(env, optionValue));
}

static void StartScanNative(ani_env *env, ani_string scannerId, ani_boolean batchMode, ani_object callback)
{
    SCAN_HILOGI("enter StartScanNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s, Batch Mode: %{public}d", id.c_str(), batchMode);
    int32_t ret = ScanManagerClient::GetInstance()->StartScan(id, batchMode);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void CancelScanNative(ani_env *env, ani_string scannerId, ani_object callback)
{
    SCAN_HILOGI("enter CancelScanNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s", id.c_str());
    int32_t ret = ScanManagerClient::GetInstance()->CancelScan(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetPictureScanProgressNative(ani_env *env, ani_string scannerId, ani_object callback)
{
    SCAN_HILOGI("enter GetPictureScanProgressNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, scannerId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Scanner ID: %{private}s", id.c_str());
    ScanProgress progress;
    int32_t ret = ScanManagerClient::GetInstance()->GetScanProgress(id, progress);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniScanProgressHelper::CreateScanProgress(env, progress));
}

static void AddScannerNative(ani_env *env, ani_string uniqueId, ani_string discoveryMode, ani_object callback)
{
    SCAN_HILOGI("enter AddScannerNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, uniqueId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    std::string mode;
    if (!GetStdString(env, discoveryMode, mode)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Unique ID: %{private}s, Discovery Mode: %{public}s", id.c_str(), mode.c_str());
    int32_t ret = ScanManagerClient::GetInstance()->AddScanner(id, mode);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void DeleteScannerNative(ani_env *env, ani_string uniqueId, ani_string discoveryMode, ani_object callback)
{
    SCAN_HILOGI("enter DeleteScannerNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string id;
    if (!GetStdString(env, uniqueId, id)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    std::string mode;
    if (!GetStdString(env, discoveryMode, mode)) {
        SCAN_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_SCAN_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    SCAN_HILOGD("Unique ID: %{private}s, Discovery Mode: %{public}s", id.c_str(), mode.c_str());
    int32_t ret = ScanManagerClient::GetInstance()->DeleteScanner(id, mode);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetAddedScannersNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter GetAddedScannersNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::vector<ScanDeviceInfo> scanners;
    int32_t ret = ScanManagerClient::GetInstance()->GetAddedScanner(scanners);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode, AniScannerDeviceHelper::CreateScannerDeviceArray(env, scanners));
}

static void OnScanDeviceFoundNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter OnScanDeviceFoundNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "scanDeviceFound";
    OHOS::sptr<IScanCallback> callbackWrapper = new (std::nothrow) ScanAniCallback(env, callback);
    ScanManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OffScanDeviceFoundNative(ani_env *env, ani_string type)
{
    SCAN_HILOGI("enter OffScanDeviceFoundNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        SCAN_HILOGE("GetStdString fail");
        return;
    }
    ScanManagerClient::GetInstance()->Off("", typeStr);
}

static void OnScanDeviceSyncNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter OnScanDeviceSyncNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "scanDeviceSync";
    OHOS::sptr<IScanCallback> callbackWrapper = new (std::nothrow) ScanAniCallback(env, callback);
    ScanManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OffScanDeviceSyncNative(ani_env *env, ani_string type)
{
    SCAN_HILOGI("enter OffScanDeviceSyncNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        SCAN_HILOGE("GetStdString fail");
        return;
    }
    ScanManagerClient::GetInstance()->Off("", typeStr);
}

static void OnScanDeviceAddNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter OnScanDeviceAddNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "scanDeviceAdd";
    OHOS::sptr<IScanCallback> callbackWrapper = new (std::nothrow) ScanAniCallback(env, callback);
    ScanManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OffScanDeviceAddNative(ani_env *env, ani_string type)
{
    SCAN_HILOGI("enter OffScanDeviceAddNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        SCAN_HILOGE("GetStdString fail");
        return;
    }
    ScanManagerClient::GetInstance()->Off("", typeStr);
}

static void OnScanDeviceDelNative(ani_env *env, ani_object callback)
{
    SCAN_HILOGI("enter OnScanDeviceDelNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "scanDeviceDel";
    OHOS::sptr<IScanCallback> callbackWrapper = new (std::nothrow) ScanAniCallback(env, callback);
    ScanManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OffScanDeviceDelNative(ani_env *env, ani_string type)
{
    SCAN_HILOGI("enter OffScanDeviceDelNative");
    if (env == nullptr) {
        SCAN_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        SCAN_HILOGE("GetStdString fail");
        return;
    }
    ScanManagerClient::GetInstance()->Off("", typeStr);
}

template<typename Func>
static inline ani_native_function MakeNativeFunc(const char* etsFuncName, Func cFunc)
{
    return {etsFuncName, nullptr, reinterpret_cast<void*>(cFunc)};
}

static std::array methods = {
    MakeNativeFunc("initNative", InitScanNative),
    MakeNativeFunc("exitNative", ExitScanNative),
    MakeNativeFunc("startScannerDiscoveryNative", StartScannerDiscoveryNative),
    MakeNativeFunc("openScannerNative", OpenScannerNative),
    MakeNativeFunc("closeScannerNative", CloseScannerNative),
    MakeNativeFunc("getScannerParameterNative", GetScannerParameterNative),
    MakeNativeFunc("setScannerParameterNative", SetScannerParameterNative),
    MakeNativeFunc("setScanAutoOptionNative", SetScanAutoOptionNative),
    MakeNativeFunc("getScannerCurrentSettingNative", GetScannerCurrentSettingNative),
    MakeNativeFunc("startScanNative", StartScanNative),
    MakeNativeFunc("cancelScanNative", CancelScanNative),
    MakeNativeFunc("getPictureScanProgressNative", GetPictureScanProgressNative),
    MakeNativeFunc("addScannerNative", AddScannerNative),
    MakeNativeFunc("deleteScannerNative", DeleteScannerNative),
    MakeNativeFunc("getAddedScannersNative", GetAddedScannersNative),
    MakeNativeFunc("onScanDeviceFoundNative", OnScanDeviceFoundNative),
    MakeNativeFunc("offScanDeviceFoundNative", OffScanDeviceFoundNative),
    MakeNativeFunc("onScanDeviceSyncNative", OnScanDeviceSyncNative),
    MakeNativeFunc("offScanDeviceSyncNative", OffScanDeviceSyncNative),
    MakeNativeFunc("onScanDeviceAddNative", OnScanDeviceAddNative),
    MakeNativeFunc("offScanDeviceAddNative", OffScanDeviceAddNative),
    MakeNativeFunc("onScanDeviceDelNative", OnScanDeviceDelNative),
    MakeNativeFunc("offScanDeviceDelNative", OffScanDeviceDelNative),
};

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    SCAN_HILOGI("enter ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        SCAN_HILOGE("vm or result is nullptr");
        return ANI_ERROR;
    }
    uint32_t status = 0;
    ani_env *env;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        SCAN_HILOGE("Unsupported ANI_VERSION_1, status = %{public}u", status);
        return static_cast<ani_status>(status);
    }

    ani_namespace ns {};
    const char* targetNamespace = "@ohos.scan.scan";
    status = env->FindNamespace(targetNamespace, &ns);
    if (status != ANI_OK) {
        SCAN_HILOGE("FindNamespace failed");
        return static_cast<ani_status>(status);
    }

    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        SCAN_HILOGE("Cannot bind native methods, status = %{public}u", status);
        return static_cast<ani_status>(status);
    };

    SCAN_HILOGI("Finish bind native methods");
    *result = ANI_VERSION_1;
    return ANI_OK;
}
