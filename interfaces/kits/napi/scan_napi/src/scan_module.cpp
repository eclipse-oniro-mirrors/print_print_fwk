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

#include "napi_inner_scan.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "napi_scan_utils.h"

using namespace OHOS::Scan;

static constexpr const char *FUNCTION_INIT_SCAN = "init";
static constexpr const char *FUNCTION_EXIT_SCAN = "exit";
static constexpr const char *FUNCTION_GET_SCANNER_LIST = "startScannerDiscovery";
static constexpr const char *FUNCTION_OPEN_SCANNER = "openScanner";
static constexpr const char *FUNCTION_CLOSE_SCANNER = "closeScanner";
static constexpr const char *FUNCTION_START_SCAN = "startScan";
static constexpr const char *FUNCTION_CANCEL_SCAN = "cancelScan";
static constexpr const char *FUNCTION_GET_SCAN_PROGRESS = "getPictureScanProgress";
static constexpr const char *FUNCTION_SET_SCAN_AUTO_OPTION = "setScanAutoOption";
static constexpr const char *FUNCTION_GET_SCAN_OPTION = "getScannerCurrentSetting";
static constexpr const char *FUNCTION_SET_SCAN_OPTION = "setScannerParameter";
static constexpr const char *FUNCTION_GET_SCAN_PARAMETERS = "getScannerParameter";

static constexpr const char *FUNCTION_ADD_SCANNER = "addScanner";
static constexpr const char *FUNCTION_DELETE_SCANNER = "deleteScanner";
static constexpr const char *FUNCTION_GET_ADDED_SCANNER = "getAddedScanners";
static constexpr const char *FUNCTION_REGISTER_EVENT = "on";
static constexpr const char *FUNCTION_UNREGISTER_EVENT = "off";


#define SCAN_NAPI_METHOD(name, func)           \
    {                                           \
        name, 0, func, 0, 0, 0, napi_default, 0 \
    }

#define SCAN_NAPI_PROPERTY(name, val)                                          \
    {                                                                           \
        (name), nullptr, nullptr, nullptr, nullptr, val, napi_static, nullptr   \
    }

static napi_value NapiCreateScanErrorCodeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        SCAN_HILOGE("Failed to create object");
        return nullptr;
    }
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_NO_PERMISSION", E_SCAN_NO_PERMISSION);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_NOT_SYSTEM_APPLICATION",
        E_SCAN_ERROR_NOT_SYSTEM_APPLICATION);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_INVALID_PARAMETER", E_SCAN_INVALID_PARAMETER);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_GENERIC_FAILURE", E_SCAN_GENERIC_FAILURE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_RPC_FAILURE", E_SCAN_RPC_FAILURE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_SERVER_FAILURE", E_SCAN_SERVER_FAILURE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_UNSUPPORTED", E_SCAN_UNSUPPORTED);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_CANCELED", E_SCAN_CANCELLED);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_DEVICE_BUSY", E_SCAN_DEVICE_BUSY);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_INVALID", E_SCAN_INVAL);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_JAMMED", E_SCAN_JAMMED);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_NO_DOCS", E_SCAN_NO_DOCS);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_COVER_OPEN", E_SCAN_COVER_OPEN);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_IO_ERROR", E_SCAN_IO_ERROR);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_ERROR_NO_MEMORY", E_SCAN_NO_MEM);
    return object;
}

static napi_value NapiCreateConstraintTypeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        SCAN_HILOGE("Failed to create object");
        return nullptr;
    }
    NapiScanUtils::SetUint32Property(env, object, "SCAN_CONSTRAINT_NONE", SCAN_CONSTRAINT_NONE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_CONSTRAINT_RANGE", SCAN_CONSTRAINT_RANGE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_CONSTRAINT_WORD_LIST", SCAN_CONSTRAINT_WORD_LIST);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_CONSTRAINT_STRING_LIST", SCAN_CONSTRAINT_STRING_LIST);
    return object;
}

static napi_value NapiCreatePhysicalUnitEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        SCAN_HILOGE("Failed to create object");
        return nullptr;
    }
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_NONE", SCANNER_UNIT_NONE);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_PIXEL", SCANNER_UNIT_PIXEL);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_BIT", SCANNER_UNIT_BIT);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_MM", SCANNER_UNIT_MM);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_DPI", SCANNER_UNIT_DPI);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_PERCENT", SCANNER_UNIT_PERCENT);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_UNIT_MICROSECOND", SCANNER_UNIT_MICROSECOND);
    return object;
}

static napi_value NapiCreateOptionValueTypeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        SCAN_HILOGE("Failed to create object");
        return nullptr;
    }
    NapiScanUtils::SetUint32Property(env, object, "SCAN_TYPE_BOOL", SCAN_VALUE_BOOL);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_TYPE_INT", SCAN_VALUE_NUM);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_TYPE_FIXED", SCAN_VALUE_FIXED);
    NapiScanUtils::SetUint32Property(env, object, "SCAN_TYPE_STRING", SCAN_VALUE_STR);
    return object;
}

static napi_value NapiCreateScannerDiscoveryModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        SCAN_HILOGE("Failed to create object");
        return nullptr;
    }
    NapiScanUtils::SetStringPropertyUtf8(env, object, "TCP_STR", "TCP");
    NapiScanUtils::SetStringPropertyUtf8(env, object, "USB_STR", "USB");
    return object;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        SCAN_NAPI_METHOD(FUNCTION_INIT_SCAN, NapiInnerScan::InitScan),
        SCAN_NAPI_METHOD(FUNCTION_EXIT_SCAN, NapiInnerScan::ExitScan),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCANNER_LIST, NapiInnerScan::GetScannerList),
        SCAN_NAPI_METHOD(FUNCTION_OPEN_SCANNER, NapiInnerScan::OpenScanner),
        SCAN_NAPI_METHOD(FUNCTION_CLOSE_SCANNER, NapiInnerScan::CloseScanner),
        SCAN_NAPI_METHOD(FUNCTION_SET_SCAN_OPTION, NapiInnerScan::SetScanOption),
        SCAN_NAPI_METHOD(FUNCTION_SET_SCAN_AUTO_OPTION, NapiInnerScan::SetScanAutoOption),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_OPTION, NapiInnerScan::GetScanOption),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_PARAMETERS, NapiInnerScan::GetScanParameters),
        SCAN_NAPI_METHOD(FUNCTION_START_SCAN, NapiInnerScan::StartScan),
        SCAN_NAPI_METHOD(FUNCTION_CANCEL_SCAN, NapiInnerScan::CancelScan),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_PROGRESS, NapiInnerScan::GetScanProgress),
        SCAN_NAPI_METHOD(FUNCTION_ADD_SCANNER, NapiInnerScan::AddScanner),
        SCAN_NAPI_METHOD(FUNCTION_DELETE_SCANNER, NapiInnerScan::DeleteScanner),
        SCAN_NAPI_METHOD(FUNCTION_GET_ADDED_SCANNER, NapiInnerScan::GetAddedScanner),
        SCAN_NAPI_METHOD(FUNCTION_REGISTER_EVENT, NapiInnerScan::On),
        SCAN_NAPI_METHOD(FUNCTION_UNREGISTER_EVENT, NapiInnerScan::Off),
        SCAN_NAPI_PROPERTY("ScanErrorCode", NapiCreateScanErrorCodeEnum(env)),
        SCAN_NAPI_PROPERTY("ConstraintType", NapiCreateConstraintTypeEnum(env)),
        SCAN_NAPI_PROPERTY("PhysicalUnit", NapiCreatePhysicalUnitEnum(env)),
        SCAN_NAPI_PROPERTY("OptionValueType", NapiCreateOptionValueTypeEnum(env)),
        SCAN_NAPI_PROPERTY("ScannerDiscoveryMode", NapiCreateScannerDiscoveryModeEnum(env)),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    SCAN_HILOGD("init scan module %{public}d", status);
    return exports;
}

static __attribute__((constructor)) void RegisterModule()
{
    static napi_module module = { .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = Init,
        .nm_modname = "scan",
        .nm_priv = ((void *)0),
        .reserved = { 0 } };
    napi_module_register(&module);
    SCAN_HILOGD("module register scan");
}
