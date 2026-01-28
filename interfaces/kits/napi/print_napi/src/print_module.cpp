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

#include <map>
#include "napi_inner_print.h"
#include "napi_print_ext.h"
#include "napi_print_task.h"
#ifdef PDFIUM_ENABLE
#include "napi_print_pdf_render.h"
#endif  // PDFIUM_ENABLE
#include "print_constant.h"
#include "print_log.h"

using namespace OHOS::Print;

static constexpr const char *FUNCTION_PRINT = "print";
static constexpr const char *FUNCTION_QUERY_EXT = "queryAllPrinterExtensionInfos";
static constexpr const char *FUNCTION_START_DISCOVERY = "startDiscoverPrinter";
static constexpr const char *FUNCTION_STOP_DISCOVERY = "stopDiscoverPrinter";
static constexpr const char *FUNCTION_CONNECT_PRINT = "connectPrinter";
static constexpr const char *FUNCTION_DISCONNECT_PRINT = "disconnectPrinter";
static constexpr const char *FUNCTION_START_PRINT_JOB = "startPrintJob";
static constexpr const char *FUNCTION_START_PRINT = "startPrint";
static constexpr const char *FUNCTION_CANCEL_PRINT = "cancelPrintJob";
static constexpr const char *FUNCTION_RESTART_PRINT = "restartPrintJob";
static constexpr const char *FUNCTION_REQUEST_PREVIEW = "requestPrintPreview";
static constexpr const char *FUNCTION_QUERY_CAPABILITY = "queryPrinterCapability";
static constexpr const char *FUNCTION_QUERY_ALL_PRINTJOB = "queryAllPrintJobs";
static constexpr const char *FUNCTION_QUERY_PRINTJOB_LIST = "queryPrintJobList";
static constexpr const char *FUNCTION_QUERY_ALL_ACTIVE_PRINTJOB = "queryAllActivePrintJobs";
static constexpr const char *FUNCTION_QUERY_PRINTJOB_BYID = "queryPrintJobById";
static constexpr const char *FUNCTION_REGISTER_EVENT = "on";
static constexpr const char *FUNCTION_UNREGISTER_EVENT = "off";
static constexpr const char *FUNCTION_ADD_PRINTER = "addPrinters";
static constexpr const char *FUNCTION_REMOVE_PRINTER = "removePrinters";
static constexpr const char *FUNCTION_UPDATE_PRINTER = "updatePrinters";
static constexpr const char *FUNCTION_UPDATE_PRINTER_STATE = "updatePrinterState";
static constexpr const char *FUNCTION_UPDATE_JOB_STATE = "updatePrintJobState";
static constexpr const char *FUNCTION_UPDATE_EXTENSION_INFO = "updateExtensionInfo";
static constexpr const char *FUNCTION_NATIVE_ADD_PRINTER_TO_CUPS = "addPrinterToCups";
static constexpr const char *FUNCTION_QUERY_CAPABILITY_BY_URI = "queryPrinterCapabilityByUri";
static constexpr const char *FUNCTION_START_GET_PRINT_FILE = "startGettingPrintFile";
static constexpr const char *FUNCTION_NOTIFY_PRINT_SERVICE = "notifyPrintService";
static constexpr const char *FUNCTION_QUERY_ADDED_PRINTER = "getAddedPrinters";
static constexpr const char *FUNCTION_QUERY_PRINTER_INFO_BY_PRINTER_ID = "getPrinterInfoById";
static constexpr const char *FUNCTION_NOTIFY_PRINT_SERVICE_EVENT = "notifyPrintServiceEvent";
static constexpr const char *FUNCTION_SET_PRINTER_PREFERENCE = "setPrinterPreference";
static constexpr const char *FUNCTION_SET_DEFAULT_PRINTER = "setDefaultPrinter";
static constexpr const char *FUNCTION_DELETE_PRINTER_FROM_CUPS = "deletePrinterFromCups";
static constexpr const char *FUNCTION_DISCOVER_USB_PRINTERS = "discoverUsbPrinters";
static constexpr const char *FUNCTION_ADD_PRINTER_TO_DISCOVERY = "addPrinterToDiscovery";
static constexpr const char *FUNCTION_UPDATE_PRINTER_IN_DISCOVERY = "updatePrinterInDiscovery";
static constexpr const char *FUNCTION_REMOVE_PRINTER_FROM_DISCOVERY = "removePrinterFromDiscovery";
static constexpr const char *FUNCTION_GET_ADDED_PRINTER_INFO_BY_ID = "getAddedPrinterInfoById";
static constexpr const char *FUNCTION_GET_PRINTER_INFORMATION_BY_ID = "getPrinterInformationById";
static constexpr const char *FUNCTION_UPDATE_PRINTER_IN_SYSTEM = "updatePrinterInSystem";
static constexpr const char *FUNCTION_UPDATE_PRINTER_INFORMATION = "updatePrinterInformation";
static constexpr const char *FUNCTION_SET_PRINTER_PREFERENCES = "setPrinterPreferences";
static constexpr const char *FUNCTION_ANYLYZE_PRINT_EVENTS = "analyzePrintEvents";
static constexpr const char *FUNCTION_AUTH_PRINT_JOB = "authPrintJob";
static constexpr const char *FUNCTION_QUERY_ALL_PRINTER_PPDS = "queryAllPrinterPpds";
static constexpr const char *FUNCTION_QUERY_PRINTER_INFO_BY_IP = "queryPrinterInfoByIp";
static constexpr const char *FUNCTION_CONNECT_PRINTER_BY_IP_AND_PPD = "connectPrinterByIpAndPpd";
static constexpr const char *FUNCTION_SAVE_PDF_FILE_JOB = "savePdfFileJob";
static constexpr const char *FUNCTION_QUERY_RECOMMAND_DRIVERS_BY_ID = "queryRecommendDriversById";
static constexpr const char *FUNCTION_CONNECT_PRINTER_BY_ID_AND_PPD = "connectPrinterByIdAndPpd";
static constexpr const char *FUNCTION_CHECK_PREFERENCES_CONFLICTS = "checkPreferencesConflicts";
static constexpr const char *FUNCTION_CHECK_PRINTJOB_CONFLICTS = "checkPrintJobConflicts";
static constexpr const char *FUNCTION_GET_PRINTER_DEFAULT_PREFERENCES = "getPrinterDefaultPreferences";
static constexpr const char *FUNCTION_GET_SHARED_HOST = "getSharedHosts";
static constexpr const char *AUTH_SMB_DEVICE_AS_GUEST = "authSmbDeviceAsGuest";
static constexpr const char *AUTH_SMB_DEVICE_AS_REGISTERED_USER = "authSmbDeviceAsRegisteredUser";

static const std::map<std::string, uint32_t> PRINT_JOB_SUBSTATE_MAP = {
    {"PRINT_JOB_COMPLETED_SUCCESS", PRINT_JOB_COMPLETED_SUCCESS},
    {"PRINT_JOB_COMPLETED_FAILED", PRINT_JOB_COMPLETED_FAILED},
    {"PRINT_JOB_COMPLETED_CANCELLED", PRINT_JOB_COMPLETED_CANCELLED},
    {"PRINT_JOB_COMPLETED_FILE_CORRUPTED", PRINT_JOB_COMPLETED_FILE_CORRUPT},
    {"PRINT_JOB_BLOCK_OFFLINE", PRINT_JOB_BLOCKED_OFFLINE},
    {"PRINT_JOB_BLOCK_BUSY", PRINT_JOB_BLOCKED_BUSY},
    {"PRINT_JOB_BLOCK_CANCELLED", PRINT_JOB_BLOCKED_CANCELLED},
    {"PRINT_JOB_BLOCK_OUT_OF_PAPER", PRINT_JOB_BLOCKED_OUT_OF_PAPER},
    {"PRINT_JOB_BLOCK_OUT_OF_INK", PRINT_JOB_BLOCKED_OUT_OF_INK},
    {"PRINT_JOB_BLOCK_OUT_OF_TONER", PRINT_JOB_BLOCKED_OUT_OF_TONER},
    {"PRINT_JOB_BLOCK_JAMMED", PRINT_JOB_BLOCKED_JAMMED},
    {"PRINT_JOB_BLOCK_DOOR_OPEN", PRINT_JOB_BLOCKED_DOOR_OPEN},
    {"PRINT_JOB_BLOCK_SERVICE_REQUEST", PRINT_JOB_BLOCKED_SERVICE_REQUEST},
    {"PRINT_JOB_BLOCK_LOW_ON_INK", PRINT_JOB_BLOCKED_LOW_ON_INK},
    {"PRINT_JOB_BLOCK_LOW_ON_TONER", PRINT_JOB_BLOCKED_LOW_ON_TONER},
    {"PRINT_JOB_BLOCK_REALLY_LOW_ON_INK", PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK},
    {"PRINT_JOB_BLOCK_BAD_CERTIFICATE", PRINT_JOB_BLOCKED_BAD_CERTIFICATE},
    {"PRINT_JOB_BLOCK_DRIVER_EXCEPTION", PRINT_JOB_BLOCKED_DRIVER_EXCEPTION},
    {"PRINT_JOB_BLOCK_ACCOUNT_ERROR", PRINT_JOB_BLOCKED_ACCOUNT_ERROR},
    {"PRINT_JOB_BLOCK_PRINT_PERMISSION_ERROR", PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR},
    {"PRINT_JOB_BLOCK_PRINT_COLOR_PERMISSION_ERROR", PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR},
    {"PRINT_JOB_BLOCK_NETWORK_ERROR", PRINT_JOB_BLOCKED_NETWORK_ERROR},
    {"PRINT_JOB_BLOCK_SERVER_CONNECTION_ERROR", PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR},
    {"PRINT_JOB_BLOCK_LARGE_FILE_ERROR", PRINT_JOB_BLOCKED_LARGE_FILE_ERROR},
    {"PRINT_JOB_BLOCK_FILE_PARSING_ERROR", PRINT_JOB_BLOCKED_FILE_PARSING_ERROR},
    {"PRINT_JOB_BLOCK_SLOW_FILE_CONVERSION", PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION},
    {"PRINT_JOB_RUNNING_UPLOADING_FILES", PRINT_JOB_RUNNING_UPLOADING_FILES},
    {"PRINT_JOB_RUNNING_CONVERTING_FILES", PRINT_JOB_RUNNING_CONVERTING_FILES},
    {"PRINT_JOB_BLOCK_INTERRUPT", PRINT_JOB_BLOCKED_INTERRUPT},
    {"PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR", PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR},
    {"PRINT_JOB_BLOCK_DRIVER_MISSING", PRINT_JOB_BLOCKED_DRIVER_MISSING},
    {"PRINT_JOB_BLOCK_INTERRUPT", PRINT_JOB_BLOCKED_INTERRUPT},
    {"PRINT_JOB_BLOCK_PRINTER_UNAVAILABLE", PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE},
    {"PRINT_JOB_BLOCK_UNKNOWN", PRINT_JOB_BLOCKED_UNKNOWN},
};

#define PRINT_NAPI_METHOD(name, func)           \
    {                                           \
        name, 0, func, 0, 0, 0, napi_default, 0 \
    }

#define PRINT_NAPI_PROPERTY(name, val)                                        \
    {                                                                         \
        (name), nullptr, nullptr, nullptr, nullptr, val, napi_static, nullptr \
    }

static void SetEnumProperty(napi_env env, napi_value object, const std::string &name, uint32_t value)
{
    if (name.empty()) {
        PRINT_HILOGE("Property name cannot be an empty string");
        return;
    }
    napi_value tempValue = nullptr;
    napi_status status = napi_create_int32(env, value, &tempValue);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create int32 value for enum %s", name.c_str());
        return;
    }
    status = napi_set_named_property(env, object, name.c_str(), tempValue);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to set property %s", name.c_str());
        return;
    }
}

static napi_value NapiCreateDirectionModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "DIRECTION_MODE_AUTO", static_cast<int32_t>(DIRECTION_MODE_AUTO));
    SetEnumProperty(env, object, "DIRECTION_MODE_PORTRAIT", static_cast<int32_t>(DIRECTION_MODE_PORTRAIT));
    SetEnumProperty(env, object, "DIRECTION_MODE_LANDSCAPE", static_cast<int32_t>(DIRECTION_MODE_LANDSCAPE));
    return object;
}

static napi_value NapiCreateColorModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "COLOR_MODE_MONOCHROME", static_cast<int32_t>(PRINT_COLOR_MODE_MONOCHROME));
    SetEnumProperty(env, object, "COLOR_MODE_COLOR", static_cast<int32_t>(PRINT_COLOR_MODE_COLOR));
    return object;
}

static napi_value NapiCreateDuplexModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "DUPLEX_MODE_NONE", static_cast<int32_t>(DUPLEX_MODE_NONE));
    SetEnumProperty(env, object, "DUPLEX_MODE_LONG_EDGE", static_cast<int32_t>(DUPLEX_MODE_LONG_EDGE));
    SetEnumProperty(env, object, "DUPLEX_MODE_SHORT_EDGE", static_cast<int32_t>(DUPLEX_MODE_SHORT_EDGE));
    return object;
}

static napi_value NapiCreateQualityEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "QUALITY_DRAFT", static_cast<int32_t>(PRINT_QUALITY_DRAFT));
    SetEnumProperty(env, object, "QUALITY_NORMAL", static_cast<int32_t>(PRINT_QUALITY_NORMAL));
    SetEnumProperty(env, object, "QUALITY_HIGH", static_cast<int32_t>(PRINT_QUALITY_HIGH));
    return object;
}

static napi_value NapiCreateDocumentFormatEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_AUTO", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_AUTO));
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_JPEG", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_JPEG));
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_PDF", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_PDF));
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_POSTSCRIPT", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_POSTSCRIPT));
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_TEXT", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_TEXT));
    SetEnumProperty(env, object, "DOCUMENT_FORMAT_RAW", static_cast<int32_t>(PRINT_DOCUMENT_FORMAT_RAW));
    return object;
}

static napi_value NapiCreateDocFlavorEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "FILE_DESCRIPTOR", static_cast<int32_t>(PRINT_FILE_DESCRIPTOR));
    SetEnumProperty(env, object, "BYTES", static_cast<int32_t>(PRINT_BYTES));
    return object;
}

static napi_value NapiCreateOrientationEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "ORIENTATION_MODE_PORTRAIT", static_cast<int32_t>(PRINT_ORIENTATION_MODE_PORTRAIT));
    SetEnumProperty(env, object, "ORIENTATION_MODE_LANDSCAPE", static_cast<int32_t>(PRINT_ORIENTATION_MODE_LANDSCAPE));
    SetEnumProperty(env,
        object,
        "ORIENTATION_MODE_REVERSE_LANDSCAPE",
        static_cast<int32_t>(PRINT_ORIENTATION_MODE_REVERSE_LANDSCAPE));
    SetEnumProperty(env,
        object,
        "ORIENTATION_MODE_REVERSE_PORTRAIT",
        static_cast<int32_t>(PRINT_ORIENTATION_MODE_REVERSE_PORTRAIT));
    SetEnumProperty(env, object, "ORIENTATION_MODE_NONE", static_cast<int32_t>(PRINT_ORIENTATION_MODE_NONE));
    return object;
}

static napi_value NapiCreatePageTypeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PAGE_ISO_A3", static_cast<int32_t>(PAGE_ISO_A3));
    SetEnumProperty(env, object, "PAGE_ISO_A4", static_cast<int32_t>(PAGE_ISO_A4));
    SetEnumProperty(env, object, "PAGE_ISO_A5", static_cast<int32_t>(PAGE_ISO_A5));
    SetEnumProperty(env, object, "PAGE_JIS_B5", static_cast<int32_t>(PAGE_JIS_B5));
    SetEnumProperty(env, object, "PAGE_ISO_C5", static_cast<int32_t>(PAGE_ISO_C5));
    SetEnumProperty(env, object, "PAGE_ISO_DL", static_cast<int32_t>(PAGE_ISO_DL));
    SetEnumProperty(env, object, "PAGE_LETTER", static_cast<int32_t>(PAGE_LETTER));
    SetEnumProperty(env, object, "PAGE_LEGAL", static_cast<int32_t>(PAGE_LEGAL));
    SetEnumProperty(env, object, "PAGE_PHOTO_4X6", static_cast<int32_t>(PAGE_PHOTO_4X6));
    SetEnumProperty(env, object, "PAGE_PHOTO_5X7", static_cast<int32_t>(PAGE_PHOTO_5X7));
    SetEnumProperty(env, object, "PAGE_INT_DL_ENVELOPE", static_cast<int32_t>(PAGE_INT_DL_ENVELOPE));
    SetEnumProperty(env, object, "PAGE_B_TABLOID", static_cast<int32_t>(PAGE_B_TABLOID));
    return object;
}

static napi_value NapiCreateDocumentAdapterStateEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PREVIEW_DESTROY", static_cast<int32_t>(PREVIEW_ABILITY_DESTROY));
    SetEnumProperty(env, object, "PRINT_TASK_SUCCEED", static_cast<int32_t>(PRINT_TASK_SUCCEED));
    SetEnumProperty(env, object, "PRINT_TASK_FAIL", static_cast<int32_t>(PRINT_TASK_FAIL));
    SetEnumProperty(env, object, "PRINT_TASK_CANCEL", static_cast<int32_t>(PRINT_TASK_CANCEL));
    SetEnumProperty(env, object, "PRINT_TASK_BLOCK", static_cast<int32_t>(PRINT_TASK_BLOCK));
    return object;
}

static napi_value NapiCreateFileCreationStateEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PRINT_FILE_CREATED", static_cast<int32_t>(PRINT_FILE_CREATED_SUCCESS));
    SetEnumProperty(env, object, "PRINT_FILE_CREATION_FAILED", static_cast<int32_t>(PRINT_FILE_CREATED_FAIL));
    SetEnumProperty(
        env, object, "PRINT_FILE_CREATED_UNRENDERED", static_cast<int32_t>(PRINT_FILE_CREATED_SUCCESS_UNRENDERED));
    return object;
}

static napi_value NapiCreatePrinterStateEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PRINTER_ADDED", static_cast<int32_t>(PRINTER_ADDED));
    SetEnumProperty(env, object, "PRINTER_REMOVED", static_cast<int32_t>(PRINTER_REMOVED));
    SetEnumProperty(env, object, "PRINTER_CAPABILITY_UPDATED", static_cast<int32_t>(PRINTER_UPDATE_CAP));
    SetEnumProperty(env, object, "PRINTER_CONNECTED", static_cast<int32_t>(PRINTER_CONNECTED));
    SetEnumProperty(env, object, "PRINTER_DISCONNECTED", static_cast<int32_t>(PRINTER_DISCONNECTED));
    SetEnumProperty(env, object, "PRINTER_RUNNING", static_cast<int32_t>(PRINTER_RUNNING));
    return object;
}

static napi_value NapiCreatePrintJobStateEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PRINT_JOB_PREPARE", static_cast<int32_t>(PRINT_JOB_PREPARED));
    SetEnumProperty(env, object, "PRINT_JOB_QUEUED", static_cast<int32_t>(PRINT_JOB_QUEUED));
    SetEnumProperty(env, object, "PRINT_JOB_RUNNING", static_cast<int32_t>(PRINT_JOB_RUNNING));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCKED", static_cast<int32_t>(PRINT_JOB_BLOCKED));
    SetEnumProperty(env, object, "PRINT_JOB_COMPLETED", static_cast<int32_t>(PRINT_JOB_COMPLETED));
    return object;
}

static napi_value NapiCreatePrintJobSubStateEnum(napi_env env)
{
    napi_value object = nullptr;
    if (napi_create_object(env, &object) != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    for (const auto &[key, value] : PRINT_JOB_SUBSTATE_MAP) {
        SetEnumProperty(env, object, key, static_cast<int32_t>(value));
    }
    return object;
}

static napi_value NapiCreatePrintErrorCodeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "E_PRINT_NONE", static_cast<int32_t>(E_PRINT_NONE));
    SetEnumProperty(env, object, "E_PRINT_NO_PERMISSION", static_cast<int32_t>(E_PRINT_NO_PERMISSION));
    SetEnumProperty(env, object, "E_PRINT_INVALID_PARAMETER", static_cast<int32_t>(E_PRINT_INVALID_PARAMETER));
    SetEnumProperty(env, object, "E_PRINT_GENERIC_FAILURE", static_cast<int32_t>(E_PRINT_GENERIC_FAILURE));
    SetEnumProperty(env, object, "E_PRINT_RPC_FAILURE", static_cast<int32_t>(E_PRINT_RPC_FAILURE));
    SetEnumProperty(env, object, "E_PRINT_SERVER_FAILURE", static_cast<int32_t>(E_PRINT_SERVER_FAILURE));
    SetEnumProperty(env, object, "E_PRINT_INVALID_EXTENSION", static_cast<int32_t>(E_PRINT_INVALID_EXTENSION));
    SetEnumProperty(env, object, "E_PRINT_INVALID_PRINTER", static_cast<int32_t>(E_PRINT_INVALID_PRINTER));
    SetEnumProperty(env, object, "E_PRINT_INVALID_PRINT_JOB", static_cast<int32_t>(E_PRINT_INVALID_PRINTJOB));
    SetEnumProperty(env, object, "E_PRINT_FILE_IO", static_cast<int32_t>(E_PRINT_FILE_IO));
    SetEnumProperty(env, object, "E_PRINT_TOO_MANY_FILES", static_cast<int32_t>(E_PRINT_TOO_MANY_FILES));
    return object;
}

static napi_value NapiCreatePrintStatusEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PRINTER_STATUS_IDLE", static_cast<int32_t>(PRINTER_STATUS_IDLE));
    SetEnumProperty(env, object, "PRINTER_STATUS_BUSY", static_cast<int32_t>(PRINTER_STATUS_BUSY));
    SetEnumProperty(env, object, "PRINTER_STATUS_UNAVAILABLE", static_cast<int32_t>(PRINTER_STATUS_UNAVAILABLE));
    return object;
}

static napi_value NapiCreatePrintEventEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "PRINTER_EVENT_ADDED", static_cast<int32_t>(PRINTER_EVENT_ADDED));
    SetEnumProperty(env, object, "PRINTER_EVENT_DELETED", static_cast<int32_t>(PRINTER_EVENT_DELETED));
    SetEnumProperty(env, object, "PRINTER_EVENT_STATE_CHANGED", static_cast<int32_t>(PRINTER_EVENT_STATE_CHANGED));
    SetEnumProperty(env, object, "PRINTER_EVENT_INFO_CHANGED", static_cast<int32_t>(PRINTER_EVENT_INFO_CHANGED));
    return object;
}

static napi_value NapiCreateApplicationEventEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(env, object, "APPLICATION_CREATED", static_cast<int32_t>(APPLICATION_CREATED));
    SetEnumProperty(
        env, object, "APPLICATION_CLOSED_FOR_STARTED", static_cast<int32_t>(APPLICATION_CLOSED_FOR_STARTED));
    SetEnumProperty(
        env, object, "APPLICATION_CLOSED_FOR_CANCELED", static_cast<int32_t>(APPLICATION_CLOSED_FOR_CANCELED));
    return object;
}

static napi_value NapiCreateDefaultPrinterTypeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_status status = napi_create_object(env, &object);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create object");
        return nullptr;
    }
    SetEnumProperty(
        env, object, "DEFAULT_PRINTER_TYPE_SETTED_BY_USER", static_cast<int32_t>(DEFAULT_PRINTER_TYPE_SETTED_BY_USER));
    SetEnumProperty(env,
        object,
        "DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER",
        static_cast<int32_t>(DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER));
    return object;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        PRINT_NAPI_PROPERTY("PrintDirectionMode", NapiCreateDirectionModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintColorMode", NapiCreateColorModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintDuplexMode", NapiCreateDuplexModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintQuality", NapiCreateQualityEnum(env)),
        PRINT_NAPI_PROPERTY("PrintDocumentFormat", NapiCreateDocumentFormatEnum(env)),
        PRINT_NAPI_PROPERTY("DocFlavor", NapiCreateDocFlavorEnum(env)),
        PRINT_NAPI_PROPERTY("PrintOrientationMode", NapiCreateOrientationEnum(env)),
        PRINT_NAPI_PROPERTY("PrintPageType", NapiCreatePageTypeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintDocumentAdapterState", NapiCreateDocumentAdapterStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintFileCreationState", NapiCreateFileCreationStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrinterState", NapiCreatePrinterStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintJobState", NapiCreatePrintJobStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintJobSubState", NapiCreatePrintJobSubStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintErrorCode", NapiCreatePrintErrorCodeEnum(env)),
        PRINT_NAPI_PROPERTY("PrinterStatus", NapiCreatePrintStatusEnum(env)),
        PRINT_NAPI_PROPERTY("PrinterEvent", NapiCreatePrintEventEnum(env)),
        PRINT_NAPI_PROPERTY("ApplicationEvent", NapiCreateApplicationEventEnum(env)),
        PRINT_NAPI_PROPERTY("DefaultPrinterType", NapiCreateDefaultPrinterTypeEnum(env)),

        PRINT_NAPI_METHOD(FUNCTION_PRINT, NapiPrintTask::Print),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_EXT, NapiInnerPrint::QueryExtensionInfo),
        PRINT_NAPI_METHOD(FUNCTION_START_DISCOVERY, NapiInnerPrint::StartDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_STOP_DISCOVERY, NapiInnerPrint::StopDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_CONNECT_PRINT, NapiInnerPrint::ConnectPrinter),
        PRINT_NAPI_METHOD(FUNCTION_DISCONNECT_PRINT, NapiInnerPrint::DisconnectPrinter),
        PRINT_NAPI_METHOD(FUNCTION_START_PRINT_JOB, NapiInnerPrint::StartPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_START_PRINT, NapiInnerPrint::StartPrint),
        PRINT_NAPI_METHOD(FUNCTION_CANCEL_PRINT, NapiInnerPrint::CancelPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_RESTART_PRINT, NapiInnerPrint::RestartPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_REQUEST_PREVIEW, NapiInnerPrint::RequestPreview),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_CAPABILITY, NapiInnerPrint::QueryCapability),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_ALL_PRINTJOB, NapiInnerPrint::QueryAllPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTJOB_LIST, NapiInnerPrint::QueryAllActivePrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_ALL_ACTIVE_PRINTJOB, NapiInnerPrint::QueryAllActivePrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTJOB_BYID, NapiInnerPrint::QueryPrintJobById),
        PRINT_NAPI_METHOD(FUNCTION_REGISTER_EVENT, NapiInnerPrint::On),
        PRINT_NAPI_METHOD(FUNCTION_UNREGISTER_EVENT, NapiInnerPrint::Off),
        PRINT_NAPI_METHOD(FUNCTION_ADD_PRINTER, NapiPrintExt::AddPrinters),
        PRINT_NAPI_METHOD(FUNCTION_REMOVE_PRINTER, NapiPrintExt::RemovePrinters),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER, NapiPrintExt::UpdatePrinters),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_STATE, NapiPrintExt::UpdatePrinterState),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_JOB_STATE, NapiPrintExt::UpdatePrintJobStateOnlyForSystemApp),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_EXTENSION_INFO, NapiPrintExt::UpdateExtensionInfo),
        PRINT_NAPI_METHOD(FUNCTION_NATIVE_ADD_PRINTER_TO_CUPS, NapiPrintExt::AddPrinterToCups),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_CAPABILITY_BY_URI, NapiPrintExt::QueryPrinterCapabilityByUri),
        PRINT_NAPI_METHOD(FUNCTION_START_GET_PRINT_FILE, NapiInnerPrint::StartGetPrintFile),
        PRINT_NAPI_METHOD(FUNCTION_NOTIFY_PRINT_SERVICE, NapiInnerPrint::NotifyPrintService),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_ADDED_PRINTER, NapiInnerPrint::QueryAddedPrinter),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTER_INFO_BY_PRINTER_ID, NapiInnerPrint::QueryPrinterInfoByPrinterId),
        PRINT_NAPI_METHOD(FUNCTION_NOTIFY_PRINT_SERVICE_EVENT, NapiInnerPrint::NotifyPrintServiceEvent),
        PRINT_NAPI_METHOD(FUNCTION_SET_PRINTER_PREFERENCE, NapiInnerPrint::SetPrinterPreference),
        PRINT_NAPI_METHOD(FUNCTION_SET_DEFAULT_PRINTER, NapiInnerPrint::SetDefaultPrinter),
        PRINT_NAPI_METHOD(FUNCTION_DELETE_PRINTER_FROM_CUPS, NapiPrintExt::DeletePrinterFromCups),
        PRINT_NAPI_METHOD(FUNCTION_DISCOVER_USB_PRINTERS, NapiPrintExt::DiscoverUsbPrinters),
        PRINT_NAPI_METHOD(FUNCTION_ADD_PRINTER_TO_DISCOVERY, NapiPrintExt::AddPrinterToDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_IN_DISCOVERY, NapiPrintExt::UpdatePrinterInDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_REMOVE_PRINTER_FROM_DISCOVERY, NapiPrintExt::RemovePrinterFromDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_GET_ADDED_PRINTER_INFO_BY_ID, NapiInnerPrint::GetAddedPrinterInfoById),
        PRINT_NAPI_METHOD(FUNCTION_GET_PRINTER_INFORMATION_BY_ID, NapiInnerPrint::GetAddedPrinterInfoById),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_IN_SYSTEM, NapiPrintExt::UpdatePrinterInSystem),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_INFORMATION, NapiPrintExt::UpdatePrinterInSystem),
        PRINT_NAPI_METHOD(FUNCTION_SET_PRINTER_PREFERENCES, NapiInnerPrint::SetPrinterPreference),
        PRINT_NAPI_METHOD(FUNCTION_ANYLYZE_PRINT_EVENTS, NapiInnerPrint::AnalyzePrintEvents),
        PRINT_NAPI_METHOD(FUNCTION_AUTH_PRINT_JOB, NapiInnerPrint::AuthPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_ALL_PRINTER_PPDS, NapiInnerPrint::QueryAllPrinterPpds),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTER_INFO_BY_IP, NapiInnerPrint::QueryPrinterInfoByIp),
        PRINT_NAPI_METHOD(FUNCTION_CONNECT_PRINTER_BY_IP_AND_PPD, NapiInnerPrint::ConnectPrinterByIpAndPpd),
        PRINT_NAPI_METHOD(FUNCTION_SAVE_PDF_FILE_JOB, NapiInnerPrint::SavePdfFileJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_RECOMMAND_DRIVERS_BY_ID, NapiInnerPrint::QueryRecommendDriversById),
        PRINT_NAPI_METHOD(FUNCTION_CONNECT_PRINTER_BY_ID_AND_PPD, NapiInnerPrint::ConnectPrinterByIdAndPpd),
        PRINT_NAPI_METHOD(FUNCTION_CHECK_PREFERENCES_CONFLICTS, NapiInnerPrint::CheckPreferencesConflicts),
        PRINT_NAPI_METHOD(FUNCTION_CHECK_PRINTJOB_CONFLICTS, NapiInnerPrint::CheckPrintJobConflicts),
        PRINT_NAPI_METHOD(FUNCTION_GET_PRINTER_DEFAULT_PREFERENCES, NapiInnerPrint::GetPrinterDefaultPreferences),
        PRINT_NAPI_METHOD(FUNCTION_GET_SHARED_HOST, NapiInnerPrint::GetSharedHosts),
        PRINT_NAPI_METHOD(AUTH_SMB_DEVICE_AS_GUEST, NapiInnerPrint::AuthSmbDeviceAsGuest),
        PRINT_NAPI_METHOD(AUTH_SMB_DEVICE_AS_REGISTERED_USER, NapiInnerPrint::AuthSmbDeviceAsRegisteredUser),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    PRINT_HILOGD("init print module %{public}d", status);
    return exports;
}

static __attribute__((constructor)) void RegisterModule()
{
    static napi_module module = {.nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = Init,
        .nm_modname = "print",
        .nm_priv = ((void *)0),
        .reserved = {0}};
    napi_module_register(&module);
    PRINT_HILOGD("module register print");
}
