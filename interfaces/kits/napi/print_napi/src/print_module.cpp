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

#include "napi_inner_print.h"
#include "napi_print_ext.h"
#include "napi_print_task.h"
#ifdef PDFIUM_ENABLE
#include "napi_print_pdf_render.h"
#endif // PDFIUM_ENABLE
#include "print_constant.h"
#include "print_log.h"

using namespace OHOS::Print;

static constexpr const char *FUNCTION_PRINT = "print";
#ifdef PDFIUM_ENABLE
static constexpr const char *FUNCTION_CREATE_PDF_RENDER = "createPdfRender";
#endif // PDFIUM_ENABLE
static constexpr const char *FUNCTION_QUERY_EXT = "queryAllPrinterExtensionInfos";
static constexpr const char *FUNCTION_START_DISCOVERY = "startDiscoverPrinter";
static constexpr const char *FUNCTION_STOP_DISCOVERY = "stopDiscoverPrinter";
static constexpr const char *FUNCTION_CONNECT_PRINT = "connectPrinter";
static constexpr const char *FUNCTION_DISCONNECT_PRINT = "disconnectPrinter";
static constexpr const char *FUNCTION_START_PRINT = "startPrintJob";
static constexpr const char *FUNCTION_CANCEL_PRINT = "cancelPrintJob";
static constexpr const char *FUNCTION_REQUEST_PREVIEW = "requestPrintPreview";
static constexpr const char *FUNCTION_QUERY_CAPABILITY = "queryPrinterCapability";
static constexpr const char *FUNCTION_QUERY_ALL_PRINTJOB = "queryAllPrintJobs";
static constexpr const char *FUNCTION_QUERY_PRINTJOB_LIST = "queryPrintJobList";
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

#define PRINT_NAPI_METHOD(name, func)           \
    {                                           \
        name, 0, func, 0, 0, 0, napi_default, 0 \
    }

#define PRINT_NAPI_PROPERTY(name, val)                                          \
    {                                                                           \
        (name), nullptr, nullptr, nullptr, nullptr, val, napi_static, nullptr   \
    }

static void SetEnumProperty(napi_env env, napi_value object, const std::string &name, uint32_t value)
{
    napi_value tempValue = nullptr;
    napi_create_int32(env, value, &tempValue);
    napi_set_named_property(env, object, name.c_str(), tempValue);
}

static napi_value NapiCreateDirectionModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    SetEnumProperty(env, object, "DIRECTION_MODE_AUTO", static_cast<int32_t>(DIRECTION_MODE_AUTO));
    SetEnumProperty(env, object, "DIRECTION_MODE_PORTRAIT", static_cast<int32_t>(DIRECTION_MODE_PORTRAIT));
    SetEnumProperty(env, object, "DIRECTION_MODE_LANDSCAPE", static_cast<int32_t>(DIRECTION_MODE_LANDSCAPE));
    return object;
}

static napi_value NapiCreateColorModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    SetEnumProperty(env, object, "COLOR_MODE_MONOCHROME", static_cast<int32_t>(PRINT_COLOR_MODE_MONOCHROME));
    SetEnumProperty(env, object, "COLOR_MODE_COLOR", static_cast<int32_t>(PRINT_COLOR_MODE_COLOR));
    return object;
}

static napi_value NapiCreateDuplexModeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    SetEnumProperty(env, object, "DUPLEX_MODE_NONE", static_cast<int32_t>(DUPLEX_MODE_NONE));
    SetEnumProperty(env, object, "DUPLEX_MODE_LONG_EDGE", static_cast<int32_t>(DUPLEX_MODE_LONG_EDGE));
    SetEnumProperty(env, object, "DUPLEX_MODE_SHORT_EDGE", static_cast<int32_t>(DUPLEX_MODE_SHORT_EDGE));
    return object;
}

static napi_value NapiCreatePageTypeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
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
    napi_create_object(env, &object);
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
    napi_create_object(env, &object);
    SetEnumProperty(env, object, "PRINT_FILE_CREATED", static_cast<int32_t>(PRINT_FILE_CREATED_SUCCESS));
    SetEnumProperty(env, object, "PRINT_FILE_CREATION_FAILED", static_cast<int32_t>(PRINT_FILE_CREATED_FAIL));
    SetEnumProperty(env, object, "PRINT_FILE_CREATED_UNRENDERED",
        static_cast<int32_t>(PRINT_FILE_CREATED_SUCCESS_UNRENDERED));
    return object;
}

static napi_value NapiCreatePrinterStateEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
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
    napi_create_object(env, &object);
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
    napi_create_object(env, &object);
    SetEnumProperty(env, object, "PRINT_JOB_COMPLETED_SUCCESS", static_cast<int32_t>(PRINT_JOB_COMPLETED_SUCCESS));
    SetEnumProperty(env, object, "PRINT_JOB_COMPLETED_FAILED", static_cast<int32_t>(PRINT_JOB_COMPLETED_FAILED));
    SetEnumProperty(env, object, "PRINT_JOB_COMPLETED_CANCELLED", static_cast<int32_t>(PRINT_JOB_COMPLETED_CANCELLED));
    SetEnumProperty(env, object, "PRINT_JOB_COMPLETED_FILE_CORRUPTED",
        static_cast<int32_t>(PRINT_JOB_COMPLETED_FILE_CORRUPT));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_OFFLINE", static_cast<int32_t>(PRINT_JOB_BLOCKED_OFFLINE));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_BUSY", static_cast<int32_t>(PRINT_JOB_BLOCKED_BUSY));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_CANCELLED", static_cast<int32_t>(PRINT_JOB_BLOCKED_CANCELLED));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_OUT_OF_PAPER", static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_PAPER));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_OUT_OF_INK", static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_INK));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_OUT_OF_TONER", static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_TONER));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_JAMMED", static_cast<int32_t>(PRINT_JOB_BLOCKED_JAMMED));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_DOOR_OPEN", static_cast<int32_t>(PRINT_JOB_BLOCKED_DOOR_OPEN));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_SERVICE_REQUEST",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_SERVICE_REQUEST));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_LOW_ON_INK", static_cast<int32_t>(PRINT_JOB_BLOCKED_LOW_ON_INK));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_LOW_ON_TONER", static_cast<int32_t>(PRINT_JOB_BLOCKED_LOW_ON_TONER));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_REALLY_LOW_ON_INK",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_BAD_CERTIFICATE",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_BAD_CERTIFICATE));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_ACCOUNT_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_ACCOUNT_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_PRINT_PERMISSION_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_PRINT_COLOR_PERMISSION_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_NETWORK_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_NETWORK_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_SERVER_CONNECTION_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_LARGE_FILE_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_LARGE_FILE_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_FILE_PARSING_ERROR",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_FILE_PARSING_ERROR));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_SLOW_FILE_CONVERSION",
        static_cast<int32_t>(PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION));
    SetEnumProperty(env, object, "PRINT_JOB_RUNNING_UPLOADING_FILES",
        static_cast<int32_t>(PRINT_JOB_RUNNING_UPLOADING_FILES));
    SetEnumProperty(env, object, "PRINT_JOB_RUNNING_CONVERTING_FILES",
        static_cast<int32_t>(PRINT_JOB_RUNNING_CONVERTING_FILES));
    SetEnumProperty(env, object, "PRINT_JOB_BLOCK_UNKNOWN", static_cast<int32_t>(PRINT_JOB_BLOCKED_UNKNOWN));
    return object;
}

static napi_value NapiCreatePrintErrorCodeEnum(napi_env env)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
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
    return object;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        PRINT_NAPI_PROPERTY("PrintDirectionMode", NapiCreateDirectionModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintColorMode", NapiCreateColorModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintDuplexMode", NapiCreateDuplexModeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintPageType", NapiCreatePageTypeEnum(env)),
        PRINT_NAPI_PROPERTY("PrintDocumentAdapterState", NapiCreateDocumentAdapterStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintFileCreationState", NapiCreateFileCreationStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrinterState", NapiCreatePrinterStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintJobState", NapiCreatePrintJobStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintJobSubState", NapiCreatePrintJobSubStateEnum(env)),
        PRINT_NAPI_PROPERTY("PrintErrorCode", NapiCreatePrintErrorCodeEnum(env)),

        PRINT_NAPI_METHOD(FUNCTION_PRINT, NapiPrintTask::Print),
#ifdef PDFIUM_ENABLE
        PRINT_NAPI_METHOD(FUNCTION_CREATE_PDF_RENDER, NapiPrintPdfRender::CreatePdfRender),
#endif // PDFIUM_ENABLE
        PRINT_NAPI_METHOD(FUNCTION_QUERY_EXT, NapiInnerPrint::QueryExtensionInfo),
        PRINT_NAPI_METHOD(FUNCTION_START_DISCOVERY, NapiInnerPrint::StartDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_STOP_DISCOVERY, NapiInnerPrint::StopDiscovery),
        PRINT_NAPI_METHOD(FUNCTION_CONNECT_PRINT, NapiInnerPrint::ConnectPrinter),
        PRINT_NAPI_METHOD(FUNCTION_DISCONNECT_PRINT, NapiInnerPrint::DisconnectPrinter),
        PRINT_NAPI_METHOD(FUNCTION_START_PRINT, NapiInnerPrint::StartPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_CANCEL_PRINT, NapiInnerPrint::CancelPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_REQUEST_PREVIEW, NapiInnerPrint::RequestPreview),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_CAPABILITY, NapiInnerPrint::QueryCapability),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_ALL_PRINTJOB, NapiInnerPrint::QueryAllPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTJOB_LIST, NapiInnerPrint::QueryAllPrintJob),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_PRINTJOB_BYID, NapiInnerPrint::QueryPrintJobById),
        PRINT_NAPI_METHOD(FUNCTION_REGISTER_EVENT, NapiInnerPrint::On),
        PRINT_NAPI_METHOD(FUNCTION_UNREGISTER_EVENT, NapiInnerPrint::Off),
        PRINT_NAPI_METHOD(FUNCTION_ADD_PRINTER, NapiPrintExt::AddPrinters),
        PRINT_NAPI_METHOD(FUNCTION_REMOVE_PRINTER, NapiPrintExt::RemovePrinters),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER, NapiPrintExt::UpdatePrinters),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_STATE, NapiPrintExt::UpdatePrinterState),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_JOB_STATE, NapiPrintExt::UpdatePrintJobState),
        PRINT_NAPI_METHOD(FUNCTION_UPDATE_EXTENSION_INFO, NapiPrintExt::UpdateExtensionInfo),
        PRINT_NAPI_METHOD(FUNCTION_NATIVE_ADD_PRINTER_TO_CUPS, NapiPrintExt::AddPrinterToCups),
        PRINT_NAPI_METHOD(FUNCTION_QUERY_CAPABILITY_BY_URI, NapiPrintExt::QueryPrinterCapabilityByUri),
        PRINT_NAPI_METHOD(FUNCTION_START_GET_PRINT_FILE, NapiInnerPrint::StartGetPrintFile),
        PRINT_NAPI_METHOD(FUNCTION_NOTIFY_PRINT_SERVICE, NapiInnerPrint::NotifyPrintService),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    PRINT_HILOGD("init print module %{public}d", status);
    return exports;
}

static __attribute__((constructor)) void RegisterModule()
{
    static napi_module module = { .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = Init,
        .nm_modname = "print",
        .nm_priv = ((void *)0),
        .reserved = { 0 } };
    napi_module_register(&module);
    PRINT_HILOGD("module register print");
}
