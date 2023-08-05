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
#include "print_constant.h"
#include "print_log.h"

using namespace OHOS::Print;

static constexpr const char *FUNCTION_PRINT = "print";
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

static constexpr const char *PROPERTY_PRINTER_ADD = "PRINTER_ADDED";
static constexpr const char *PROPERTY_PRINTER_REMOVE = "PRINTER_REMOVED";
static constexpr const char *PROPERTY_PRINTER_UPDATE_CAP = "PRINTER_UPDATE_CAP";
static constexpr const char *PROPERTY_PRINTER_CONNECTED = "PRINTER_CONNECTED";
static constexpr const char *PROPERTY_PRINTER_DISCONNECTED = "PRINTER_DISCONNECTED";
static constexpr const char *PROPERTY_PRINTER_RUNNING = "PRINTER_RUNNING";

static constexpr const char *PROPERTY_PRINT_JOB_PREPARE = "PRINT_JOB_PREPARE";
static constexpr const char *PROPERTY_PRINT_JOB_QUEUED = "PRINT_JOB_QUEUED";
static constexpr const char *PROPERTY_PRINT_JOB_RUNNING = "PRINT_JOB_RUNNING";
static constexpr const char *PROPERTY_PRINT_JOB_BLOCKED = "PRINT_JOB_BLOCKED";
static constexpr const char *PROPERTY_PRINT_JOB_COMPLETED = "PRINT_JOB_COMPLETED";

static constexpr const char *PROPERTY_COMPLETED_SUCCESS = "PRINT_JOB_COMPLETED_SUCCESS";
static constexpr const char *PROPERTY_COMPLETED_FAILED = "PRINT_JOB_COMPLETED_FAILED";
static constexpr const char *PROPERTY_COMPLETED_CANCELLED = "PRINT_JOB_COMPLETED_CANCELLED";
static constexpr const char *PROPERTY_COMPLETED_FILE_CORRUPT = "PRINT_JOB_COMPLETED_FILE_CORRUPT";
static constexpr const char *PROPERTY_BLOCK_OFFLINE = "PRINT_JOB_BLOCK_OFFLINE";
static constexpr const char *PROPERTY_BLOCK_BUSY = "PRINT_JOB_BLOCK_BUSY";
static constexpr const char *PROPERTY_BLOCK_CANCELLED = "PRINT_JOB_BLOCK_CANCELLED";
static constexpr const char *PROPERTY_BLOCK_OUT_OF_PAPER = "PRINT_JOB_BLOCK_OUT_OF_PAPER";
static constexpr const char *PROPERTY_BLOCK_OUT_OF_INK = "PRINT_JOB_BLOCK_OUT_OF_INK";
static constexpr const char *PROPERTY_BLOCK_OUT_OF_TONER = "PRINT_JOB_BLOCK_OUT_OF_TONER";
static constexpr const char *PROPERTY_BLOCK_JAMMED = "PRINT_JOB_BLOCK_JAMMED";
static constexpr const char *PROPERTY_BLOCK_DOOR_OPEN = "PRINT_JOB_BLOCK_DOOR_OPEN";
static constexpr const char *PROPERTY_BLOCK_SERVICE_REQUEST = "PRINT_JOB_BLOCK_SERVICE_REQUEST";
static constexpr const char *PROPERTY_BLOCK_LOW_ON_INK = "PRINT_JOB_BLOCK_LOW_ON_INK";
static constexpr const char *PROPERTY_BLOCK_LOW_ON_TONER = "PRINT_JOB_BLOCK_LOW_ON_TONER";
static constexpr const char *PROPERTY_BLOCK_REALLY_LOW_ON_INK = "PRINT_JOB_BLOCK_REALLY_LOW_ON_INK";
static constexpr const char *PROPERTY_BLOCK_BAD_CERTIFICATE = "PRINT_JOB_BLOCK_BAD_CERTIFICATE";
static constexpr const char *PROPERTY_BLOCK_ACCOUNT_ERROR = "PRINT_BLOCK_ACCOUNT_ERROR";
static constexpr const char *PROPERTY_BLOCK_PRINT_PERMISSION_ERROR = "PRINT_JOB_BLOCK_PRINT_PERMISSION_ERROR";
static constexpr const char *PROPERTY_BLOCK_PRINT_COLOR_PERMISSION_ERROR = "PRINT_JOB_BLOCK_PRINT_COLOR_PERMISSION_ERROR";
static constexpr const char *PROPERTY_BLOCK_NETWORK_ERROR = "PRINT_JOB_BLOCK_NETWORK_ERROR";
static constexpr const char *PROPERTY_BLOCK_CONNECT_SERVER_ERROR = "PRINT_JOB_BLOCK_CONNECT_SERVER_ERROR";
static constexpr const char *PROPERTY_BLOCK_LARGE_FILE_ERROR = "PRINT_JOB_BLOCK_LARGE_FILE_ERROR";
static constexpr const char *PROPERTY_BLOCK_PARSE_FILE_ERROR = "PRINT_JOB_BLOCK_PARSE_FILE_ERROR";
static constexpr const char *PROPERTY_BLOCK_FILE_CONVERT_SLOWLY = "PRINT_JOB_BLOCK_FILE_CONVERT_SLOWLY";
static constexpr const char *PROPERTY_RUNNING_UPLOADING_FILES = "PRINT_JOB_RUNNING_UPLOADING_FILES";
static constexpr const char *PROPERTY_RUNNING_CONVERTING_FILES = "PRINT_JOB_RUNNING_CONVERTING_FILES";
static constexpr const char *PROPERTY_BLOCK_UNKNOWN = "PRINT_JOB_BLOCK_UNKNOWN";

static constexpr const char *PROPERTY_ERR_NONE = "E_PRINT_NONE";
static constexpr const char *PROPERTY_ERR_NO_PERMISSION = "E_PRINT_NO_PERMISSION";
static constexpr const char *PROPERTY_ERR_INVALID_PARAMETER = "E_PRINT_INVALID_PARAMETER";
static constexpr const char *PROPERTY_ERR_GENERIC_FAILURE = "E_PRINT_GENERIC_FAILURE";
static constexpr const char *PROPERTY_ERR_RPC_FAILURE = "E_PRINT_RPC_FAILURE";
static constexpr const char *PROPERTY_ERR_SERVER_FAILURE = "E_PRINT_SERVER_FAILURE";
static constexpr const char *PROPERTY_ERR_INVALID_EXTENSION = "E_PRINT_INVALID_EXTENSION";
static constexpr const char *PROPERTY_ERR_INVALID_PRINTER = "E_PRINT_INVALID_PRINTER";
static constexpr const char *PROPERTY_ERR_INVALID_PRINTJOB = "E_PRINT_INVALID_PRINTJOB";
static constexpr const char *PROPERTY_ERR_FILE_IO = "E_PRINT_FILE_IO";

static napi_value printer_add = nullptr;
static napi_value printer_removed = nullptr;
static napi_value printer_updatecap = nullptr;
static napi_value printer_connected = nullptr;
static napi_value printer_disconnected = nullptr;
static napi_value printer_running = nullptr;

static napi_value print_job_prepare = nullptr;
static napi_value print_job_queued = nullptr;
static napi_value print_job_running = nullptr;
static napi_value print_job_blocked = nullptr;
static napi_value print_job_completed = nullptr;

static napi_value completed_success = nullptr;
static napi_value completed_failed = nullptr;
static napi_value completed_cancelled = nullptr;
static napi_value completed_file_corrupt = nullptr;
static napi_value block_offline = nullptr;
static napi_value block_busy = nullptr;
static napi_value block_cancelled = nullptr;
static napi_value block_out_of_paper = nullptr;
static napi_value block_out_of_ink = nullptr;
static napi_value block_out_of_toner = nullptr;
static napi_value block_jammed = nullptr;
static napi_value block_door_open = nullptr;
static napi_value block_service_request = nullptr;
static napi_value block_low_on_ink = nullptr;
static napi_value block_low_on_toner = nullptr;
static napi_value block_really_low_on_ink = nullptr;
static napi_value block_bad_certificate = nullptr;
static napi_value block_account_error = nullptr;
static napi_value block_print_permission_error = nullptr;
static napi_value block_print_color_permission_error = nullptr;
static napi_value block_network_error = nullptr;
static napi_value block_connect_server_error = nullptr;
static napi_value block_large_file_error = nullptr;
static napi_value block_parse_file_error = nullptr;
static napi_value block_file_convert_slowly = nullptr;
static napi_value running_uploading_files = nullptr;
static napi_value running_converting_files = nullptr;
static napi_value block_unknown = nullptr;

static napi_value err_none = nullptr;
static napi_value err_no_permission = nullptr;
static napi_value err_invalid_parameter = nullptr;
static napi_value err_generic_failure = nullptr;
static napi_value err_rpc_failure = nullptr;
static napi_value err_server_failure = nullptr;
static napi_value err_invalid_extension = nullptr;
static napi_value err_invalid_printer = nullptr;
static napi_value err_invalid_printjob = nullptr;
static napi_value err_file_io = nullptr;

#define PRINT_NAPI_METHOD(name, func)           \
    {                                           \
        name, 0, func, 0, 0, 0, napi_default, 0 \
    }

#define PRINT_NAPI_PROPERTY(name, val)                                          \
    {                                                                           \
        (name), nullptr, nullptr, nullptr, nullptr, val, napi_static, nullptr   \
    }

static void NapiCreateEnum(napi_env env)
{
    // create printer state enum
    napi_create_int32(env, static_cast<int32_t>(PRINTER_ADDED), &printer_add);
    napi_create_int32(env, static_cast<int32_t>(PRINTER_REMOVED), &printer_removed);
    napi_create_int32(env, static_cast<int32_t>(PRINTER_UPDATE_CAP), &printer_updatecap);
    napi_create_int32(env, static_cast<int32_t>(PRINTER_CONNECTED), &printer_connected);
    napi_create_int32(env, static_cast<int32_t>(PRINTER_DISCONNECTED), &printer_disconnected);
    napi_create_int32(env, static_cast<int32_t>(PRINTER_RUNNING), &printer_running);

    // create print job state enum
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_PREPARED), &print_job_prepare);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_QUEUED), &print_job_queued);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_RUNNING), &print_job_running);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED), &print_job_blocked);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_COMPLETED), &print_job_completed);

    // create print job sub-state enum
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_COMPLETED_SUCCESS), &completed_success);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_COMPLETED_FAILED), &completed_failed);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_COMPLETED_CANCELLED), &completed_cancelled);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_COMPLETED_FILE_CORRUPT), &completed_file_corrupt);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_OFFLINE), &block_offline);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_BUSY), &block_busy);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_CANCELLED), &block_cancelled);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_PAPER), &block_out_of_paper);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_INK), &block_out_of_ink);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_OUT_OF_TONER), &block_out_of_toner);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_JAMMED), &block_jammed);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_DOOR_OPEN), &block_door_open);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_SERVICE_REQUEST), &block_service_request);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_LOW_ON_INK), &block_low_on_ink);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_LOW_ON_TONER), &block_low_on_toner);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK), &block_really_low_on_ink);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_BAD_CERTIFICATE), &block_bad_certificate);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_ACCOUNT_ERROR), &block_account_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR), &block_print_permission_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR), &block_print_color_permission_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_NETWORK_ERROR), &block_network_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_CONNECT_SERVER_ERROR), &block_connect_server_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_LARGE_FILE_ERROR), &block_large_file_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_PARSE_FILE_ERROR), &block_parse_file_error);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_FILE_CONVERT_SLOWLY), &block_file_convert_slowly);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_RUNNING_UPLOADING_FILES), &running_uploading_files);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_RUNNING_CONVERTING_FILES), &running_converting_files);
    napi_create_int32(env, static_cast<int32_t>(PRINT_JOB_BLOCKED_UNKNOWN), &block_unknown);

    // create error code of js api
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_NONE), &err_none);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_NO_PERMISSION), &err_no_permission);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_INVALID_PARAMETER), &err_invalid_parameter);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_GENERIC_FAILURE), &err_generic_failure);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_RPC_FAILURE), &err_rpc_failure);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_SERVER_FAILURE), &err_server_failure);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_INVALID_EXTENSION), &err_invalid_extension);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_INVALID_PRINTER), &err_invalid_printer);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_INVALID_PRINTJOB), &err_invalid_printjob);
    napi_create_int32(env, static_cast<int32_t>(E_PRINT_FILE_IO), &err_file_io);
}

static napi_value Init(napi_env env, napi_value exports)
{
    NapiCreateEnum(env);
    napi_property_descriptor desc[] = {
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_ADD, printer_add),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_REMOVE, printer_removed),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_UPDATE_CAP, printer_updatecap),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_CONNECTED, printer_connected),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_DISCONNECTED, printer_disconnected),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINTER_RUNNING, printer_running),

        PRINT_NAPI_PROPERTY(PROPERTY_PRINT_JOB_PREPARE, print_job_prepare),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINT_JOB_QUEUED, print_job_queued),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINT_JOB_RUNNING, print_job_running),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINT_JOB_BLOCKED, print_job_blocked),
        PRINT_NAPI_PROPERTY(PROPERTY_PRINT_JOB_COMPLETED, print_job_completed),

        PRINT_NAPI_PROPERTY(PROPERTY_COMPLETED_SUCCESS, completed_success),
        PRINT_NAPI_PROPERTY(PROPERTY_COMPLETED_FAILED, completed_failed),
        PRINT_NAPI_PROPERTY(PROPERTY_COMPLETED_CANCELLED, completed_cancelled),
        PRINT_NAPI_PROPERTY(PROPERTY_COMPLETED_FILE_CORRUPT, completed_file_corrupt),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_OFFLINE, block_offline),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_BUSY, block_busy),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_CANCELLED, block_cancelled),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_OUT_OF_PAPER, block_out_of_paper),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_OUT_OF_INK, block_out_of_ink),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_OUT_OF_TONER, block_out_of_toner),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_JAMMED, block_jammed),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_DOOR_OPEN, block_door_open),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_SERVICE_REQUEST, block_service_request),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_LOW_ON_INK, block_low_on_ink),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_LOW_ON_TONER, block_low_on_toner),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_REALLY_LOW_ON_INK, block_really_low_on_ink),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_BAD_CERTIFICATE, block_bad_certificate),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_ACCOUNT_ERROR, block_account_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_PRINT_PERMISSION_ERROR, block_print_permission_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_PRINT_COLOR_PERMISSION_ERROR, block_print_color_permission_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_NETWORK_ERROR, block_network_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_CONNECT_SERVER_ERROR, block_connect_server_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_LARGE_FILE_ERROR, block_large_file_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_PARSE_FILE_ERROR, block_parse_file_error),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_FILE_CONVERT_SLOWLY, block_file_convert_slowly),
        PRINT_NAPI_PROPERTY(PROPERTY_RUNNING_UPLOADING_FILES, running_uploading_files),
        PRINT_NAPI_PROPERTY(PROPERTY_RUNNING_CONVERTING_FILES, running_converting_files),
        PRINT_NAPI_PROPERTY(PROPERTY_BLOCK_UNKNOWN, block_unknown),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_NONE, err_none),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_NO_PERMISSION, err_no_permission),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_INVALID_PARAMETER, err_invalid_parameter),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_GENERIC_FAILURE, err_generic_failure),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_RPC_FAILURE, err_rpc_failure),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_SERVER_FAILURE, err_server_failure),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_INVALID_EXTENSION, err_invalid_extension),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_INVALID_PRINTER, err_invalid_printer),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_INVALID_PRINTJOB, err_invalid_printjob),
        PRINT_NAPI_PROPERTY(PROPERTY_ERR_FILE_IO, err_file_io),
        PRINT_NAPI_METHOD(FUNCTION_PRINT, NapiPrintTask::Print),
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
