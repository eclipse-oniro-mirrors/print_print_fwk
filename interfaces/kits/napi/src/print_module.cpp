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
static constexpr const char *FUNCTION_QUERY_EXT = "queryExtensionAbilityInfos";
static constexpr const char *FUNCTION_START_DISCOVERY = "startDiscoverPrinter";
static constexpr const char *FUNCTION_STOP_DISCOVERY = "stopDiscoverPrinter";
static constexpr const char *FUNCTION_CONNECT_PRINT = "connectPrinter";
static constexpr const char *FUNCTION_DISCONNECT_PRINT = "disconnectPrinter";
static constexpr const char *FUNCTION_START_PRINT = "startPrintJob";
static constexpr const char *FUNCTION_CANCEL_PRINT = "cancelPrintJob";
static constexpr const char *FUNCTION_REQUEST_PREVIEW = "requestPrintPreview";
static constexpr const char *FUNCTION_QUERY_CAPABILITY = "queryPrinterCapability";
static constexpr const char *FUNCTION_REGISTER_EVENT = "on";
static constexpr const char *FUNCTION_UNREGISTER_EVENT = "off";
static constexpr const char *FUNCTION_ADD_PRINTER = "addPrinters";
static constexpr const char *FUNCTION_REMOVE_PRINTER = "removePrinters";
static constexpr const char *FUNCTION_UPDATE_PRINTER_STATE = "updatePrinterState";
static constexpr const char *FUNCTION_UPDATE_JOB_STATE = "updatePrintJobState";

#define DECLARE_NAPI_METHOD(name, func)         \
    {                                           \
        name, 0, func, 0, 0, 0, napi_default, 0 \
    }

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_METHOD(FUNCTION_PRINT, NapiPrintTask::Print),
        DECLARE_NAPI_METHOD(FUNCTION_QUERY_EXT, NapiInnerPrint::QueryExtensionInfo),
        DECLARE_NAPI_METHOD(FUNCTION_START_DISCOVERY, NapiInnerPrint::StartDiscovery),
        DECLARE_NAPI_METHOD(FUNCTION_STOP_DISCOVERY, NapiInnerPrint::StopDiscovery),
        DECLARE_NAPI_METHOD(FUNCTION_CONNECT_PRINT, NapiInnerPrint::ConnectPrint),
        DECLARE_NAPI_METHOD(FUNCTION_DISCONNECT_PRINT, NapiInnerPrint::DisconnectPrint),
        DECLARE_NAPI_METHOD(FUNCTION_START_PRINT, NapiInnerPrint::StartPrintJob),
        DECLARE_NAPI_METHOD(FUNCTION_CANCEL_PRINT, NapiInnerPrint::CancelPrintJob),
        DECLARE_NAPI_METHOD(FUNCTION_REQUEST_PREVIEW, NapiInnerPrint::RequestPreview),
        DECLARE_NAPI_METHOD(FUNCTION_QUERY_CAPABILITY, NapiInnerPrint::QueryCapability),
        DECLARE_NAPI_METHOD(FUNCTION_REGISTER_EVENT, NapiInnerPrint::On),
        DECLARE_NAPI_METHOD(FUNCTION_UNREGISTER_EVENT, NapiInnerPrint::Off),
        DECLARE_NAPI_METHOD(FUNCTION_ADD_PRINTER, NapiPrintExt::AddPrinters),
        DECLARE_NAPI_METHOD(FUNCTION_REMOVE_PRINTER, NapiPrintExt::RemovePrinters),
        DECLARE_NAPI_METHOD(FUNCTION_UPDATE_PRINTER_STATE, NapiPrintExt::UpdatePrinterState),
        DECLARE_NAPI_METHOD(FUNCTION_UPDATE_JOB_STATE, NapiPrintExt::UpdatePrintJobState),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    PRINT_HILOGD("init upload %{public}d", status);
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
