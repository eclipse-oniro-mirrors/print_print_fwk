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
#include "scan_log.h"

using namespace OHOS::Scan;

static constexpr const char *FUNCTION_INIT_SCAN = "initScan";
static constexpr const char *FUNCTION_EXIT_SCAN = "exitScan";
static constexpr const char *FUNCTION_GET_SCANNER_LIST = "getScannerList";
static constexpr const char *FUNCTION_STOP_DISCOVER = "stopDiscover";
static constexpr const char *FUNCTION_OPEN_SCANNER = "openScanner";
static constexpr const char *FUNCTION_CLOSE_SCANNER = "closeScanner";
static constexpr const char *FUNCTION_GET_SCAN_OPTION_DESC = "getScanOptionDesc";
static constexpr const char *FUNCTION_SET_SCAN_OPTION = "setScanOption";
static constexpr const char *FUNCTION_SET_SCAN_AUTO_OPTION = "setScanAutoOption";
static constexpr const char *FUNCTION_GET_SCAN_OPTION = "getScanOption";
static constexpr const char *FUNCTION_GET_SCAN_PARAMETERS = "getScanParameters";
static constexpr const char *FUNCTION_START_SCAN = "startScan";
static constexpr const char *FUNCTION_GET_SINGLE_FRAME_FD = "getSingleFrameFD";
static constexpr const char *FUNCTION_CANCEL_SCAN = "cancelScan";
static constexpr const char *FUNCTION_SET_SCAN_IO_MODE = "setScanIOMode";
static constexpr const char *FUNCTION_GET_SCAN_SELECT_FD = "getScanSelectFd";
static constexpr const char *FUNCTION_GET_SCANNER_STATE = "getScannerState";
static constexpr const char *FUNCTION_GET_SCAN_PROGRESS = "getScanProgress";
static constexpr const char *FUNCTION_ADD_SCANNER = "addScanner";
static constexpr const char *FUNCTION_DELETE_SCANNER = "deleteScanner";
static constexpr const char *FUNCTION_GET_ADDED_SCANNER = "getAddedScanner";
static constexpr const char *FUNCTION_UPDATE_SCANNER_NAME = "updateScannerName";

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


static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        SCAN_NAPI_METHOD(FUNCTION_INIT_SCAN, NapiInnerScan::InitScan),
        SCAN_NAPI_METHOD(FUNCTION_EXIT_SCAN, NapiInnerScan::ExitScan),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCANNER_LIST, NapiInnerScan::GetScannerList),
        SCAN_NAPI_METHOD(FUNCTION_STOP_DISCOVER, NapiInnerScan::StopDiscover),
        SCAN_NAPI_METHOD(FUNCTION_OPEN_SCANNER, NapiInnerScan::OpenScanner),
        SCAN_NAPI_METHOD(FUNCTION_CLOSE_SCANNER, NapiInnerScan::CloseScanner),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_OPTION_DESC, NapiInnerScan::GetScanOptionDesc),
        SCAN_NAPI_METHOD(FUNCTION_SET_SCAN_OPTION, NapiInnerScan::SetScanOption),
        SCAN_NAPI_METHOD(FUNCTION_SET_SCAN_AUTO_OPTION, NapiInnerScan::SetScanAutoOption),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_OPTION, NapiInnerScan::GetScanOption),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_PARAMETERS, NapiInnerScan::GetScanParameters),
        SCAN_NAPI_METHOD(FUNCTION_START_SCAN, NapiInnerScan::StartScan),
        SCAN_NAPI_METHOD(FUNCTION_GET_SINGLE_FRAME_FD, NapiInnerScan::GetSingleFrameFD),
        SCAN_NAPI_METHOD(FUNCTION_CANCEL_SCAN, NapiInnerScan::CancelScan),
        SCAN_NAPI_METHOD(FUNCTION_SET_SCAN_IO_MODE, NapiInnerScan::SetScanIOMode),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_SELECT_FD, NapiInnerScan::GetScanSelectFd),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCANNER_STATE, NapiInnerScan::GetScannerState),
        SCAN_NAPI_METHOD(FUNCTION_GET_SCAN_PROGRESS, NapiInnerScan::GetScanProgress),
        SCAN_NAPI_METHOD(FUNCTION_ADD_SCANNER, NapiInnerScan::AddScanner),
        SCAN_NAPI_METHOD(FUNCTION_DELETE_SCANNER, NapiInnerScan::DeleteScanner),
        SCAN_NAPI_METHOD(FUNCTION_GET_ADDED_SCANNER, NapiInnerScan::GetAddedScanner),
        SCAN_NAPI_METHOD(FUNCTION_UPDATE_SCANNER_NAME, NapiInnerScan::UpdateScannerName),

        SCAN_NAPI_METHOD(FUNCTION_REGISTER_EVENT, NapiInnerScan::On),
        SCAN_NAPI_METHOD(FUNCTION_UNREGISTER_EVENT, NapiInnerScan::Off),
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
