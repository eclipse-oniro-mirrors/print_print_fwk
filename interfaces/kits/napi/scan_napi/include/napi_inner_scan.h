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

#ifndef NAPI_INNER_SCAN_H
#define NAPI_INNER_SCAN_H
#define TDD_ENABLE 1

#include <string>
#include <vector>

#include "napi/native_api.h"
#include "scan_async_call.h"
#include "iscan_callback.h"
#include "scan_callback.h"
#include "scan_constant.h"
#include "scan_option_descriptor.h"
#include "scan_option_descriptor_helper.h"
#include "scan_option_value.h"
#include "scan_option_value_helper.h"
#include "scan_parameters.h"
#include "scan_parameters_helper.h"
#include "scanner_info.h"
#include "scanner_info_helper.h"
#include "scan_progress.h"
#include "scan_progress_helper.h"


namespace OHOS::Scan {

class NapiInnerScan {
public:
    static napi_value InitScan(napi_env env, napi_callback_info info);
    static napi_value ExitScan(napi_env env, napi_callback_info info);
    static napi_value GetScannerList(napi_env env, napi_callback_info info);
    static napi_value StopDiscover(napi_env env, napi_callback_info info);
    static napi_value OpenScanner(napi_env env, napi_callback_info info);
    static napi_value CloseScanner(napi_env env, napi_callback_info info);
    static napi_value GetScanOptionDesc(napi_env env, napi_callback_info info);
    static napi_value SetScanOption(napi_env env, napi_callback_info info);
    static napi_value SetScanAutoOption(napi_env env, napi_callback_info info);
    static napi_value GetScanOption(napi_env env, napi_callback_info info);
    static napi_value GetScanParameters(napi_env env, napi_callback_info info);
    static napi_value StartScan(napi_env env, napi_callback_info info);
    static napi_value GetSingleFrameFD(napi_env env, napi_callback_info info);
    static napi_value CancelScan(napi_env env, napi_callback_info info);
    static napi_value SetScanIOMode(napi_env env, napi_callback_info info);
    static napi_value GetScanSelectFd(napi_env env, napi_callback_info info);
    static napi_value GetScannerState(napi_env env, napi_callback_info info);
    static napi_value GetScanProgress(napi_env env, napi_callback_info info);
    static napi_value AddScanner(napi_env env, napi_callback_info info);
    static napi_value DeleteScanner(napi_env env, napi_callback_info info);
    static napi_value GetAddedScanner(napi_env env, napi_callback_info info);
    static napi_value UpdateScannerName(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

private:
    static bool IsSupportType(const std::string& type);

private:
    struct NapiScanContext : public ScanAsyncCall::Context {
        bool result = false;
        std::string exeCMD = "";
        std::string exePath = "";

        int32_t scanVersion = 0;
        int32_t fd = 0;
        int32_t optionIndex = 0;
        std::string scannerId = "";
        std::string serialNumber = "";
        std::string discoverMode = "";
        std::string deviceName = "";
        std::vector<ScanDeviceInfo> allAddedScanner;

        bool isNonBlocking = false;
        ScanOptionDescriptor desc;
        ScanOptionValue optionValue;
        int32_t info = 0;
        ScanParameters para;
        ScanProgress prog;
        int32_t scannerState = 0;

        uint32_t frameSize = 0;
        uint32_t image_fd = 0;
        uint8_t *data = nullptr;
        bool batchMode = 0;

        NapiScanContext() : Context(nullptr, nullptr) {};
        NapiScanContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)) {};
        virtual ~NapiScanContext() {};
    };
};
} // namespace OHOS::Scan
#endif // NAPI_INNER_SCAN_H
