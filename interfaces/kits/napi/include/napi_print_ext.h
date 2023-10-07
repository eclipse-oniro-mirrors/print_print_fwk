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

#ifndef NAPI_PRINT_EXT_H
#define NAPI_PRINT_EXT_H

#include "napi/native_api.h"
#include "noncopyable.h"
#include "print_async_call.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_resolution.h"
#include "print_task.h"
#include "printer_capability.h"
#include "printer_info.h"

namespace OHOS::Print {
class NapiPrintExt {
public:
    static napi_value AddPrinters(napi_env env, napi_callback_info info);
    static napi_value RemovePrinters(napi_env env, napi_callback_info info);
    static napi_value UpdatePrinters(napi_env env, napi_callback_info info);
    static napi_value UpdatePrinterState(napi_env env, napi_callback_info info);
    static napi_value UpdatePrintJobState(napi_env env, napi_callback_info info);
    static napi_value UpdateExtensionInfo(napi_env env, napi_callback_info info);
    static napi_value AddPrinterToCups(napi_env env, napi_callback_info info);
    static napi_value QueryPrinterCapabilityByUri(napi_env env, napi_callback_info info);

private:
    static bool IsValidPrinterState(uint32_t state);
    static bool IsValidPrintJobState(uint32_t state);
    static bool IsValidPrintJobSubState(uint32_t subState);

private:
    struct NapiPrintExtContext : public PrintAsyncCall::Context {
        bool result = true;
        std::vector<PrinterInfo> printerInfos;
        std::vector<std::string> printerIds;

        std::string printerId = "";
        uint32_t printerState = 0;

        std::string printJobId = "";
        uint32_t printJobState = 0;
        uint32_t jobSubState = 0;

        std::string extensionId = "";
        std::string extInfo = "";

        std::string printerUri = "";
        std::string printerName = "";
        std::string printerMake = "";
        PrinterCapability printerCaps;

        NapiPrintExtContext() : Context(nullptr, nullptr) {};
        NapiPrintExtContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)) {};
        virtual ~NapiPrintExtContext() {};
    };
};
}  // namespace OHOS::Print
#endif  // NAPI_PRINT_EXT_H
