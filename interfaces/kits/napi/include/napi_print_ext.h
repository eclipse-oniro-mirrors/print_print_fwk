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

#include "async_call.h"
#include "napi/native_api.h"
#include "print_task.h"
#include "print_info.h"
#include "noncopyable.h"

namespace OHOS::Print {
class NapiPrintExt {
public:
    static napi_value AddPrinters(napi_env env, napi_callback_info info);
    static napi_value RemovePrinters(napi_env env, napi_callback_info info);
    static napi_value UpdatePrinterState(napi_env env, napi_callback_info info);
    static napi_value UpdatePrintJobState(napi_env env, napi_callback_info info);
    static bool ParseInfo(napi_env env, napi_value InfoValue, PrintInfo &Info);
    static bool ParseInfoParam(napi_env env, napi_value InfoValue, PrintInfo &info);
    static bool ParseCapability(napi_env env, napi_value InfoValue, PrinterCapability &capability);
private:
    struct NapiPrintExtContext : public AsyncCall::Context {
        PrintTask *task_ = nullptr;
        PrintInfo info_;
        std::vector<PrintInfo> arrayPrintInfo;
        bool result = false;
        uint32_t printerId = 0;
        uint32_t printerJobId = 0;
        uint32_t printerState = 0;
        uint32_t printerJobState = 0;
        napi_status status = napi_generic_failure;
        std::vector<PrintInfo> printInfoVector;
        NapiPrintExtContext() : Context(nullptr, nullptr) {};
        NapiPrintExtContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)) {};
        virtual ~NapiPrintExtContext() {};
    };
};
} // namespace OHOS::Print
#endif // NAPI_PRINT_EXT_H