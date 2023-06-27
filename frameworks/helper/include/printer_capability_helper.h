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
#ifndef PRINTER_CAPABILITY_HELPER_H
#define PRINTER_CAPABILITY_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "printer_capability.h"

namespace OHOS::Print {
class PrinterCapabilityHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrinterCapability &cap);
    static std::shared_ptr<PrinterCapability> BuildFromJs(napi_env env, napi_value jsValue);
    static std::shared_ptr<PrinterCapability> BuildFromJsSecond(napi_env env, napi_value jsValue,
        napi_value jsPageSizes, std::shared_ptr<PrinterCapability> nativeObj);

private:
    static bool CreatePageSizeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateResolutionList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool ValidateProperty(napi_env env, napi_value object);
};
}  // namespace OHOS::Print
#endif  // PRINTER_CAPABILITY_HELPER_H
