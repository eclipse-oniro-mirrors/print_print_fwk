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

#ifndef PRINTER_INFO_HELPER_H
#define PRINTER_INFO_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "printer_info.h"

namespace OHOS::Print {
class PrinterInfoHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrinterInfo &info);
    static std::shared_ptr<PrinterInfo> BuildFromJs(napi_env env, napi_value jsValue);

private:
    static bool ValidateProperty(napi_env env, napi_value object);
};
}  // namespace OHOS::Print
#endif  // PRINTER_INFO_H
