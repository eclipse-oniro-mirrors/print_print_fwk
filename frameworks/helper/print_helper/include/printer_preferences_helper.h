/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PRINTER_PREFERENCES_HELPER_H
#define PRINTER_PREFERENCES_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "printer_preferences.h"

namespace OHOS::Print {
class PrinterPreferencesHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrinterPreferences &preferences);
    static std::shared_ptr<PrinterPreferences> BuildFromJs(napi_env env, napi_value jsValue);

private:
    static bool ValidateProperty(napi_env env, napi_value object);
    static void BuildFromBoolOptionJs(napi_env env, napi_value jsValue,
        std::shared_ptr<PrinterPreferences> nativeObj);
};
}  // namespace OHOS::Print
#endif  // PRINTER_PREFERENCES_HELPER_H
