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

#ifndef ANI_PRINTER_PREFERENCES_HELPER_H
#define ANI_PRINTER_PREFERENCES_HELPER_H

#include <map>
#include <ani.h>
#include "printer_preferences.h"

namespace OHOS::Print {
class PrinterPreferencesAniHelper {
public:
    static PrinterPreferences ParsePreferences(ani_env *env, ani_ref preferences);
    static ani_object CreatePrinterPreferences(ani_env *env, const PrinterPreferences &preferences);

private:
    static bool ValidateProperty(ani_env *env, ani_ref preferences);
};
}  // namespace OHOS::Print
#endif  // PRINTER_PREFERENCES_ANI_HELPER_H
