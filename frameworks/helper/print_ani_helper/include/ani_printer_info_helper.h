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
#ifndef OHOS_PRINTER_INFO_HELPER_H
#define OHOS_PRINTER_INFO_HELPER_H

#include <ani.h>
#include <string>
#include "printer_info.h"
namespace OHOS::Print {
class PrinterInfoAniHelper {
public:
    static PrinterInfo ParsePrinterInfo(ani_env *env, ani_ref printerInfo);
    static PrinterInfo ParsePrinterInformation(ani_env *env, ani_object printerInformation);
    static ani_object CreatePrinterInfo(ani_env *env, const PrinterInfo &info);
    static ani_object CreatePrinterInformation(ani_env *env, const PrinterInfo &info);
    static bool GetPrinterInfoArray(ani_env *env, ani_object param, std::vector<PrinterInfo> &res);

private:
    static bool ValidateProperty(ani_env *env, ani_ref printerInfo);
    static void ParsePrinterInfoStringField(ani_env *env, ani_ref printerInfoAni, PrinterInfo& printerInfo);
};
} // namespace OHOS::Print
#endif  // OHOS_PRINTER_INFO_HELPER_H