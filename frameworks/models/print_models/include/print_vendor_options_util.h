/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PRINT_VENDOR_OPTIONS_UTIL_H
#define PRINT_VENDOR_OPTIONS_UTIL_H

#include <string>
#include "json/json.h"

namespace OHOS::Print {

class PrintVendorOptionsUtil {
public:
    static void SplitVendorOptions(const std::string &vendorOptions,
                                   std::string &printerVendorOptions,
                                   std::string &userVendorOptions);

    static std::string MergeVendorOptions(const std::string &defaultVendorOptions,
                                          const std::string &overrideVendorOptions);

    static bool IsUserField(const std::string &key);

    static void ClassifyFields(const Json::Value &vendorJson,
                               Json::Value &printerFields,
                               Json::Value &userFields);
};

} // namespace OHOS::Print

#endif // PRINT_VENDOR_OPTIONS_UTIL_H