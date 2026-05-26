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

#include "print_vendor_options_util.h"
#include "print_log.h"
#include "print_json_util.h"

namespace OHOS::Print {

void PrintVendorOptionsUtil::SplitVendorOptions(const std::string &vendorOptions,
                                                std::string &printerVendorOptions,
                                                std::string &userVendorOptions)
{
    if (vendorOptions.empty()) {
        return;
    }
    Json::Value vendorJson;
    if (!PrintJsonUtil::Parse(vendorOptions, vendorJson)) {
        PRINT_HILOGW("Failed to parse vendorOptions JSON");
        printerVendorOptions = vendorOptions;
        return;
    }
    if (!vendorJson.isObject()) {
        PRINT_HILOGW("vendorOptions is not a JSON object");
        printerVendorOptions = vendorOptions;
        return;
    }
    Json::Value printerFields;
    Json::Value userFields;
    ClassifyFields(vendorJson, printerFields, userFields);
    if (!printerFields.empty()) {
        printerVendorOptions = PrintJsonUtil::WriteString(printerFields);
    }
    if (!userFields.empty()) {
        userVendorOptions = PrintJsonUtil::WriteString(userFields);
    }
    PRINT_HILOGD("SplitVendorOptions: printerVendorOptions=%{private}s, userVendorOptions=%{private}s",
        printerVendorOptions.c_str(), userVendorOptions.c_str());
}

std::string PrintVendorOptionsUtil::MergeVendorOptions(const std::string &defaultVendorOptions,
                                                       const std::string &overrideVendorOptions)
{
    Json::Value mergedJson;
    Json::Value defaultJson;
    if (!defaultVendorOptions.empty() && PrintJsonUtil::Parse(defaultVendorOptions, defaultJson)) {
        if (defaultJson.isObject()) {
            mergedJson = defaultJson;
        }
    }
    Json::Value overrideJson;
    if (!overrideVendorOptions.empty() && PrintJsonUtil::Parse(overrideVendorOptions, overrideJson)) {
        if (overrideJson.isObject()) {
            Json::Value::Members keys = overrideJson.getMemberNames();
            for (const auto &key : keys) {
                mergedJson[key] = overrideJson[key];
            }
        }
    }
    if (mergedJson.empty()) {
        PRINT_HILOGD("MergeVendorOptions: result is empty");
        return "";
    }
    std::string result = PrintJsonUtil::WriteString(mergedJson);
    PRINT_HILOGD("MergeVendorOptions: result=%{private}s", result.c_str());
    return result;
}

bool PrintVendorOptionsUtil::IsUserField(const std::string &key)
{
    const std::string USER_PREFIX = "user_";
    if (key.length() < USER_PREFIX.length()) {
        return false;
    }
    return key.compare(0, USER_PREFIX.length(), USER_PREFIX) == 0;
}

void PrintVendorOptionsUtil::ClassifyFields(const Json::Value &vendorJson,
                                            Json::Value &printerFields,
                                            Json::Value &userFields)
{
    Json::Value::Members keys = vendorJson.getMemberNames();
    for (const auto &key : keys) {
        if (IsUserField(key)) {
            userFields[key] = vendorJson[key];
        } else {
            printerFields[key] = vendorJson[key];
        }
    }
}

} // namespace OHOS::Print