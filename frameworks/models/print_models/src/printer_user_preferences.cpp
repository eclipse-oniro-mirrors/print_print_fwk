/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "printer_user_preferences.h"
#include "print_log.h"
#include "print_json_util.h"

namespace OHOS::Print {

PrinterUserPreferences::PrinterUserPreferences() {}

PrinterUserPreferences::PrinterUserPreferences(const PrinterUserPreferences &other)
    : userId_(other.userId_)
    , printerId_(other.printerId_)
    , hasVendorOptions_(other.hasVendorOptions_)
    , vendorOptions_(other.vendorOptions_) {}

PrinterUserPreferences::~PrinterUserPreferences() {}

void PrinterUserPreferences::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t PrinterUserPreferences::GetUserId() const
{
    return userId_;
}

void PrinterUserPreferences::SetPrinterId(const std::string &printerId)
{
    printerId_ = printerId;
}

std::string PrinterUserPreferences::GetPrinterId() const
{
    return printerId_;
}

void PrinterUserPreferences::SetVendorOptions(const std::string &vendorOptions)
{
    vendorOptions_ = vendorOptions;
    hasVendorOptions_ = !vendorOptions_.empty();
}

bool PrinterUserPreferences::HasVendorOptions() const
{
    return hasVendorOptions_;
}

std::string PrinterUserPreferences::GetVendorOptions() const
{
    return vendorOptions_;
}

Json::Value PrinterUserPreferences::ConvertToJson() const
{
    Json::Value userPrefsJson;
    userPrefsJson["userId"] = userId_;
    userPrefsJson["printerId"] = printerId_;
    if (hasVendorOptions_) {
        userPrefsJson["vendorOptions"] = vendorOptions_;
    }
    return userPrefsJson;
}

void PrinterUserPreferences::ConvertFromJson(Json::Value &json)
{
    if (PrintJsonUtil::IsMember(json, "userId") && json["userId"].isInt()) {
        SetUserId(json["userId"].asInt());
    }
    if (PrintJsonUtil::IsMember(json, "printerId") && json["printerId"].isString()) {
        SetPrinterId(json["printerId"].asString());
    }
    if (PrintJsonUtil::IsMember(json, "vendorOptions") && json["vendorOptions"].isString()) {
        SetVendorOptions(json["vendorOptions"].asString());
    }
}

void PrinterUserPreferences::Dump() const
{
    PRINT_HILOGD("userId: %{private}d", userId_);
    PRINT_HILOGD("printerId: %{public}s", printerId_.c_str());
    PRINT_HILOGD("vendorOptions: %{public}s", vendorOptions_.c_str());
}

} // namespace OHOS::Print