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
    : userId_(other.userId_), printerId_(other.printerId_),
      hasVendorOptions_(other.hasVendorOptions_), vendorOptions_(other.vendorOptions_),
      customOptions_(other.customOptions_) {}

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

void PrinterUserPreferences::SetCustomOption(const std::string &key, const std::string &value)
{
    for (auto &option : customOptions_) {
        if (option.key == key) {
            option.isSet = true;
            option.value = value;
            return;
        }
    }
    CustomOption option;
    option.key = key;
    option.isSet = true;
    option.value = value;
    customOptions_.push_back(option);
}

void PrinterUserPreferences::SetCustomOptionUnset(const std::string &key)
{
    for (auto &option : customOptions_) {
        if (option.key == key) {
            option.isSet = false;
            return;
        }
    }
    CustomOption option;
    option.key = key;
    option.isSet = false;
    option.value = "";
    customOptions_.push_back(option);
}

bool PrinterUserPreferences::GetCustomOption(const std::string &key, std::string &value) const
{
    for (const auto &option : customOptions_) {
        if (option.key == key) {
            value = option.value;
            return true;
        }
    }
    return false;
}

bool PrinterUserPreferences::IsCustomOptionSet(const std::string &key) const
{
    for (const auto &option : customOptions_) {
        if (option.key == key) {
            return option.isSet;
        }
    }
    return false;
}

void PrinterUserPreferences::RemoveCustomOption(const std::string &key)
{
    for (auto it = customOptions_.begin(); it != customOptions_.end(); ++it) {
        if (it->key == key) {
            customOptions_.erase(it);
            return;
        }
    }
}

const std::vector<CustomOption>& PrinterUserPreferences::GetAllCustomOptions() const
{
    return customOptions_;
}

Json::Value PrinterUserPreferences::ConvertToJson() const
{
    Json::Value userPrefsJson;
    userPrefsJson["userId"] = userId_;
    userPrefsJson["printerId"] = printerId_;
    if (hasVendorOptions_) {
        userPrefsJson["vendorOptions"] = vendorOptions_;
    }
    if (!customOptions_.empty()) {
        Json::Value customArr;
        for (const auto &opt : customOptions_) {
            Json::Value optJson;
            optJson["key"] = opt.key;
            optJson["isSet"] = opt.isSet;
            optJson["value"] = opt.value;
            customArr.append(optJson);
        }
        userPrefsJson["customOptions"] = customArr;
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
    if (PrintJsonUtil::IsMember(json, "customOptions") && json["customOptions"].isArray()) {
        for (const auto &optJson : json["customOptions"]) {
            if (!optJson.isObject()) {
                continue;
            }
            CustomOption opt;
            if (optJson["key"].isString()) {
                opt.key = optJson["key"].asString();
            }
            if (optJson["isSet"].isBool()) {
                opt.isSet = optJson["isSet"].asBool();
            }
            if (optJson["value"].isString()) {
                opt.value = optJson["value"].asString();
            }
            customOptions_.push_back(opt);
        }
    }
}

void PrinterUserPreferences::Dump() const
{
    PRINT_HILOGD("userId: %{private}d", userId_);
    PRINT_HILOGD("printerId: %{public}s", printerId_.c_str());
    PRINT_HILOGD("vendorOptions: %{public}s", vendorOptions_.c_str());
    for (const auto &opt : customOptions_) {
        PRINT_HILOGD("customOption: key=%{public}s, isSet=%{public}d",
            opt.key.c_str(), opt.isSet);
    }
}

} // namespace OHOS::Print