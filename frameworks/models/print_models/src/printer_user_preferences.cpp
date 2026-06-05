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

#include "printer_user_preferences.h"
#include "print_log.h"
#include "print_json_util.h"
#include "print_util.h"
#include "print_constant.h"
#include <cstring>
#include "securec.h"

namespace OHOS::Print {

SecureBlob::SecureBlob(const SecureBlob &other) : size(0), data(nullptr)
{
    SetData(other.data, other.size);
}

SecureBlob::SecureBlob(uint32_t s, uint8_t *d) : size(0), data(nullptr)
{
    SetData(d, s);
}

SecureBlob& SecureBlob::operator=(const SecureBlob &other)
{
    if (this == &other) {
        return *this;
    }
    SetData(other.data, other.size);
    return *this;
}

SecureBlob::SecureBlob(SecureBlob &&other) noexcept : size(other.size), data(other.data)
{
    other.size = 0;
    other.data = nullptr;
}

SecureBlob& SecureBlob::operator=(SecureBlob &&other) noexcept
{
    if (this == &other) {
        return *this;
    }
    Clear();
    size = other.size;
    data = other.data;
    other.size = 0;
    other.data = nullptr;
    return *this;
}

SecureBlob::~SecureBlob()
{
    Clear();
}

void SecureBlob::Clear()
{
    PrintUtil::SecureDeleteBlob(data, size);
}

void SecureBlob::SetData(const uint8_t *src, uint32_t srcSize)
{
    Clear();
    if (src != nullptr && srcSize > 0) {
        data = new (std::nothrow) uint8_t[srcSize];
        if (data != nullptr) {
            if (memcpy_s(data, srcSize, src, srcSize) == EOK) {
                size = srcSize;
            } else {
                delete[] data;
                data = nullptr;
            }
        }
    }
}

void SecureBlob::Allocate(uint32_t allocSize)
{
    Clear();
    if (allocSize > 0) {
        data = new (std::nothrow) uint8_t[allocSize];
        if (data != nullptr) {
            size = allocSize;
        }
    }
}

std::string SecureBlob::ToString() const
{
    if (data == nullptr || size == 0) {
        return "";
    }
    return std::string(reinterpret_cast<const char *>(data), size);
}

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

void PrinterUserPreferences::SetCustomOption(const std::string &key, const std::string &choice,
    const SecureBlob &value)
{
    for (auto &option : customOptions_) {
        if (option.key == key) {
            option.choice = choice;
            option.value = (choice == CUSTOM_OPTION_CHOICE) ? value : SecureBlob{};
            return;
        }
    }
    CustomOption option;
    option.key = key;
    option.choice = choice;
    option.value = (choice == CUSTOM_OPTION_CHOICE) ? value : SecureBlob{};
    customOptions_.push_back(option);
}

std::shared_ptr<CustomOption> PrinterUserPreferences::GetCustomOption(const std::string &key) const
{
    for (const auto &option : customOptions_) {
        if (option.key == key && !option.choice.empty()) {
            return std::make_shared<CustomOption>(option);
        }
    }
    return nullptr;
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

std::vector<std::string> PrinterUserPreferences::GetAllCustomOptionKeys() const
{
    std::vector<std::string> keys;
    keys.reserve(customOptions_.size());
    for (const auto &option : customOptions_) {
        keys.push_back(option.key);
    }
    return keys;
}

bool PrinterUserPreferences::IsEmpty() const
{
    if (hasVendorOptions_) {
        return false;
    }
    for (const auto &option : customOptions_) {
        if (!option.choice.empty()) {
            return false;
        }
    }
    return true;
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
            optJson["choice"] = opt.choice;
            optJson["value"] = opt.value.ToString();
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
            if (optJson["choice"].isString()) {
                opt.choice = optJson["choice"].asString();
            } else if (optJson["isSet"].isBool()) {
                opt.choice = optJson["isSet"].asBool() ? CUSTOM_OPTION_CHOICE : "";
            }
            if (optJson["value"].isString()) {
                opt.value.SetData(reinterpret_cast<const uint8_t *>(
                    optJson["value"].asString().c_str()), optJson["value"].asString().size());
            }
            customOptions_.push_back(opt);
        }
    }
}

void PrinterUserPreferences::Dump() const
{
    PRINT_HILOGD("userId: %{private}d", userId_);
    PRINT_HILOGD("printerId: %{private}s", printerId_.c_str());
    PRINT_HILOGD("vendorOptions: %{private}s", vendorOptions_.c_str());
    for (const auto &opt : customOptions_) {
        PRINT_HILOGD("customOption: key=%{public}s, choice=%{public}s",
            opt.key.c_str(), opt.choice.c_str());
    }
}

} // namespace OHOS::Print