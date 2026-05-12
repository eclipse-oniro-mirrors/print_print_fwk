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

#ifndef PRINTER_USER_PREFERENCES_H
#define PRINTER_USER_PREFERENCES_H

#include <string>
#include <cstdint>
#include "json/json.h"

namespace OHOS::Print {

struct SecureBlob {
    uint32_t size = 0;
    uint8_t *data = nullptr;

    SecureBlob() : size(0), data(nullptr) {}
    SecureBlob(uint32_t s, uint8_t *d) : size(s), data(d) {}
    SecureBlob(const SecureBlob &other);
    SecureBlob& operator=(const SecureBlob &other);
    SecureBlob(SecureBlob &&other) noexcept;
    SecureBlob& operator=(SecureBlob &&other) noexcept;
    ~SecureBlob();

    void Clear();
    bool IsEmpty() const { return data == nullptr || size == 0; }
    void SetData(const uint8_t *src, uint32_t srcSize);
    std::string ToString() const;
};

struct CustomOption {
    std::string key;
    bool isSet = false;
    SecureBlob value;
};

class PrinterUserPreferences {
public:
    PrinterUserPreferences();
    PrinterUserPreferences(const PrinterUserPreferences &other);
    ~PrinterUserPreferences();

    void SetUserId(int32_t userId);
    int32_t GetUserId() const;

    void SetPrinterId(const std::string &printerId);
    std::string GetPrinterId() const;

    void SetVendorOptions(const std::string &vendorOptions);
    bool HasVendorOptions() const;
    std::string GetVendorOptions() const;

    void SetCustomOption(const std::string &key, const SecureBlob &value);
    void SetCustomOptionUnset(const std::string &key);
    bool GetCustomOption(const std::string &key, SecureBlob &value) const;
    bool IsCustomOptionSet(const std::string &key) const;
    void RemoveCustomOption(const std::string &key);
    const std::vector<CustomOption>& GetAllCustomOptions() const;

    Json::Value ConvertToJson() const;
    void ConvertFromJson(Json::Value &json);

    void Dump() const;

private:
    int32_t userId_ = 0;
    std::string printerId_ = "";
    bool hasVendorOptions_ = false;
    std::string vendorOptions_ = "";
    std::vector<CustomOption> customOptions_;
};

} // namespace OHOS::Print

#endif // PRINTER_USER_PREFERENCES_H