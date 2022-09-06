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

#ifndef PRINT_EXTENSION_INFO_H
#define PRINT_EXTENSION_INFO_H

#include <map>
#include <string>

namespace OHOS::Print {
class PrinterExtensionInfo {
public:
    PrinterExtensionInfo();

    void SetExtensionId(uint32_t extensionId);

    void SetVendorId(uint32_t vendorId);

    void SetVendorName(const std::string &vendorName);

    void SetVendorIcon(uint32_t vendorIcon);

    void SetVersion(const std::string &version);

    [[nodiscard]] uint32_t GetExtensionId() const;

    [[nodiscard]] uint32_t GetVendorId() const;

    [[nodiscard]] const std::string &GetVendorName() const;

    [[nodiscard]] uint32_t GetVendorIcon() const;

    [[nodiscard]] const std::string &GetVersion() const;

    void Dump();

    ~PrinterExtensionInfo();

private:
    uint32_t extensionId_;
    uint32_t vendorId_;
    std::string vendorName_;
    uint32_t vendorIcon_;
    std::string version_;
};
} // namespace OHOS::Print
#endif // PRINT_EXTENSION_INFO_H
