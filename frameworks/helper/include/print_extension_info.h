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

#include "parcel.h"

namespace OHOS::Print {
class PrintExtensionInfo final : public Parcelable {
public:
    explicit PrintExtensionInfo();
    PrintExtensionInfo(const PrintExtensionInfo &right);
    ~PrintExtensionInfo() = default;

    PrintExtensionInfo &operator=(const PrintExtensionInfo &right);

    void SetExtensionId(const std::string &extensionId);

    void SetVendorId(const std::string &vendorId);

    void SetVendorName(const std::string &vendorName);

    void SetVendorIcon(uint32_t vendorIcon);

    void SetVersion(const std::string &version);

    [[nodiscard]] const std::string &GetExtensionId() const;

    [[nodiscard]] const std::string &GetVendorId() const;

    [[nodiscard]] const std::string &GetVendorName() const;

    [[nodiscard]] uint32_t GetVendorIcon() const;

    [[nodiscard]] const std::string &GetVersion() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintExtensionInfo> Unmarshalling(Parcel &parcel);

    void Dump();

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string extensionId_;
    std::string vendorId_;
    std::string vendorName_;
    uint32_t vendorIcon_;
    std::string version_;
};
}  // namespace OHOS::Print
#endif  // PRINT_EXTENSION_INFO_H
