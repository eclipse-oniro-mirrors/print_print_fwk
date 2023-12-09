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

#include "print_extension_info.h"
#include "print_log.h"

namespace OHOS::Print {
PrintExtensionInfo::PrintExtensionInfo() : extensionId_(""), vendorId_(""), vendorName_(""),
    vendorIcon_(0), version_("") {
}

PrintExtensionInfo::PrintExtensionInfo(const PrintExtensionInfo &right)
{
    extensionId_ = right.extensionId_;
    vendorId_ = right.vendorId_;
    vendorName_ = right.vendorName_;
    vendorIcon_ = right.vendorIcon_;
    version_ = right.version_;
}

PrintExtensionInfo &PrintExtensionInfo::operator=(const PrintExtensionInfo &right)
{
    if (this != &right) {
        extensionId_ = right.extensionId_;
        vendorId_ = right.vendorId_;
        vendorName_ = right.vendorName_;
        vendorIcon_ = right.vendorIcon_;
        version_ = right.version_;
    }
    return *this;
}

void PrintExtensionInfo::SetExtensionId(const std::string &extensionId)
{
    extensionId_ = extensionId;
}

void PrintExtensionInfo::SetVendorId(const std::string &vendorId)
{
    vendorId_ = vendorId;
}

void PrintExtensionInfo::SetVendorName(const std::string &vendorName)
{
    vendorName_ = vendorName;
}

void PrintExtensionInfo::SetVendorIcon(uint32_t vendorIcon)
{
    vendorIcon_ = vendorIcon;
}

void PrintExtensionInfo::SetVersion(const std::string &version)
{
    version_ = version;
}

const std::string &PrintExtensionInfo::GetExtensionId() const
{
    return extensionId_;
}

const std::string &PrintExtensionInfo::GetVendorId() const
{
    return vendorId_;
}

const std::string &PrintExtensionInfo::GetVendorName() const
{
    return vendorName_;
}

uint32_t PrintExtensionInfo::GetVendorIcon() const
{
    return vendorIcon_;
}

const std::string &PrintExtensionInfo::GetVersion() const
{
    return version_;
}

void PrintExtensionInfo::ReadFromParcel(Parcel &parcel)
{
    SetExtensionId(parcel.ReadString());
    SetVendorId(parcel.ReadString());
    SetVendorName(parcel.ReadString());
    SetVendorIcon(parcel.ReadUint32());
    SetVersion(parcel.ReadString());
}

bool PrintExtensionInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetExtensionId());
    parcel.WriteString(GetVendorId());
    parcel.WriteString(GetVendorName());
    parcel.WriteUint32(GetVendorIcon());
    parcel.WriteString(GetVersion());
    return true;
}

std::shared_ptr<PrintExtensionInfo> PrintExtensionInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintExtensionInfo>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintExtensionInfo::Dump()
{
    PRINT_HILOGD("extensionId = %{public}s", extensionId_.c_str());
    PRINT_HILOGD("vendorId_ = %{public}s", vendorId_.c_str());
    PRINT_HILOGD("vendorName_ = %{public}s", vendorName_.c_str());
    PRINT_HILOGD("vendorIcon_ = %{public}d", vendorIcon_);
    PRINT_HILOGD("version_ = %{public}s", version_.c_str());
}
}  // namespace OHOS::Print
