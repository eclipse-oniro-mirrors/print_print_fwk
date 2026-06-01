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
#include "print_constant.h"
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

bool PrintExtensionInfo::ReadFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(extensionId_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(vendorId_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(vendorName_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(vendorIcon_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(version_), false);
    return true;
}

bool PrintExtensionInfo::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetExtensionId()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVendorId()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVendorName()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetVendorIcon()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVersion()), false);
    return true;
}

std::shared_ptr<PrintExtensionInfo> PrintExtensionInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintExtensionInfo>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
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
