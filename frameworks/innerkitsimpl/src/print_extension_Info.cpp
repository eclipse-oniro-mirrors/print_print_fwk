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
PrinterExtensionInfo::PrinterExtensionInfo  () 
    : extensionId_(0), vendorId_(0), vendorName_("PrinterExtensionInfo"), 
    vendorIcon_(0), version_("PrinterExtensionInfo") {
    
}

void PrinterExtensionInfo::SetExtensionId(uint32_t extensionId)
{
    extensionId_ = extensionId;
}

void PrinterExtensionInfo::SetVendorId(uint32_t vendorId)
{
    vendorId_ = vendorId;
}

void PrinterExtensionInfo::SetVendorName(const std::string &vendorName)
{
    vendorName_ = vendorName;
}

void PrinterExtensionInfo::SetVendorIcon(uint32_t vendorIcon)
{
    vendorIcon_ = vendorIcon;
}

void PrinterExtensionInfo::SetVersion(const std::string &version)
{
    version_ = version;
}

uint32_t PrinterExtensionInfo::GetExtensionId() const
{
    return extensionId_;
}

uint32_t PrinterExtensionInfo::GetVendorId() const
{
    return vendorId_;
}

std::string &PrinterExtensionInfo::GetVendorName()
{
    return vendorName_;
}

uint32_t PrinterExtensionInfo::GetVendorIcon() const
{
    return vendorIcon_;
}

std::string &PrinterExtensionInfo::GetVersion()
{
    return version_;
}

void PrinterExtensionInfo::Dump()
{
    PRINT_HILOGD("extensionId = %{public}d", extensionId_);
    PRINT_HILOGD("vendorId_ = %{public}d", vendorId_);
    PRINT_HILOGD("vendorName_ = %{public}s", vendorName_.c_str());
    PRINT_HILOGD("vendorIcon_ = %{public}d", vendorIcon_);
    PRINT_HILOGD("version_ = %{public}s", version_.c_str());
}

PrinterExtensionInfo::~PrinterExtensionInfo()
{

}
} // namespace OHOS::Print
