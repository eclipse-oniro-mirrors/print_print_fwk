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

#include "print_resolution.h"
#include "print_log.h"

namespace OHOS::Print {
PrintResolution::PrintResolution() : id_(""), horizontalDpi_(0), verticalDpi_(0) {
}

PrintResolution::PrintResolution(const PrintResolution &right)
{
    SetId(right.id_);
    SetHorizontalDpi(right.horizontalDpi_);
    SetVerticalDpi(right.verticalDpi_);
}

PrintResolution &PrintResolution::operator=(const PrintResolution &right)
{
    if (this != &right) {
        SetId(right.id_);
        SetHorizontalDpi(right.horizontalDpi_);
        SetVerticalDpi(right.verticalDpi_);
    }
    return *this;
}

PrintResolution::~PrintResolution()
{
}

void PrintResolution::Reset()
{
    SetId("");
    SetHorizontalDpi(0);
    SetVerticalDpi(0);
}

const std::string &PrintResolution::GetId() const
{
    return id_;
}

uint32_t PrintResolution::GetHorizontalDpi() const
{
    return horizontalDpi_;
}

uint32_t PrintResolution::GetVerticalDpi() const
{
    return verticalDpi_;
}

void PrintResolution::SetId(const std::string &id)
{
    id_ = id;
}

void PrintResolution::SetHorizontalDpi(uint32_t horizontalDpi)
{
    horizontalDpi_ = horizontalDpi;
}

void PrintResolution::SetVerticalDpi(uint32_t verticalDpi)
{
    verticalDpi_ = verticalDpi;
}

void PrintResolution::ReadFromParcel(Parcel &parcel)
{
    SetId(parcel.ReadString());
    SetHorizontalDpi(parcel.ReadUint32());
    SetVerticalDpi(parcel.ReadUint32());
}

bool PrintResolution::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetId());
    parcel.WriteUint32(GetHorizontalDpi());
    parcel.WriteUint32(GetVerticalDpi());
    return true;
}

std::shared_ptr<PrintResolution> PrintResolution::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintResolution>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintResolution::Dump()
{
    PRINT_HILOGD("id_ = %{public}s", id_.c_str());
    PRINT_HILOGD("horizontalDpi_ = %{public}d", horizontalDpi_);
    PRINT_HILOGD("verticalDpi_ = %{public}d", verticalDpi_);
}
} // namespace OHOS::Print
