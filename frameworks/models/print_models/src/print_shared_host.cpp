/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "print_constant.h"
#include "print_log.h"
#include "print_shared_host.h"

namespace OHOS::Print {
void PrintSharedHost::SetIp(const std::string &ip)
{
    ip_ = ip;
}

void PrintSharedHost::SetShareName(const std::string &shareName)
{
    shareName_ = shareName;
}

void PrintSharedHost::SetWorkgroupName(const std::string &workgroupName)
{
    workgroupName_ = workgroupName;
}

std::string PrintSharedHost::GetIp() const
{
    return ip_;
}

std::string PrintSharedHost::GetShareName() const
{
    return shareName_;
}

std::string PrintSharedHost::GetWorkgroupName() const
{
    return workgroupName_;
}

bool PrintSharedHost::ReadFromParcel(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    SetIp(parcel.ReadString());
    SetShareName(parcel.ReadString());
    SetWorkgroupName(parcel.ReadString());
    return true;
}

bool PrintSharedHost::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(GetIp())) {
        PRINT_HILOGE("parcel WriteString ip failed");
        return false;
    }
    if (!parcel.WriteString(GetShareName())) {
        PRINT_HILOGE("parcel WriteString shareName failed");
        return false;
    }
    if (!parcel.WriteString(GetWorkgroupName())) {
        PRINT_HILOGE("parcel WriteString workgroupName failed");
        return false;
    }
    return true;
}

std::shared_ptr<PrintSharedHost> PrintSharedHost::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintSharedHost>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return nativeObj;
}

void PrintSharedHost::Dump() const
{
    PRINT_HILOGD("PrintSharedHost:[%{private}s] [%{private}s] [%{private}s]",
        ip_.c_str(), shareName_.c_str(), workgroupName_.c_str());
}
}  // namespace OHOS::Print