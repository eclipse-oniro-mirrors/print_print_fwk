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
#include "ppd_info.h"
#include "print_json_util.h"

namespace OHOS::Print {
PpdInfo::PpdInfo()
    : hasManufacturer_(false),
      hasNickName_(false),
      hasPpdName_(false),
      manufacturer_(""),
      nickName_(""),
      ppdName_("")
{
}
 
PpdInfo::PpdInfo(const PpdInfo &right)
    : hasManufacturer_(right.hasManufacturer_),
      hasNickName_(right.hasNickName_),
      hasPpdName_(right.hasPpdName_),
      manufacturer_(right.manufacturer_),
      nickName_(right.nickName_),
      ppdName_(right.ppdName_)
{
}
 
PpdInfo &PpdInfo::operator=(const PpdInfo &right)
{
    if (this != &right) {
        hasManufacturer_ = right.hasManufacturer_;
        hasNickName_ = right.hasNickName_;
        hasPpdName_ = right.hasPpdName_;
        manufacturer_ = right.manufacturer_;
        nickName_ = right.nickName_;
        ppdName_ = right.ppdName_;
    }
    return *this;
}
 
PpdInfo::~PpdInfo() {}

void PpdInfo::SetManufacturer(const std::string &manufacturer)
{
    hasManufacturer_ = true;
    manufacturer_ = manufacturer;
}

void PpdInfo::SetNickName(const std::string &nickName)
{
    hasNickName_ = true;
    nickName_ = nickName;
}

void PpdInfo::SetPpdName(const std::string &ppdName)
{
    hasPpdName_ = true;
    ppdName_ = ppdName;
}

void PpdInfo::SetPpdInfo(const std::string &manufacturer, const std::string &nickName, const std::string &ppdName)
{
    SetManufacturer(manufacturer);
    SetNickName(nickName);
    SetPpdName(ppdName);
}

std::string PpdInfo::GetManufacturer() const
{
    return manufacturer_;
}

std::string PpdInfo::GetNickName() const
{
    return nickName_;
}

std::string PpdInfo::GetPpdName() const
{
    return ppdName_;
}

bool PpdInfo::ReadFromParcel(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    std::string element = parcel.ReadString();
    if (element.empty()) {
        PRINT_HILOGE("manufacturer is empty");
        return false;
    }
    SetManufacturer(element);
    element = parcel.ReadString();
    if (element.empty()) {
        PRINT_HILOGE("nickName is empty");
        return false;
    }
    SetNickName(element);
    element = parcel.ReadString();
    if (element.empty()) {
        PRINT_HILOGE("ppdName is empty");
        return false;
    }
    SetPpdName(element);
    return true;
}

bool PpdInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(GetManufacturer())) {
        PRINT_HILOGE("parcel WriteString Manufacturer failed");
        return false;
    }
    if (!parcel.WriteString(GetNickName())) {
        PRINT_HILOGE("parcel WriteString NickName failed");
        return false;
    }
    if (!parcel.WriteString(GetPpdName())) {
        PRINT_HILOGE("parcel WriteString PpdName failed");
        return false;
    }
    return true;
}

std::shared_ptr<PpdInfo> PpdInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PpdInfo>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return nativeObj;
}

void PpdInfo::Reset()
{
    hasManufacturer_ = false;
    hasNickName_ = false;
    hasPpdName_ = false;
    manufacturer_.clear();
    nickName_.clear();
    ppdName_.clear();
}

Json::Value PpdInfo::ConvertToJson() const
{
    Json::Value ppdInfoJson;
    if (hasManufacturer_) {
        ppdInfoJson["manufacturer"] = manufacturer_;
    }
    if (hasNickName_) {
        ppdInfoJson["nickName"] = nickName_;
    }
    if (hasPpdName_) {
        ppdInfoJson["ppdName"] = ppdName_;
    }
    return ppdInfoJson;
}

bool PpdInfo::ConvertFromJson(Json::Value &driverJson)
{
    if (!PrintJsonUtil::IsMember(driverJson, "manufacturer") || !driverJson["manufacturer"].isString()) {
        PRINT_HILOGW("can not find manufacturer");
        return false;
    }
    if (!PrintJsonUtil::IsMember(driverJson, "nickName") || !driverJson["nickName"].isString()) {
        PRINT_HILOGW("can not find nickName");
        return false;
    }
    if (!PrintJsonUtil::IsMember(driverJson, "ppdName") || !driverJson["ppdName"].isString()) {
        PRINT_HILOGW("can not find ppdName");
        return false;
    }

    SetManufacturer(driverJson["manufacturer"].asString());
    SetNickName(driverJson["nickName"].asString());
    SetPpdName(driverJson["ppdName"].asString());

    return true;
}

void PpdInfo::Dump() const
{
    if (hasManufacturer_) {
        PRINT_HILOGD("manufacturer: %{public}s", manufacturer_.c_str());
    }
    if (hasNickName_) {
        PRINT_HILOGD("nickName: %{public}s", nickName_.c_str());
    }
    if (hasPpdName_) {
        PRINT_HILOGD("ppdName: %{public}s", ppdName_.c_str());
    }
}
}  // namespace OHOS::Print