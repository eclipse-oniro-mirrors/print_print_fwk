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

#include "scan_option_descriptor.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanOptionDescriptor::ScanOptionDescriptor() : optionName_(""), optionIndex_(0),
    optionTitle_(""), optionDesc_(""),
    optionType_(0), optionUnit_(0), optionConstraintType_(0) {
    optionConstraintString_.clear();
    optionConstraintNumber_.clear();
}

ScanOptionDescriptor::ScanOptionDescriptor(const ScanOptionDescriptor &right)
{
    optionName_ = right.optionName_;
    optionIndex_ = right.optionIndex_;
    optionTitle_ = right.optionTitle_;
    optionDesc_ = right.optionDesc_;
    optionType_ = right.optionType_;
    optionUnit_ = right.optionUnit_;
    optionConstraintType_ = right.optionConstraintType_;
    optionConstraintString_.assign(right.optionConstraintString_.begin(), right.optionConstraintString_.end());
    optionConstraintNumber_.assign(right.optionConstraintNumber_.begin(), right.optionConstraintNumber_.end());
    optionConstraintRange_ = right.optionConstraintRange_;
}

ScanOptionDescriptor &ScanOptionDescriptor::operator=(const ScanOptionDescriptor &right)
{
    if (this != &right) {
        optionName_ = right.optionName_;
        optionIndex_ = right.optionIndex_;
        optionTitle_ = right.optionTitle_;
        optionDesc_ = right.optionDesc_;
        optionType_ = right.optionType_;
        optionUnit_ = right.optionUnit_;
        optionConstraintType_ = right.optionConstraintType_;
        optionConstraintString_.assign(right.optionConstraintString_.begin(), right.optionConstraintString_.end());
        optionConstraintNumber_.assign(right.optionConstraintNumber_.begin(), right.optionConstraintNumber_.end());
        optionConstraintRange_ = right.optionConstraintRange_;
    }
    return *this;
}

void ScanOptionDescriptor::SetOptionName(const std::string &optionName)
{
    optionName_ = optionName;
}

void ScanOptionDescriptor::SetOptionIndex(const uint32_t& optionIndex)
{
    optionIndex_ = optionIndex;
}

void ScanOptionDescriptor::SetOptionTitle(const std::string &optionTitle)
{
    optionTitle_ = optionTitle;
}

void ScanOptionDescriptor::SetOptionDesc(const std::string &optionDesc)
{
    optionDesc_ = optionDesc;
}

void ScanOptionDescriptor::SetOptionType(const uint32_t &optionType)
{
    optionType_ = optionType;
}

void ScanOptionDescriptor::SetOptionUnit(const uint32_t &optionUnit)
{
    optionUnit_ = optionUnit;
}

void ScanOptionDescriptor::SetOptionConstraintType(const uint32_t &optionConstraintType)
{
    optionConstraintType_ = optionConstraintType;
}

void ScanOptionDescriptor::SetOptionConstraintString(const std::vector<std::string> &optionConstraintString)
{
    optionConstraintString_.assign(optionConstraintString.begin(), optionConstraintString.end());
}

void ScanOptionDescriptor::SetOptionConstraintNumber(const std::vector<int32_t> &optionConstraintNumber)
{
    optionConstraintNumber_.assign(optionConstraintNumber.begin(), optionConstraintNumber.end());
}

void ScanOptionDescriptor::SetOptionConstraintRange(const ScanRange &optionConstraintRange)
{
    optionConstraintRange_ = optionConstraintRange;
}

std::string ScanOptionDescriptor::GetOptionName() const
{
    return optionName_;
}

uint32_t ScanOptionDescriptor::GetOptionIndex() const
{
    return optionIndex_;
}

std::string ScanOptionDescriptor::GetOptionTitle() const
{
    return optionTitle_;
}

std::string ScanOptionDescriptor::GetOptionDesc() const
{
    return optionDesc_;
}

uint32_t ScanOptionDescriptor::GetOptionType() const
{
    return optionType_;
}

uint32_t ScanOptionDescriptor::GetOptionUnit() const
{
    return optionUnit_;
}

uint32_t ScanOptionDescriptor::GetOptionConstraintType() const
{
    return optionConstraintType_;
}

void ScanOptionDescriptor::GetOptionConstraintString(std::vector<std::string> &optionConstraintString) const
{
    optionConstraintString.assign(optionConstraintString_.begin(), optionConstraintString_.end());
}

void ScanOptionDescriptor::GetOptionConstraintNumber(std::vector<int32_t> &optionConstraintNumber) const
{
    optionConstraintNumber.assign(optionConstraintNumber_.begin(), optionConstraintNumber_.end());
}

void ScanOptionDescriptor::GetOptionConstraintRange(ScanRange &optionConstraintRange) const
{
    optionConstraintRange = optionConstraintRange_;
}

void ScanOptionDescriptor::ReadFromParcel(Parcel &parcel)
{
    SetOptionName(parcel.ReadString());
    SetOptionTitle(parcel.ReadString());
    SetOptionDesc(parcel.ReadString());
    SetOptionType(parcel.ReadUint32());
    SetOptionUnit(parcel.ReadUint32());

    SetOptionConstraintType(parcel.ReadUint32());

    std::vector<std::string> optionConstraintString;
    parcel.ReadStringVector(&optionConstraintString);
    if (optionConstraintString.size() > 0) {
        SetOptionConstraintString(optionConstraintString);
    }

    std::vector<std::int32_t> optionConstraintNumber;
    parcel.ReadInt32Vector(&optionConstraintNumber);
    if (optionConstraintNumber.size() > 0) {
        SetOptionConstraintNumber(optionConstraintNumber);
    }

    auto scanRange = ScanRange::Unmarshalling(parcel);
    if (scanRange != nullptr) {
        ScanRange optionConstraintRange = *scanRange;
        SetOptionConstraintRange(optionConstraintRange);
    }
}

bool ScanOptionDescriptor::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(optionName_);
    parcel.WriteString(optionTitle_);
    parcel.WriteString(optionDesc_);
    parcel.WriteUint32(optionType_);
    parcel.WriteUint32(optionUnit_);

    parcel.WriteUint32(optionConstraintType_);

    parcel.WriteStringVector(optionConstraintString_);

    parcel.WriteInt32Vector(optionConstraintNumber_);

    optionConstraintRange_.Marshalling(parcel);
    return true;
}

std::shared_ptr<ScanOptionDescriptor> ScanOptionDescriptor::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanOptionDescriptor>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void ScanOptionDescriptor::Dump()
{
    SCAN_HILOGI("optionName = %{public}s", optionName_.c_str());
    SCAN_HILOGI("optionTitle = %{public}s", optionTitle_.c_str());
    SCAN_HILOGI("optionDesc = %{public}s", optionDesc_.c_str());
    SCAN_HILOGI("optionType = %{public}d", optionType_);
    SCAN_HILOGI("optionUnit = %{public}d", optionUnit_);

    SCAN_HILOGI("optionConstraintType = %{public}d", optionConstraintType_);
    for (const auto& str : optionConstraintString_) {
        SCAN_HILOGI("str = %{public}s", str.c_str());
    }
    for (const auto& number : optionConstraintNumber_) {
        SCAN_HILOGI("number = %{public}d", number);
    }
    optionConstraintRange_.Dump();
}
}  // namespace OHOS::Scan
