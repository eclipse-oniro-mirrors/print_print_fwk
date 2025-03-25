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

#include "scan_option_value.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanOptionValue::ScanOptionValue() : valueType_(SCAN_VALUE_BOOL
    ), valueSize_(0), numValue_(0), strValue_(""), boolValue_(false)
{
    numListValue_.clear();
}

ScanOptionValue::ScanOptionValue(const ScanOptionValue &right)
{
    valueType_ = right.valueType_;
    valueSize_ = right.valueSize_;
    numValue_ = right.numValue_;
    strValue_ = right.strValue_;
    boolValue_ = right.boolValue_;
    numListValue_.assign(right.numListValue_.begin(), right.numListValue_.end());
}

ScanOptionValue &ScanOptionValue::operator=(const ScanOptionValue &right)
{
    if (this != &right) {
        valueType_ = right.valueType_;
        valueSize_ = right.valueSize_;
        numValue_ = right.numValue_;
        strValue_ = right.strValue_;
        boolValue_ = right.boolValue_;
        numListValue_.assign(right.numListValue_.begin(), right.numListValue_.end());
    }
    return *this;
}

ScanOptionValue::~ScanOptionValue()
{}

void ScanOptionValue::Reset()
{
    valueType_ = SCAN_VALUE_BOOL;
    valueSize_ = 0;
    numValue_ = 0;
    strValue_ = "";
    boolValue_ = false;
    numListValue_.clear();
}

void ScanOptionValue::SetScanOptionValueType(const ScanOptionValueType &valueType)
{
    valueType_ = valueType;
}

void ScanOptionValue::SetValueSize(const int32_t &valueSize)
{
    valueSize_ = valueSize;
}

void ScanOptionValue::SetNumValue(const int32_t &numValue)
{
    numValue_ = numValue;
}

void ScanOptionValue::SetNumListValue(const std::vector<int32_t> &numListValue)
{
    numListValue_.assign(numListValue.begin(), numListValue.end());
}

void ScanOptionValue::SetStrValue(const std::string &strValue)
{
    strValue_ = strValue;
}

void ScanOptionValue::SetBoolValue(const bool &boolValue)
{
    boolValue_ = boolValue;
}

ScanOptionValueType ScanOptionValue::GetScanOptionValueType() const
{
    return valueType_;
}

int32_t ScanOptionValue::GetValueSize() const
{
    return valueSize_;
}

int32_t ScanOptionValue::GetNumValue() const
{
    return numValue_;
}

void ScanOptionValue::GetNumListValue(std::vector<int32_t> &numListValue) const
{
    numListValue.assign(numListValue_.begin(), numListValue_.end());
}

std::string ScanOptionValue::GetStrValue() const
{
    return strValue_;
}

bool ScanOptionValue::GetBoolValue() const
{
    return boolValue_;
}

void ScanOptionValue::ReadFromParcel(Parcel &parcel)
{
    SetScanOptionValueType((ScanOptionValueType)parcel.ReadUint32());
    SetValueSize(parcel.ReadInt32());
    if (valueType_ == SCAN_VALUE_STR) {
        SetStrValue(parcel.ReadString());
    } else {
        SetNumValue(parcel.ReadInt32());
    }
}

bool ScanOptionValue::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteUint32(valueType_);
    status &= parcel.WriteInt32(valueSize_);
    if (valueType_ == SCAN_VALUE_STR) {
        status &= parcel.WriteString(strValue_);
    } else {
        status &= parcel.WriteInt32(numValue_);
    }
    return status;
}

std::shared_ptr<ScanOptionValue> ScanOptionValue::Unmarshalling(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        SCAN_HILOGE("There are no bytes to read");
        return nullptr;
    }
    auto nativeObj = std::make_shared<ScanOptionValue>();
    if (nativeObj == nullptr) {
        SCAN_HILOGE("nativeObj is a nullptr");
        return nullptr;
    }
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void ScanOptionValue::Dump()
{
    SCAN_HILOGD("ValueType = %{public}d", valueType_);
    SCAN_HILOGD("ValueSize = %{public}d", valueSize_);
    if (valueType_ == SCAN_VALUE_STR) {
        SCAN_HILOGD("StrValue = %{public}s", strValue_.c_str());
    } else {
        SCAN_HILOGD("NumValue = %{public}d", numValue_);
    }
}
} // namespace OHOS::Scan
