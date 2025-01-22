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

#include "scan_range.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanRange::ScanRange() : minValue_(0), maxValue_(0), quantValue_(0)
{}

ScanRange::ScanRange(const ScanRange &right)
{
    minValue_ = right.minValue_;
    maxValue_ = right.maxValue_;
    quantValue_ = right.quantValue_;
}

ScanRange &ScanRange::operator=(const ScanRange &right)
{
    if (this != &right) {
        minValue_ = right.minValue_;
        maxValue_ = right.maxValue_;
        quantValue_ = right.quantValue_;
    }
    return *this;
}

ScanRange::~ScanRange()
{}

void ScanRange::Reset()
{
    minValue_ = 0;
    maxValue_ = 0;
    quantValue_ = 0;
}

void ScanRange::SetMinValue(const int32_t &minValue)
{
    minValue_ = minValue;
}

void ScanRange::SetMaxValue(const int32_t &maxValue)
{
    maxValue_ = maxValue;
}

void ScanRange::SetQuantValue(const int32_t &quantValue)
{
    quantValue_ = quantValue;
}

int32_t ScanRange::GetMinValue() const
{
    return minValue_;
}

int32_t ScanRange::GetMaxValue() const
{
    return maxValue_;
}

int32_t ScanRange::GetQuantValue() const
{
    return quantValue_;
}

void ScanRange::ReadFromParcel(Parcel &parcel)
{
    SetMinValue(parcel.ReadInt32());

    SetMaxValue(parcel.ReadInt32());

    SetQuantValue(parcel.ReadInt32());
}

bool ScanRange::Marshalling(Parcel &parcel) const
{
    parcel.WriteInt32(minValue_);

    parcel.WriteInt32(maxValue_);

    parcel.WriteInt32(quantValue_);
    return true;
}

std::shared_ptr<ScanRange> ScanRange::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanRange>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void ScanRange::Dump() const
{
    SCAN_HILOGD("MinValue = %{public}d", minValue_);
    SCAN_HILOGD("MaxValue = %{public}d", maxValue_);
    SCAN_HILOGD("QuantValue = %{public}d", quantValue_);
}
} // namespace OHOS::Scan
