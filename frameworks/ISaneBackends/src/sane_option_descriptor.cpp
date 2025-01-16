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

#include "sane_option_descriptor.h"
#include "scan_log.h"
#include "message_parcel.h"

namespace OHOS::Scan {
SaneOptionDescriptor::SaneOptionDescriptor() : optionType_(0), optionUnit_(0), optionSize_(0),
    optionCap_(0), optionConstraintType_(0), minValue_(0), maxValue_(0), quantValue_(0) {}
bool SaneOptionDescriptor::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteString(optionName_);
    status &= parcel.WriteString(optionTitle_);
    status &= parcel.WriteString(optionDesc_);
    status &= parcel.WriteInt32(optionType_);
    status &= parcel.WriteInt32(optionUnit_);
    status &= parcel.WriteInt32(optionSize_);
    status &= parcel.WriteInt32(optionCap_);
    status &= parcel.WriteInt32(optionConstraintType_);
    status &= parcel.WriteStringVector(optionConstraintString_);
    status &= parcel.WriteInt32Vector(optionConstraintNumber_);
    status &= parcel.WriteInt32(minValue_);
    status &= parcel.WriteInt32(maxValue_);
    status &= parcel.WriteInt32(quantValue_);
    return status;
}

SaneOptionDescriptor* SaneOptionDescriptor::Unmarshalling(Parcel &parcel)
{
    SaneOptionDescriptor* obj = new (std::nothrow) SaneOptionDescriptor();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr.");
        return nullptr;
    }
    obj->optionName_ = parcel.ReadString();
    obj->optionTitle_ = parcel.ReadString();
    obj->optionDesc_ = parcel.ReadString();
    obj->optionType_ = parcel.ReadInt32();
    obj->optionUnit_ = parcel.ReadInt32();
    obj->optionSize_ = parcel.ReadInt32();
    obj->optionCap_ = parcel.ReadInt32();
    obj->optionConstraintType_ = parcel.ReadInt32();
    parcel.ReadStringVector(&(obj->optionConstraintString_));
    parcel.ReadInt32Vector(&(obj->optionConstraintNumber_));
    obj->minValue_ = parcel.ReadInt32();
    obj->maxValue_ = parcel.ReadInt32();
    obj->quantValue_ = parcel.ReadInt32();
    return obj;
}

void SaneOptionDescriptor::Dump()
{
    SCAN_HILOGD("optionName_ = %{public}s", optionName_.c_str());
    SCAN_HILOGD("optionTitle_ = %{public}s", optionTitle_.c_str());
    SCAN_HILOGD("optionDesc_ = %{public}s", optionDesc_.c_str());
    SCAN_HILOGD("optionType_ = %{public}d", optionType_);
    SCAN_HILOGD("optionUnit_ = %{public}d", optionUnit_);
    SCAN_HILOGD("optionSize_ = %{public}d", optionSize_);
    SCAN_HILOGD("optionCap_ = %{public}d", optionCap_);
    SCAN_HILOGD("optionConstraintType_ = %{public}d", optionConstraintType_);
    for (const auto& str : optionConstraintString_) {
        SCAN_HILOGD("optionConstraintString_ = %{public}s", str.c_str());
    }
    for (const auto& number : optionConstraintNumber_) {
        SCAN_HILOGD("optionConstraintNumber_ = %{public}d", number);
    }
    SCAN_HILOGD("minValue_ = %{public}d", minValue_);
    SCAN_HILOGD("maxValue_ = %{public}d", maxValue_);
    SCAN_HILOGD("quantValue_ = %{public}d", quantValue_);
}
}   // namespace OHOS::Scan