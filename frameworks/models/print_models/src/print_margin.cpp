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

#include "print_margin.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintMargin::PrintMargin() : hasTop_(false), top_(0), hasBottom_(false), bottom_(0), hasLeft_(false), left_(0),
    hasRight_(false), right_(0) {
}

PrintMargin::PrintMargin(const PrintMargin &right)
{
    Set(right);
}

void PrintMargin::Set(const PrintMargin &right)
{
    hasTop_ = right.hasTop_;
    top_ = right.top_;
    hasBottom_ = right.hasBottom_;
    bottom_ = right.bottom_;
    hasLeft_ = right.hasLeft_;
    left_ = right.left_;
    hasRight_ = right.hasRight_;
    right_ = right.right_;
}

PrintMargin &PrintMargin::operator=(const PrintMargin &right)
{
    if (this != &right) {
        Set(right);
    }
    return *this;
}

PrintMargin::~PrintMargin()
{
}

void PrintMargin::Reset()
{
    hasTop_ = false;
    top_ = 0;
    hasBottom_ = false;
    bottom_ = 0;
    hasLeft_ = false;
    left_ = 0;
    hasRight_ = false;
    right_ = 0;
}

void PrintMargin::SetTop(uint32_t top)
{
    hasTop_ = true;
    top_ = top;
}

void PrintMargin::SetBottom(uint32_t bottom)
{
    hasBottom_ = true;
    bottom_ = bottom;
}

void PrintMargin::SetLeft(uint32_t left)
{
    hasLeft_ = true;
    left_ = left;
}

void PrintMargin::SetRight(uint32_t right)
{
    hasRight_ = true;
    right_ = right;
}

bool PrintMargin::HasTop() const
{
    return hasTop_;
}

uint32_t PrintMargin::GetTop() const
{
    return top_;
}

bool PrintMargin::HasBottom() const
{
    return hasBottom_;
}

uint32_t PrintMargin::GetBottom() const
{
    return bottom_;
}

bool PrintMargin::HasLeft() const
{
    return hasLeft_;
}

uint32_t PrintMargin::GetLeft() const
{
    return left_;
}

bool PrintMargin::HasRight() const
{
    return hasRight_;
}

uint32_t PrintMargin::GetRight() const
{
    return right_;
}

bool PrintMargin::ReadFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasTop_), false);
    if (hasTop_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(top_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasBottom_), false);
    if (hasBottom_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(bottom_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasLeft_), false);
    if (hasLeft_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(left_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasRight_), false);
    if (hasRight_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(right_), false);
    }
    return true;
}

bool PrintMargin::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasTop_), false);
    if (hasTop_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetTop()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasBottom_), false);
    if (hasBottom_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetBottom()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasLeft_), false);
    if (hasLeft_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetLeft()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasRight_), false);
    if (hasRight_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetRight()), false);
    }
    return true;
}

std::shared_ptr<PrintMargin> PrintMargin::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintMargin>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return nativeObj;
}

void PrintMargin::Dump() const
{
    if (hasTop_) {
        PRINT_HILOGD("top_ = %{public}d", top_);
    }

    if (hasBottom_) {
        PRINT_HILOGD("bottom_ = %{public}d", bottom_);
    }

    if (hasLeft_) {
        PRINT_HILOGD("left_ = %{public}d", left_);
    }

    if (hasRight_) {
        PRINT_HILOGD("right_ = %{public}d", right_);
    }
}

Json::Value PrintMargin::ConvertToJsonObject() const
{
    Json::Value marginJson;
    marginJson["hasTop_"] = hasTop_;
    if (hasTop_) {
        marginJson["top_"] = top_;
    }
    marginJson["hasBottom_"] = hasBottom_;
    if (hasBottom_) {
        marginJson["bottom_"] = bottom_;
    }
    marginJson["hasLeft_"] = hasLeft_;
    if (hasLeft_) {
        marginJson["left_"] = left_;
    }
    marginJson["hasRight_"] = hasRight_;
    if (hasRight_) {
        marginJson["right_"] = right_;
    }
    return marginJson;
}
} // namespace OHOS::Print
