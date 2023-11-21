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

void PrintMargin::ReadFromParcel(Parcel &parcel)
{
    hasTop_ = parcel.ReadBool();
    if (hasTop_) {
        SetTop(parcel.ReadUint32());
    }

    hasBottom_ = parcel.ReadBool();
    if (hasBottom_) {
        SetBottom(parcel.ReadUint32());
    }

    hasLeft_ = parcel.ReadBool();
    if (hasLeft_) {
        SetLeft(parcel.ReadUint32());
    }

    hasRight_ = parcel.ReadBool();
    if (hasRight_) {
        SetRight(parcel.ReadUint32());
    }
}

bool PrintMargin::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(hasTop_);
    if (hasTop_) {
        parcel.WriteUint32(GetTop());
    }

    parcel.WriteBool(hasBottom_);
    if (hasBottom_) {
        parcel.WriteUint32(GetBottom());
    }

    parcel.WriteBool(hasLeft_);
    if (hasLeft_) {
        parcel.WriteUint32(GetLeft());
    }

    parcel.WriteBool(hasRight_);
    if (hasRight_) {
        parcel.WriteUint32(GetRight());
    }
    return true;
}

std::shared_ptr<PrintMargin> PrintMargin::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintMargin>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintMargin::Dump()
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
} // namespace OHOS::Print
