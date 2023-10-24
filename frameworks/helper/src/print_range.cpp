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

#include "print_range.h"
#include "print_log.h"

namespace OHOS::Print {
PrintRange::PrintRange() : hasStartPage_(false), startPage_(0), hasEndPage_(false),
    endPage_(0), hasPages_(false)
{
    pages_.clear();
}

PrintRange::PrintRange(const PrintRange &right)
{
    hasStartPage_ = right.hasStartPage_;
    startPage_ = right.startPage_;
    hasEndPage_ = right.hasEndPage_;
    endPage_ = right.endPage_;
    hasPages_ = right.hasPages_;
    pages_.assign(right.pages_.begin(), right.pages_.end());
}

PrintRange &PrintRange::operator=(const PrintRange &right)
{
    if (this != &right) {
        hasStartPage_ = right.hasStartPage_;
        startPage_ = right.startPage_;
        hasEndPage_ = right.hasEndPage_;
        endPage_ = right.endPage_;
        hasPages_ = right.hasPages_;
        pages_.assign(right.pages_.begin(), right.pages_.end());
    }
    return *this;
}

PrintRange::~PrintRange()
{
    pages_.clear();
}

void PrintRange::Reset()
{
    hasStartPage_ = false;
    startPage_ = 0;
    hasEndPage_ = false;
    endPage_ = 0;
    hasPages_ = false;
    pages_.clear();
}

bool PrintRange::HasStartPage() const
{
    return hasStartPage_;
}

uint32_t PrintRange::GetStartPage() const
{
    return startPage_;
}

bool PrintRange::HasEndPage() const
{
    return hasEndPage_;
}

uint32_t PrintRange::GetEndPage() const
{
    return endPage_;
}

bool PrintRange::HasPages() const
{
    return hasPages_;
}

void PrintRange::GetPages(std::vector<uint32_t> &pages) const
{
    pages.assign(pages_.begin(), pages_.end());
}

void PrintRange::SetStartPage(uint32_t startpage)
{
    hasStartPage_ = true;
    startPage_ = startpage;
}

void PrintRange::SetEndPage(uint32_t endpage)
{
    hasEndPage_ = true;
    endPage_ = endpage;
}

void PrintRange::SetPages(const std::vector<uint32_t> &pages)
{
    hasPages_ = true;
    pages_.assign(pages.begin(), pages.end());
}

void PrintRange::ReadFromParcel(Parcel &parcel)
{
    hasStartPage_ = parcel.ReadBool();
    if (hasStartPage_) {
        SetStartPage(parcel.ReadUint32());
    }

    hasEndPage_ = parcel.ReadBool();
    if (hasEndPage_) {
        SetEndPage(parcel.ReadUint32());
    }

    hasPages_ = parcel.ReadBool();
    if (hasPages_) {
        std::vector<uint32_t> pages;
        parcel.ReadUInt32Vector(&pages);
        if (pages.size() > 0) {
            SetPages(pages);
        }
    }
}

bool PrintRange::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(hasStartPage_);
    if (hasStartPage_) {
        parcel.WriteUint32(GetStartPage());
    }

    parcel.WriteBool(hasEndPage_);
    if (hasEndPage_) {
        parcel.WriteUint32(GetEndPage());
    }

    parcel.WriteBool(hasPages_);
    if (hasPages_ && !parcel.WriteUInt32Vector(pages_)) {
        PRINT_HILOGE("Failed to marshalling print range object");
        return false;
    }
    return true;
}

std::shared_ptr<PrintRange> PrintRange::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintRange>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintRange::Dump()
{
    if (hasStartPage_) {
        PRINT_HILOGD("startPage_ = %{public}d", startPage_);
    }

    if (hasEndPage_) {
        PRINT_HILOGD("endPage_ = %{public}d", endPage_);
    }

    if (hasPages_) {
        uint32_t pageLength = pages_.size();
        for (uint32_t i = 0; i < pageLength; i++) {
            PRINT_HILOGD("pages_ = %{public}d", pages_[i]);
        }
    }
}
} // namespace OHOS::Print
