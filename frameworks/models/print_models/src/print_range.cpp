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
#include "print_constant.h"
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

bool PrintRange::ReadFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasStartPage_), false);
    if (hasStartPage_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(startPage_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasEndPage_), false);
    if (hasEndPage_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(endPage_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasPages_), false);
    if (hasPages_) {
        std::vector<uint32_t> pages;
        if (!parcel.ReadUInt32Vector(&pages)) {
            PRINT_HILOGE("ReadUInt32Vector for pages failed");
            return false;
        }
        if (pages.size() > 0) {
            SetPages(pages);
        }
    }
    return true;
}

bool PrintRange::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasStartPage_), false);
    if (hasStartPage_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetStartPage()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasEndPage_), false);
    if (hasEndPage_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetEndPage()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPages_), false);
    if (hasPages_ && !parcel.WriteUInt32Vector(pages_)) {
        PRINT_HILOGE("Failed to marshalling print range object");
        return false;
    }
    return true;
}

std::shared_ptr<PrintRange> PrintRange::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintRange>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
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

Json::Value PrintRange::ConvertToJsonObject() const
{
    Json::Value pageRangeJson;
    pageRangeJson["hasStartPage_"] = hasStartPage_;
    if (hasStartPage_) {
        pageRangeJson["startPage"] = startPage_;
    }
    pageRangeJson["hasEndPage_"] = hasEndPage_;
    if (hasEndPage_) {
        pageRangeJson["endPage"] = endPage_;
    }
    std::vector<uint32_t> pages_;
    if (HasPages()) {
        GetPages(pages_);
        Json::Value jsonArray;
        for (const auto& item : pages_) {
            jsonArray.append(item);
        }
        pageRangeJson["pages"] = jsonArray;
    }
    return pageRangeJson;
}
} // namespace OHOS::Print
