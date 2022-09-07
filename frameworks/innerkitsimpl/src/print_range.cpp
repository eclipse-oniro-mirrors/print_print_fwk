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
PrintRange::PrintRange() : startPage_(0), endPage_(0)
{
    pages_.clear();
}

PrintRange::PrintRange(const PrintRange &right)
{
    startPage_ = right.startPage_;
    endPage_ = right.endPage_;
    pages_.clear();
    pages_.assign(right.pages_.begin(), right.pages_.end());
}

PrintRange &PrintRange::operator=(const PrintRange &right)
{
    if (this != &right) {
        startPage_ = right.startPage_;
        endPage_ = right.endPage_;
        pages_.clear();
        pages_.assign(right.pages_.begin(), right.pages_.end());
    }
    return *this;
}

PrintRange::~PrintRange()
{
    pages_.clear();
}

void PrintRange::SetStartPage(uint32_t startpage)
{
    startPage_ = startpage;
}

void PrintRange::SetEndPage(uint32_t endpage)
{
    endPage_ = endpage;
}

void PrintRange::SetPages(const std::vector<uint32_t> &pages)
{
    pages_.clear();
    pages_.assign(pages.begin(), pages.end());
}

void PrintRange::Reset()
{
    startPage_ = 0;
    endPage_ = 0;
    pages_.clear();
}

uint32_t PrintRange::GetStartPage() const
{
    return startPage_;
}

uint32_t PrintRange::GetEndPage() const
{
    return endPage_;
}

void PrintRange::GetPages(std::vector<uint32_t> &pages) const
{
    pages.clear();
    pages.assign(pages_.begin(), pages_.end());
}

void PrintRange::Dump()
{
    PRINT_HILOGD("startPage_ = %{public}d", startPage_);
    PRINT_HILOGD("endPage_ = %{public}d", endPage_);
    uint32_t pageLength = pages_.size();
    for (uint32_t i = 0; i < pageLength; i++) {
        PRINT_HILOGD("pages_ = %{public}d", pages_[i]);
    }
}
} // namespace OHOS::Print
