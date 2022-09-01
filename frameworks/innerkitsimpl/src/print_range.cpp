/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "log.h"

namespace OHOS::Print {
PrinterRange::PrinterRange()
{

}

PrinterRange::~PrinterRange()
{

}

void PrinterRange::SetStartPage(uint32_t startpage)
{
    startPage_ = startpage;
}

void PrinterRange::SetEndPage(uint32_t endpage)
{
    endPage_ = endpage;
}

void PrinterRange::SetPages(uint32_t pages)
{
    pages_.push_back(pages);
}

uint32_t PrinterRange::GetStartPage() const
{
    return startPage_;
}

uint32_t PrinterRange::GetEndPage() const
{
    return endPage_;
}

std::vector<uint32_t> &PrinterRange::GetPages()
{
    return pages_;
}

void PrinterRange::Dump()
{
    PRINT_HILOGD("startPage_ = %{public}d", startPage_);
    PRINT_HILOGD("endPage_ = %{public}d", endPage_);
    uint32_t pageLength = pages_.size();
    for(uint32_t i = 0; i < pageLength; i++)
    {
        PRINT_HILOGD("pages_ = %{public}d", pages_[i]);
    }
}
}

