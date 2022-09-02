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

#include "printer_capability.h"

#include "print_log.h"

namespace OHOS::Print {
PrinterCapability::PrinterCapability() : minMargin_(), colorMode_(0), duplexMode_(0)
{
    pageSizeList_.clear();
    resolutionList_.clear();
}

PrinterCapability::PrinterCapability(const PrinterCapability &right)
{
    minMargin_ = right.minMargin_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    SetPageSize(right.pageSizeList_);
    SetResolution(right.resolutionList_);
}

PrinterCapability &PrinterCapability::operator=(const PrinterCapability &right)
{
    if (this != &right) {
        minMargin_ = right.minMargin_;
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        SetPageSize(right.pageSizeList_);
        SetResolution(right.resolutionList_);
    }
    return *this;
}

PrinterCapability::~PrinterCapability() {}

void PrinterCapability::SetMinMargin(PrintMargin &minMargin)
{
    minMargin_ = minMargin;
}

void PrinterCapability::SetPageSize(const std::vector<PrintPageSize> &pageSizeList)
{
    pageSizeList_.clear();
    pageSizeList_.assign(pageSizeList.begin(), pageSizeList.end());
}

void PrinterCapability::SetResolution(const std::vector<PrintResolution> &resolutionList)
{
    resolutionList_.clear();
    resolutionList_.assign(resolutionList.begin(), resolutionList.end());
}

void PrinterCapability::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}

void PrinterCapability::SetDuplexMode(uint32_t duplexMode)
{
    duplexMode_ = duplexMode;
}

void PrinterCapability::GetMinMargin(PrintMargin &margin) const
{
    margin = minMargin_;
}

void PrinterCapability::GetPageSize(std::vector<PrintPageSize> &pageSizeList) const
{
    pageSizeList.clear();
    pageSizeList.assign(pageSizeList_.begin(), pageSizeList_.end());
}

void PrinterCapability::GetResolution(std::vector<PrintResolution> &resolutionList) const
{
    resolutionList.clear();
    resolutionList.assign(resolutionList_.begin(), resolutionList_.end());
}

uint32_t PrinterCapability::GetColorMode() const
{
    return colorMode_;
}

uint32_t PrinterCapability::GetDuplexMode() const
{
    return duplexMode_;
}

void PrinterCapability::Dump()
{
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);
    minMargin_.Dump();
    auto pageIt = pageSizeList_.begin();
    while (pageIt != pageSizeList_.end()) {
        pageIt->Dump();
        pageIt++;
    }

    auto resIt = resolutionList_.begin();
    while (resIt != resolutionList_.end()) {
        resIt->Dump();
        resIt++;
    }
}
} // namespace OHOS::Print
