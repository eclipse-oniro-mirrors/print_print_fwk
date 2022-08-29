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

#include "print_cap_ability.h"
#include "log.h"

namespace OHOS::Print {
PrinterCapability::PrinterCapability ()
    : colorMode_(1), duplexMode_(1) {
    
}

void PrinterCapability::SetMinMargin(PrintMargin &minMargin)
{
    minMargin_ = minMargin;
}

void PrinterCapability::SetPageSize(PrinterPageSize pageSize)
{
    pageSize_.push_back(pageSize);
}

void PrinterCapability::SetResolution(PrinterResolution resolution)
{
    resolution_.push_back(resolution);
}

void PrinterCapability::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}

void PrinterCapability::SetDuplexMode(uint32_t duplexMode)
{
    duplexMode_ = duplexMode;
}

PrintMargin &PrinterCapability::GetMinMargin()
{
    return minMargin_;
}

std::vector<PrinterPageSize> &PrinterCapability::GetPageSize()
{
    return pageSize_;
}

std::vector<PrinterResolution> &PrinterCapability::GetResolution()
{
    return resolution_;
}

uint32_t PrinterCapability::GetColorMode()
{
    return colorMode_;
}

uint32_t PrinterCapability::GetDuplexMode()
{
    return duplexMode_;
}

void PrinterCapability::Dump()
{
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);
}

PrinterCapability ::~PrinterCapability ()
{

}

} // namespace OHOS::Print
