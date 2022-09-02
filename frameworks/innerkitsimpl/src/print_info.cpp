/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "print_info.h"
#include "log.h"
#include "constant.h"

namespace OHOS::Print {
PrintInfo::PrintInfo()
    : printerId_(0), printerName_(""), printerIcon_(0), printerState_(ERROR_UNKNOWN), description_("") {
}

void PrintInfo::SetPrinterId(uint32_t printerId)
{
    printerId_ = printerId;
}
void PrintInfo::SetPrinterName(std::string printerName)
{
    printerName_ = printerName;
}
void PrintInfo::SetPrinterIcon(uint32_t printIcon)
{
    printerIcon_ = printIcon;
}
void PrintInfo::SetPrinterState(uint32_t printerState)
{
    printerState_ = printerState;
}
void PrintInfo::SetDescription(std::string description)
{
    description_ = description;
}
void PrintInfo::SetCapability(PrinterCapability capability)
{
    capability_ = capability;
}

uint32_t PrintInfo::GetPrintId() const
{
    return printerId_;
}
std::string &PrintInfo::GetPrinterName()
{
    return printerName_;
}

uint32_t PrintInfo::GetPrinterIcon() const
{
    return printerIcon_;
}
uint32_t PrintInfo::GetPrinterState() const
{
    return printerState_;
}
std::string &PrintInfo::GetDescription()
{
    return description_;
}
PrinterCapability &PrintInfo::GetCapability()
{
    return capability_;
}

void PrintInfo::Dump()
{
    PRINT_HILOGD("printerId: %{public}d", printerId_);
    PRINT_HILOGD("printerName: %{public}s", printerName_.c_str());
    PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGD("printerState: %{public}d", printerState_);
    PRINT_HILOGD("description: %{public}s", description_.c_str());
}
} // namespace OHOS::Print