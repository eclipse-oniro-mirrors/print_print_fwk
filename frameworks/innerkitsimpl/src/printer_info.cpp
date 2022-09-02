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

#include "printer_info.h"
#include "print_log.h"
#include "print_constant.h"

namespace OHOS::Print {
PrinterInfo::PrinterInfo() : printerId_(0), printerName_(""), printerIcon_(0), printerState_(PRINTER_UNKNOWN), description_("")
{
}

PrinterInfo::PrinterInfo(const PrinterInfo& right)
{
    printerId_ = right.printerId_;
    printerName_ = right.printerName_;
    printerState_ = right.printerState_;
    description_ = right.description_;
    capability_ =  right.capability_;
}

PrinterInfo& PrinterInfo::operator=(PrinterInfo &right)
{
    if(this != &right) {
        printerId_ = right.printerId_;
        printerName_ = right.printerName_;
        printerState_ = right.printerState_;
        description_ = right.description_;
        capability_ =  right.capability_;
    }
    return *this;
}

PrinterInfo::~PrinterInfo()
{
}

void PrinterInfo::SetPrinterId(uint32_t printerId)
{
    printerId_ = printerId;
}
void PrinterInfo::SetPrinterName(std::string printerName)
{
    printerName_ = printerName;
}
void PrinterInfo::SetPrinterIcon(uint32_t printIcon)
{
    printerIcon_ = printIcon;
}
void PrinterInfo::SetPrinterState(uint32_t printerState)
{
    printerState_ = printerState;
}
void PrinterInfo::SetDescription(std::string description)
{
    description_ = description;
}
void PrinterInfo::SetCapability(PrinterCapability capability)
{
    capability_ = capability;
}

uint32_t PrinterInfo::GetPrintId() const
{
    return printerId_;
}

const std::string& PrinterInfo::GetPrinterName() const
{
    return printerName_;
}

uint32_t PrinterInfo::GetPrinterIcon() const
{
    return printerIcon_;
}

uint32_t PrinterInfo::GetPrinterState() const
{
    return printerState_;
}

const std::string& PrinterInfo::GetDescription() const
{
    return description_;
}

void PrinterInfo::GetCapability(PrinterCapability& cap) const
{
    cap = capability_;
}

void PrinterInfo::Dump()
{
    PRINT_HILOGD("printerId: %{public}d", printerId_);
    PRINT_HILOGD("printerName: %{public}s", printerName_.c_str());
    PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGD("printerState: %{public}d", printerState_);
    PRINT_HILOGD("description: %{public}s", description_.c_str());
    capability_.Dump();
}
} // namespace OHOS::Print