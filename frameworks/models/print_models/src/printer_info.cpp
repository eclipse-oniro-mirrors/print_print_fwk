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

#include "printer_info.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrinterInfo::PrinterInfo()
    : printerId_(""), printerName_(""), printerState_(PRINTER_UNKNOWN), printerIcon_(PRINT_INVALID_ID),
      description_(""), hasCapability_(false), hasOption_(false), option_(""), hasIsDefaultPrinter_(false),
      isDefaultPrinter_(false), hasIsLastUsedPrinter_(false), isLastUsedPrinter_(false), hasPrinterStatus_(false),
      printerStatus_(PRINTER_STATUS_UNAVAILABLE)
{
    capability_.Reset();
}

PrinterInfo::PrinterInfo(const PrinterInfo &right)
{
    printerId_ = right.printerId_;
    printerName_ = right.printerName_;
    printerState_ = right.printerState_;
    printerIcon_ = right.printerIcon_;
    description_ = right.description_;
    hasCapability_ = right.hasCapability_;
    capability_ = right.capability_;
    hasOption_ = right.hasOption_;
    option_= right.option_;
    hasIsDefaultPrinter_ = right.hasIsDefaultPrinter_;
    isDefaultPrinter_ = right.isDefaultPrinter_;
    hasIsLastUsedPrinter_ = right.hasIsLastUsedPrinter_;
    isLastUsedPrinter_ = right.isLastUsedPrinter_;
    hasPrinterStatus_ = right.hasPrinterStatus_;
    printerStatus_ = right.printerStatus_;
}

PrinterInfo &PrinterInfo::operator=(const PrinterInfo &right)
{
    if (this != &right) {
        printerId_ = right.printerId_;
        printerName_ = right.printerName_;
        printerState_ = right.printerState_;
        printerIcon_ = right.printerIcon_;
        description_ = right.description_;
        hasCapability_ = right.hasCapability_;
        capability_ = right.capability_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
        hasIsDefaultPrinter_ = right.hasIsDefaultPrinter_;
        isDefaultPrinter_ = right.isDefaultPrinter_;
        hasIsLastUsedPrinter_ = right.hasIsLastUsedPrinter_;
        isLastUsedPrinter_ = right.isLastUsedPrinter_;
        hasPrinterStatus_ = right.hasPrinterStatus_;
        printerStatus_ = right.printerStatus_;
    }
    return *this;
}

PrinterInfo::~PrinterInfo()
{
}

void PrinterInfo::SetPrinterId(const std::string &printerId)
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

void PrinterInfo::SetCapability(const PrinterCapability &capability)
{
    hasCapability_ = true;
    capability_ = capability;
}

void PrinterInfo::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

void PrinterInfo::SetIsDefaultPrinter(bool isDefaultPrinter)
{
    hasIsDefaultPrinter_ = true;
    isDefaultPrinter_ = true;
}

void PrinterInfo::SetIsLastUsedPrinter(bool isLastUsedPrinter)
{
    hasIsLastUsedPrinter_ = true;
    isLastUsedPrinter_ = true;
}

void PrinterInfo::SetPrinterStatus(uint32_t printerStatus)
{
    hasPrinterStatus_ = true;
    printerStatus_ = printerStatus;
}

const std::string &PrinterInfo::GetPrinterId() const
{
    return printerId_;
}

const std::string &PrinterInfo::GetPrinterName() const
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

const std::string &PrinterInfo::GetDescription() const
{
    return description_;
}

bool PrinterInfo::HasCapability() const
{
    return hasCapability_;
}

void PrinterInfo::GetCapability(PrinterCapability &cap) const
{
    cap = capability_;
}

bool PrinterInfo::HasOption() const
{
    return hasOption_;
}

std::string PrinterInfo::GetOption() const
{
    return option_;
}

bool PrinterInfo::HasIsDefaultPrinter() const
{
    return hasIsDefaultPrinter_;
}

bool PrinterInfo::GetIsDefaultPrinter() const
{
    return isDefaultPrinter_;
}

bool PrinterInfo::HasIsLastUsedPrinter() const
{
    return hasIsLastUsedPrinter_;
}

bool PrinterInfo::GetIsLastUsedPrinter() const
{
    return isLastUsedPrinter_;
}

bool PrinterInfo::HasPrinterStatus() const
{
    return hasPrinterStatus_;
}

uint32_t PrinterInfo::GetPrinterStatus() const
{
    return printerStatus_;
}

bool PrinterInfo::ReadFromParcel(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    SetPrinterId(parcel.ReadString());
    SetPrinterName(parcel.ReadString());
    SetPrinterState(parcel.ReadUint32());

    uint32_t iconId = PRINT_INVALID_ID;
    if (parcel.ReadBool()) {
        iconId = parcel.ReadUint32();
    }
    SetPrinterIcon(iconId);

    std::string desc = "";
    if (parcel.ReadBool()) {
        desc = parcel.ReadString();
    }
    SetDescription(desc);

    hasCapability_ = parcel.ReadBool();
    if (hasCapability_) {
        auto capPtr = PrinterCapability::Unmarshalling(parcel);
        if (capPtr == nullptr) {
            PRINT_HILOGE("failed to build capability from printer info");
            return false;
        }
        capability_ = *capPtr;
    }

    hasOption_ = parcel.ReadBool();
    if (hasOption_) {
        SetOption(parcel.ReadString());
    }

    hasIsDefaultPrinter_ = parcel.ReadBool();
    if (hasIsDefaultPrinter_) {
        isDefaultPrinter_ = parcel.ReadBool();
    }

    hasIsLastUsedPrinter_ = parcel.ReadBool();
    if (hasIsLastUsedPrinter_) {
        isLastUsedPrinter_ = parcel.ReadBool();
    }

    hasPrinterStatus_ = parcel.ReadBool();
    PRINT_HILOGD("hasPrinterStatus_: %{public}d", hasPrinterStatus_);
    if (hasPrinterStatus_) {
        SetPrinterStatus(parcel.ReadUint32());
        PRINT_HILOGD("GetPrinterStatus(): %{public}d", GetPrinterStatus());
    }

    return true;
}

bool PrinterInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetPrinterId());
    parcel.WriteString(GetPrinterName());
    parcel.WriteUint32(GetPrinterState());

    if (GetPrinterIcon() != PRINT_INVALID_ID) {
        parcel.WriteBool(true);
        parcel.WriteUint32(GetPrinterIcon());
    } else {
        parcel.WriteBool(false);
    }

    if (GetDescription() != "") {
        parcel.WriteBool(true);
        parcel.WriteString(GetDescription());
    } else {
        parcel.WriteBool(false);
    }

    parcel.WriteBool(hasCapability_);
    if (hasCapability_) {
        capability_.Marshalling(parcel);
    }

    parcel.WriteBool(hasOption_);
    if (hasOption_) {
        parcel.WriteString(GetOption());
    }

    parcel.WriteBool(hasIsDefaultPrinter_);
    if (hasIsDefaultPrinter_) {
        parcel.WriteBool(isDefaultPrinter_);
    }

    parcel.WriteBool(hasIsLastUsedPrinter_);
    if (hasIsLastUsedPrinter_) {
        parcel.WriteBool(isLastUsedPrinter_);
    }

    parcel.WriteBool(hasPrinterStatus_);
    PRINT_HILOGD("hasPrinterStatus_: %{public}d", hasPrinterStatus_);
    if (hasPrinterStatus_) {
        PRINT_HILOGD("GetPrinterStatus(): %{public}d", GetPrinterStatus());
        parcel.WriteUint32(GetPrinterStatus());
    }
    return true;
}

std::shared_ptr<PrinterInfo> PrinterInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterInfo>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrinterInfo::Dump()
{
    PRINT_HILOGD("printerId: %{private}s", printerId_.c_str());
    PRINT_HILOGD("printerName: %{private}s", printerName_.c_str());
    PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGD("printerState: %{public}d", printerState_);
    if (description_ != "") {
        PRINT_HILOGD("description: %{private}s", description_.c_str());
    }
    PRINT_HILOGD("description: %{private}s", description_.c_str());
    if (hasCapability_) {
        capability_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
    if (hasIsDefaultPrinter_) {
        PRINT_HILOGD("isDefaultPrinter: %{public}d", isDefaultPrinter_);
    }
    if (hasIsLastUsedPrinter_) {
        PRINT_HILOGD("isLastUsedPrinter: %{public}d", isLastUsedPrinter_);
    }
    if (hasPrinterStatus_) {
        PRINT_HILOGD("printerStatus: %{public}d", printerStatus_);
    }
}
}  // namespace OHOS::Print