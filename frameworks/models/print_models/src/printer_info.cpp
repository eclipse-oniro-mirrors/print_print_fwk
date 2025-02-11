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
    : printerId_(""),
      printerName_(""),
      printerState_(PRINTER_UNKNOWN),
      hasPrinterIcon_(false),
      printerIcon_(PRINT_INVALID_ID),
      hasDescription_(false),
      description_(""),
      hasPrinterStatus_(false),
      printerStatus_(PRINTER_STATUS_UNAVAILABLE),
      hasCapability_(false),
      hasUri_(false),
      uri_(""),
      hasPrinterMake_(false),
      printerMake_(""),
      hasOption_(false),
      option_(""),
      hasPrinterUuid_(false),
      printerUuid_(""),
      hasIsDefaultPrinter_(false),
      isDefaultPrinter_(false),
      hasIsLastUsedPrinter_(false),
      isLastUsedPrinter_(false)
{
    capability_.Reset();
}

PrinterInfo::PrinterInfo(const PrinterInfo &right)
    : printerId_(right.printerId_),
      printerName_(right.printerName_),
      printerState_(right.printerState_),
      hasPrinterIcon_(right.hasPrinterIcon_),
      printerIcon_(right.printerIcon_),
      hasDescription_(right.hasDescription_),
      description_(right.description_),
      hasPrinterStatus_(right.hasPrinterStatus_),
      printerStatus_(right.printerStatus_),
      hasCapability_(right.hasCapability_),
      capability_(right.capability_),
      hasUri_(right.hasUri_),
      uri_(right.uri_),
      hasPrinterMake_(right.hasPrinterMake_),
      printerMake_(right.printerMake_),
      hasOption_(right.hasOption_),
      option_(right.option_),
      hasPrinterUuid_(right.hasPrinterUuid_),
      printerUuid_(right.printerUuid_),
      hasIsDefaultPrinter_(right.hasIsDefaultPrinter_),
      isDefaultPrinter_(right.isDefaultPrinter_),
      hasIsLastUsedPrinter_(right.hasIsLastUsedPrinter_),
      isLastUsedPrinter_(right.isLastUsedPrinter_)
{
}
PrinterInfo &PrinterInfo::operator=(const PrinterInfo &right)
{
    if (this != &right) {
        printerId_ = right.printerId_;
        printerName_ = right.printerName_;
        printerState_ = right.printerState_;
        hasPrinterIcon_ = right.hasPrinterIcon_;
        printerIcon_ = right.printerIcon_;
        hasDescription_ = right.hasDescription_;
        description_ = right.description_;
        hasCapability_ = right.hasCapability_;
        capability_ = right.capability_;
        hasOption_ = right.hasOption_;
        hasUri_ = right.hasUri_;
        uri_ = right.uri_;
        hasPrinterMake_ = right.hasPrinterMake_;
        printerMake_ = right.printerMake_;
        hasPrinterUuid_ = right.hasPrinterUuid_,
        printerUuid_ = right.printerUuid_,
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

PrinterInfo::~PrinterInfo() {}

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

void PrinterInfo::SetUri(const std::string &uri)
{
    hasUri_ = true;
    uri_ = uri;
}

void PrinterInfo::SetPrinterMake(const std::string &printerMake)
{
    hasPrinterMake_ = true;
    printerMake_ = printerMake;
}

void PrinterInfo::SetPrinterUuid(const std::string &printerUuid)
{
    hasPrinterUuid_ = true;
    printerUuid_ = printerUuid;
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

bool PrinterInfo::HasUri() const
{
    return hasUri_;
}

std::string PrinterInfo::GetUri() const
{
    return uri_;
}

bool PrinterInfo::HasPrinterMake() const
{
    return hasPrinterMake_;
}

std::string PrinterInfo::GetPrinterMake() const
{
    return printerMake_;
}

bool PrinterInfo::HasPrinterUuid() const
{
    return hasPrinterUuid_;
}

std::string PrinterInfo::GetPrinterUuid() const
{
    return printerUuid_;
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
    PrinterInfo right;
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    right.SetPrinterId(parcel.ReadString());
    right.SetPrinterName(parcel.ReadString());
    right.SetPrinterState(parcel.ReadUint32());

    uint32_t iconId = PRINT_INVALID_ID;
    right.hasPrinterIcon_ = parcel.ReadBool();
    if (right.hasPrinterIcon_) {
        iconId = parcel.ReadUint32();
    }
    right.SetPrinterIcon(iconId);

    right.hasDescription_ = parcel.ReadBool();
    if (right.hasDescription_) { right.SetDescription(parcel.ReadString()); }

    right.hasPrinterStatus_ = parcel.ReadBool();
    if (right.hasPrinterStatus_) { right.SetPrinterStatus(parcel.ReadUint32()); }

    right.hasCapability_ = parcel.ReadBool();
    if (right.hasCapability_) {
        auto capPtr = PrinterCapability::Unmarshalling(parcel);
        if (capPtr == nullptr) {
            PRINT_HILOGE("failed to build capability from printer info");
            return false;
        }
        right.SetCapability(*capPtr);
    }

    right.hasUri_ = parcel.ReadBool();
    if (right.hasUri_) { right.SetUri(parcel.ReadString()); }

    right.hasPrinterMake_ = parcel.ReadBool();
    if (right.hasPrinterMake_) { right.SetPrinterMake(parcel.ReadString()); }

    right.hasPrinterUuid_ = parcel.ReadBool();
    if (right.hasPrinterUuid_) { right.SetPrinterUuid(parcel.ReadString()); }

    right.hasOption_ = parcel.ReadBool();
    if (right.hasOption_) { right.SetOption(parcel.ReadString()); }
    ReadInnerPropertyFromParcel(right, parcel);

    right.Dump();
    *this = right;
    return true;
}

void PrinterInfo::ReadInnerPropertyFromParcel(PrinterInfo& right, Parcel& parcel)
{
    right.hasIsDefaultPrinter_ = parcel.ReadBool();
    if (right.hasIsDefaultPrinter_) {
        right.isDefaultPrinter_ = parcel.ReadBool();
    }

    right.hasIsLastUsedPrinter_ = parcel.ReadBool();
    if (right.hasIsLastUsedPrinter_) {
        right.isLastUsedPrinter_ = parcel.ReadBool();
    }
}

bool PrinterInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetPrinterId());
    parcel.WriteString(GetPrinterName());
    parcel.WriteUint32(GetPrinterState());

    parcel.WriteBool(hasPrinterIcon_);
    if (hasPrinterIcon_) {
        parcel.WriteUint32(GetPrinterIcon());
    }

    parcel.WriteBool(hasDescription_);
    if (hasDescription_) {
        parcel.WriteString(GetDescription());
    }

    parcel.WriteBool(hasPrinterStatus_);
    if (hasPrinterStatus_) {
        parcel.WriteUint32(GetPrinterStatus());
    }

    parcel.WriteBool(hasCapability_);
    if (hasCapability_) {
        capability_.Marshalling(parcel);
    }

    parcel.WriteBool(hasUri_);
    if (hasUri_) {
        parcel.WriteString(GetUri());
    }

    parcel.WriteBool(hasPrinterMake_);
    if (hasPrinterMake_) {
        parcel.WriteString(GetPrinterMake());
    }

    parcel.WriteBool(hasPrinterUuid_);
    if (hasPrinterUuid_) {
        parcel.WriteString(GetPrinterUuid());
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

    return true;
}

std::shared_ptr<PrinterInfo> PrinterInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterInfo>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrinterInfo::Dump() const
{
    PRINT_HILOGD("printerId: %{private}s", printerId_.c_str());
    PRINT_HILOGD("printerName: %{private}s", printerName_.c_str());
    PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGD("printerState: %{public}d", printerState_);

    if (hasPrinterIcon_) {
        PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    }
    if (hasDescription_) {
        PRINT_HILOGD("description: %{private}s", description_.c_str());
    }
    if (hasPrinterStatus_) {
        PRINT_HILOGD("printerStatus: %{public}d", printerStatus_);
    }
    if (hasCapability_) {
        capability_.Dump();
    }
    if (hasUri_) {
        PRINT_HILOGD("uri: %{private}s", uri_.c_str());
    }
    if (hasPrinterMake_) {
        PRINT_HILOGD("printerMake: %{private}s", printerMake_.c_str());
    }
    if (hasPrinterUuid_) {
        PRINT_HILOGD("printerUuid: %{private}s", printerUuid_.c_str());
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
}
}  // namespace OHOS::Print