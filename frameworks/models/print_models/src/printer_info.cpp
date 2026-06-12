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
#include "print_utils.h"

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
      hasPreferences_(false),
      hasAlias_(false),
      alias_(""),
      hasOption_(false),
      option_(""),
      hasPrinterUuid_(false),
      printerUuid_(""),
      hasIsDefaultPrinter_(false),
      isDefaultPrinter_(false),
      hasIsLastUsedPrinter_(false),
      isLastUsedPrinter_(false),
      ppdHashCode_(""),
      hasSelectedDriver_(false),
      hasSelectedProtocol_(false),
      selectedProtocol_(""),
      hasOriginId_(false)
{
    capability_.Reset();
    preferences_.Reset();
    selectedDriver_.Reset();
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
      hasPreferences_(right.hasPreferences_),
      preferences_(right.preferences_),
      hasAlias_(right.hasAlias_),
      alias_(right.alias_),
      hasOption_(right.hasOption_),
      option_(right.option_),
      hasPrinterUuid_(right.hasPrinterUuid_),
      printerUuid_(right.printerUuid_),
      hasIsDefaultPrinter_(right.hasIsDefaultPrinter_),
      isDefaultPrinter_(right.isDefaultPrinter_),
      hasIsLastUsedPrinter_(right.hasIsLastUsedPrinter_),
      isLastUsedPrinter_(right.isLastUsedPrinter_),
      ppdHashCode_(right.ppdHashCode_),
      hasSelectedDriver_(right.hasSelectedDriver_),
      selectedDriver_(right.selectedDriver_),
      hasSelectedProtocol_(right.hasSelectedProtocol_),
      selectedProtocol_(right.selectedProtocol_),
      hasOriginId_(right.hasOriginId_),
      originId_(right.originId_)
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
        hasPreferences_ = right.hasPreferences_;
        preferences_ = right.preferences_;
        hasAlias_ = right.hasAlias_;
        alias_ = right.alias_;
        hasPrinterUuid_ = right.hasPrinterUuid_;
        printerUuid_ = right.printerUuid_;
        option_ = right.option_;
        hasIsDefaultPrinter_ = right.hasIsDefaultPrinter_;
        isDefaultPrinter_ = right.isDefaultPrinter_;
        hasIsLastUsedPrinter_ = right.hasIsLastUsedPrinter_;
        isLastUsedPrinter_ = right.isLastUsedPrinter_;
        hasPrinterStatus_ = right.hasPrinterStatus_;
        printerStatus_ = right.printerStatus_;
        ppdHashCode_ = right.ppdHashCode_;
        hasSelectedDriver_ = right.hasSelectedDriver_;
        selectedDriver_ = right.selectedDriver_;
        hasSelectedProtocol_ = right.hasSelectedProtocol_;
        selectedProtocol_ = right.selectedProtocol_;
        hasOriginId_ = right.hasOriginId_;
        originId_ = right.originId_;
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
    hasPrinterIcon_ = true;
    printerIcon_ = printIcon;
}

void PrinterInfo::SetPrinterState(uint32_t printerState)
{
    printerState_ = printerState;
}

void PrinterInfo::SetDescription(std::string description)
{
    hasDescription_ = true;
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

void PrinterInfo::SetPreferences(const PrinterPreferences &preferences)
{
    hasPreferences_ = true;
    preferences_ = preferences;
}

void PrinterInfo::SetAlias(const std::string &alias)
{
    hasAlias_ = true;
    alias_ = alias;
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
    isDefaultPrinter_ = isDefaultPrinter;
}

void PrinterInfo::SetIsLastUsedPrinter(bool isLastUsedPrinter)
{
    hasIsLastUsedPrinter_ = true;
    isLastUsedPrinter_ = isLastUsedPrinter;
}

void PrinterInfo::SetPrinterStatus(uint32_t printerStatus)
{
    hasPrinterStatus_ = true;
    printerStatus_ = printerStatus;
}

void PrinterInfo::SetPpdHashCode(const std::string &ppdHashCode)
{
    ppdHashCode_ = ppdHashCode;
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

bool PrinterInfo::HasPreferences() const
{
    return hasPreferences_;
}

void PrinterInfo::GetPreferences(PrinterPreferences &preferences) const
{
    preferences = preferences_;
}

bool PrinterInfo::HasAlias() const
{
    return hasAlias_;
}

std::string PrinterInfo::GetAlias() const
{
    return alias_;
}

std::string PrinterInfo::GetPpdHashCode() const
{
    return ppdHashCode_;
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

void PrinterInfo::SetSelectedDriver(const PpdInfo &selectedDriver)
{
    hasSelectedDriver_ = true;
    selectedDriver_ = selectedDriver;
}

bool PrinterInfo::HasSelectedDriver() const
{
    return hasSelectedDriver_;
}

void PrinterInfo::GetSelectedDriver(PpdInfo &ppdInfo) const
{
    ppdInfo = selectedDriver_;
}

void PrinterInfo::SetSelectedProtocol(const std::string &selectedProtocol)
{
    hasSelectedProtocol_ = true;
    selectedProtocol_ = selectedProtocol;
}

void PrinterInfo::SetOriginId(const std::string &originId)
{
    hasOriginId_ = true;
    originId_ = originId;
}

bool PrinterInfo::HasSelectedProtocol() const
{
    return hasSelectedProtocol_;
}

std::string PrinterInfo::GetSelectedProtocol() const
{
    return selectedProtocol_;
}

bool PrinterInfo::HasOriginId() const
{
    return hasOriginId_;
}

std::string PrinterInfo::GetOriginId() const
{
    return originId_;
}

bool PrinterInfo::ReadFromParcel(Parcel &parcel)
{
    PrinterInfo right;
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    if (!ReadBasicInfoFromParcel(right, parcel)) {
        return false;
    }
    if (!ReadCapabilityAndUriFromParcel(right, parcel)) {
        return false;
    }
    if (!ReadInnerPropertyFromParcel(right, parcel)) {
        return false;
    }
    right.Dump();
    *this = right;
    return true;
}

bool PrinterInfo::ReadBasicInfoFromParcel(PrinterInfo& right, Parcel& parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.printerId_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.printerName_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(right.printerState_), false);

    uint32_t iconId = PRINT_INVALID_ID;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasPrinterIcon_), false);
    if (right.hasPrinterIcon_) {
        uint32_t iconIdVal = 0;
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(iconIdVal), false);
        iconId = iconIdVal;
    }
    right.SetPrinterIcon(iconId);

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasDescription_), false);
    if (right.hasDescription_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.description_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasPrinterStatus_), false);
    if (right.hasPrinterStatus_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(right.printerStatus_), false);
    }
    return true;
}

bool PrinterInfo::ReadCapabilityAndUriFromParcel(PrinterInfo& right, Parcel& parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasCapability_), false);
    if (right.hasCapability_) {
        auto capPtr = PrinterCapability::Unmarshalling(parcel);
        if (capPtr == nullptr) {
            PRINT_HILOGE("failed to build capability from printer info");
            return false;
        }
        right.SetCapability(*capPtr);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasUri_), false);
    if (right.hasUri_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.uri_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasPrinterMake_), false);
    if (right.hasPrinterMake_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.printerMake_), false);
    }
    return true;
}

bool PrinterInfo::ReadInnerPropertyFromParcel(PrinterInfo& right, Parcel& parcel)
{
    if (!ReadDriverAndPrefsFromParcel(right, parcel)) {
        return false;
    }
    if (!ReadFlagsFromParcel(right, parcel)) {
        return false;
    }
    return true;
}

bool PrinterInfo::ReadDriverAndPrefsFromParcel(PrinterInfo& right, Parcel& parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasSelectedDriver_), false);
    if (right.hasSelectedDriver_) {
        auto ppdInfo = PpdInfo::Unmarshalling(parcel);
        if (ppdInfo == nullptr) {
            PRINT_HILOGE("failed to build ppdInfo from printer info");
            return false;
        }
        right.SetSelectedDriver(*ppdInfo);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasSelectedProtocol_), false);
    if (right.hasSelectedProtocol_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.selectedProtocol_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasPrinterUuid_), false);
    if (right.hasPrinterUuid_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.printerUuid_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasPreferences_), false);
    if (right.hasPreferences_) {
        auto preferencesPtr = PrinterPreferences::Unmarshalling(parcel);
        if (preferencesPtr == nullptr) {
            PRINT_HILOGE("failed to build preferences from printer info");
            return false;
        }
        right.SetPreferences(*preferencesPtr);
    }
    return true;
}

bool PrinterInfo::ReadFlagsFromParcel(PrinterInfo& right, Parcel& parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasAlias_), false);
    if (right.hasAlias_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.alias_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasOption_), false);
    if (right.hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.option_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasIsDefaultPrinter_), false);
    if (right.hasIsDefaultPrinter_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.isDefaultPrinter_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasIsLastUsedPrinter_), false);
    if (right.hasIsLastUsedPrinter_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.isLastUsedPrinter_), false);
    }
    return true;
}

bool PrinterInfo::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetPrinterId()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetPrinterName()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetPrinterState()), false);

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPrinterIcon_), false);
    if (hasPrinterIcon_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetPrinterIcon()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasDescription_), false);
    if (hasDescription_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetDescription()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPrinterStatus_), false);
    if (hasPrinterStatus_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetPrinterStatus()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasCapability_), false);
    if (hasCapability_) {
        if (!capability_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for capability_ failed");
            return false;
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasUri_), false);
    if (hasUri_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetUri()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPrinterMake_), false);
    if (hasPrinterMake_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetPrinterMake()), false);
    }

    return MarshallingInnerProperty(parcel);
}

bool PrinterInfo::MarshallingInnerProperty(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasSelectedDriver_), false);
    if (hasSelectedDriver_) {
        if (!selectedDriver_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for selectedDriver_ failed");
            return false;
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasSelectedProtocol_), false);
    if (hasSelectedProtocol_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetSelectedProtocol()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPrinterUuid_), false);
    if (hasPrinterUuid_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetPrinterUuid()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPreferences_), false);
    if (hasPreferences_) {
        if (!preferences_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for preferences_ failed");
            return false;
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasAlias_), false);
    if (hasAlias_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetAlias()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasOption_), false);
    if (hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetOption()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasIsDefaultPrinter_), false);
    if (hasIsDefaultPrinter_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(isDefaultPrinter_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasIsLastUsedPrinter_), false);
    if (hasIsLastUsedPrinter_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(isLastUsedPrinter_), false);
    }
    return true;
}

std::shared_ptr<PrinterInfo> PrinterInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterInfo>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
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
    if (hasPreferences_) {
        preferences_.Dump();
    }
    if (hasAlias_) {
        PRINT_HILOGD("alias: %{private}s", alias_.c_str());
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
    if (hasSelectedDriver_) {
        selectedDriver_.Dump();
    }
    if (hasSelectedProtocol_) {
        PRINT_HILOGD("selectedProtocol: %{public}s", selectedProtocol_.c_str());
    }
    DumpInnerInfo();
}

void PrinterInfo::DumpInnerInfo() const
{
    if (hasOriginId_) {
        PRINT_HILOGD("originId: %{private}s", originId_.c_str());
    }
}
void PrinterInfo::DumpInfo() const
{
    PRINT_HILOGI("printerId: %{public}s", PrintUtils::AnonymizePrinterId(printerId_).c_str());
    PRINT_HILOGI("printerName: %{public}s", printerName_.c_str());
    PRINT_HILOGI("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGI("printerState: %{public}d", printerState_);

    if (hasCapability_) {
        capability_.DumpInfo();
    }
    if (hasUri_) {
        PRINT_HILOGI("uri: %{public}s", uri_.c_str());
    }
    if (hasPrinterMake_) {
        PRINT_HILOGI("printerMake: %{public}s", printerMake_.c_str());
    }
    if (hasPreferences_) {
        preferences_.DumpInfo();
    }
}

void PrinterInfo::SetOptionField(const std::string &key, const std::string &value)
{
    if (key.empty()) {
        return;
    }
    Json::Value optionJson(Json::objectValue);
    if (HasOption()) {
        std::string option = GetOption();
        PrintJsonUtil::Parse(option, optionJson);
    }
    if (optionJson.isObject()) {
        optionJson[key] = value;
    }
    SetOption(PrintJsonUtil::WriteString(optionJson));
}

}  // namespace OHOS::Print
