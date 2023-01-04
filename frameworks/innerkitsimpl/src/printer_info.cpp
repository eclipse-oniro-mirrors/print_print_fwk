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
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_INFO_PRINTERID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState";
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";
static constexpr const char *PARAM_JOB_OPTION = "option";

PrinterInfo::PrinterInfo() : printerId_(""), printerName_(""), printerState_(PRINTER_UNKNOWN),
    printerIcon_(PRINT_INVALID_ID), description_(""), hasCapability_(false), hasOption_(false), option_("") {
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
        option_= right.option_;
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

void PrinterInfo::GetCapability(PrinterCapability &cap) const
{
    cap = capability_;
}

std::string PrinterInfo::GetOption() const
{
    return option_;
}

bool PrinterInfo::ReadFromParcel(Parcel &parcel)
{
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

    // check capability
    hasCapability_ = parcel.ReadBool();
    if (hasCapability_) {
        auto capPtr = PrinterCapability::Unmarshalling(parcel);
        if (capPtr == nullptr) {
            PRINT_HILOGE("failed to build capability from printer info");
            return false;
        }
        capability_ = *capPtr;
    }

    // check option
    hasOption_ = parcel.ReadBool();
    if (hasOption_) {
        SetOption(parcel.ReadString());
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
    return true;
}

std::shared_ptr<PrinterInfo> PrinterInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterInfo>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create printer info object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling printer info");
        return nullptr;
    }
    return nativeObj;
}
    
napi_value PrinterInfo::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_PRINTERID, GetPrinterId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_PRINTERNAME, GetPrinterName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_INFO_PRINTERSTATE, GetPrinterState());

    if (GetPrinterIcon() != PRINT_INVALID_ID) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_INFO_PRINTERICON, GetPrinterIcon());
    }
    
    if (GetDescription() != "") {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DESCRIPTION, GetDescription());
    }

    if (hasCapability_) {
        napi_value jsCapability = capability_.ToJsObject(env);
        PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_INFO_CAPABILITY, jsCapability));
    }

    if (hasOption_) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_OPTION, GetOption());
    }
    return jsObj;
}

std::shared_ptr<PrinterInfo> PrinterInfo::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterInfo>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create printer info object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of printer info");
        return nullptr;
    }

    std::string printerId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_PRINTERID);
    std::string printerName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_PRINTERNAME);
    if (printerId == "" || printerName == "") {
        PRINT_HILOGE("Invalid printer id[%{public}s] or printer name[%{public}s]",
            printerId.c_str(), printerName.c_str());
        return nullptr;
    }
    nativeObj->SetPrinterId(printerId);
    nativeObj->SetPrinterName(printerName);

    uint32_t printerState = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_INFO_PRINTERSTATE);
    if (printerState >= PRINTER_UNKNOWN) {
        PRINT_HILOGE("Invalid printer state");
        return nullptr;
    }
    nativeObj->SetPrinterState(printerState);

    auto jsIcon = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_PRINTERICON);
    if (jsIcon != nullptr) {
        nativeObj->SetPrinterIcon(NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_INFO_PRINTERICON));
    }

    auto jsDesc = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_DESCRIPTION);
    if (jsDesc != nullptr) {
        nativeObj->SetDescription(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_DESCRIPTION));
    }

    auto jsCapability = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_CAPABILITY);
    if (jsCapability != nullptr) {
        auto capabilityPtr = PrinterCapability::BuildFromJs(env, jsCapability);
        if (capabilityPtr == nullptr) {
            PRINT_HILOGE("Failed to build printer info object from js");
            return nullptr;
        }
        nativeObj->SetCapability(*capabilityPtr);
    }

    auto jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_OPTION));
    }
    return nativeObj;
}

bool PrinterInfo::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_INFO_PRINTERID, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERNAME, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERSTATE, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERICON, PRINT_PARAM_OPT},
        {PARAM_INFO_DESCRIPTION, PRINT_PARAM_OPT},
        {PARAM_INFO_CAPABILITY, PRINT_PARAM_OPT},
        {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
    };
    
    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    for (auto propertypItem : propertyList) {
        if (propertypItem.second == PRINT_PARAM_NOT_SET) {
            PRINT_HILOGE("Missing Property: %{public}s", propertypItem.first.c_str());
            return false;
        }
    }
    return true;
}

void PrinterInfo::Dump()
{
    PRINT_HILOGD("printerId: %{public}s", printerId_.c_str());
    PRINT_HILOGD("printerName: %{public}s", printerName_.c_str());
    PRINT_HILOGD("printerIcon: %{public}d", printerIcon_);
    PRINT_HILOGD("printerState: %{public}d", printerState_);
    if (description_ != "") {
        PRINT_HILOGD("description: %{public}s", description_.c_str());
    }
    PRINT_HILOGD("description: %{public}s", description_.c_str());
    if (hasCapability_) {
        capability_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{public}s", option_.c_str());
    }
}
} // namespace OHOS::Print