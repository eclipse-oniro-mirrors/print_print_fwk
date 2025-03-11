/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "printer_preferences.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_json_util.h"

namespace OHOS::Print {
PrinterPreferences::PrinterPreferences()
    : hasDefaultDuplexMode_(false),
      defaultDuplexMode_(DUPLEX_MODE_NONE),
      hasDefaultPrintQuality_(false),
      defaultPrintQuality_(PRINT_QUALITY_NORMAL),
      hasDefaultMediaType_(false),
      defaultMediaType_(""),
      hasDefaultPageSizeId_(false),
      defaultPageSizeId_(""),
      hasDefaultOrientation_(false),
      defaultOrientation_(0),
      hasBorderless_(false),
      borderless_(false),
      hasOption_(false),
      option_("")
{
}

PrinterPreferences::PrinterPreferences(const PrinterPreferences &right)
    : hasDefaultDuplexMode_(right.hasDefaultDuplexMode_),
      defaultDuplexMode_(right.defaultDuplexMode_),
      hasDefaultPrintQuality_(right.hasDefaultPrintQuality_),
      defaultPrintQuality_(right.defaultPrintQuality_),
      hasDefaultMediaType_(right.hasDefaultMediaType_),
      defaultMediaType_(right.defaultMediaType_),
      hasDefaultPageSizeId_(right.hasDefaultPageSizeId_),
      defaultPageSizeId_(right.defaultPageSizeId_),
      hasDefaultOrientation_(right.hasDefaultOrientation_),
      defaultOrientation_(right.defaultOrientation_),
      hasBorderless_(right.hasBorderless_),
      borderless_(right.borderless_),
      hasOption_(right.hasOption_),
      option_(right.option_)
{
}

PrinterPreferences &PrinterPreferences::operator=(const PrinterPreferences &right)
{
    if (this != &right) {
        hasDefaultDuplexMode_ = right.hasDefaultDuplexMode_;
        defaultDuplexMode_ = right.defaultDuplexMode_;
        hasDefaultPrintQuality_ = right.hasDefaultPrintQuality_;
        defaultPrintQuality_ = right.defaultPrintQuality_;
        hasDefaultMediaType_ = right.hasDefaultMediaType_;
        defaultMediaType_ = right.defaultMediaType_;
        hasDefaultPageSizeId_ = right.hasDefaultPageSizeId_;
        defaultPageSizeId_ = right.defaultPageSizeId_;
        hasDefaultOrientation_ = right.hasDefaultOrientation_;
        defaultOrientation_ = right.defaultOrientation_;
        hasBorderless_ = right.hasBorderless_;
        borderless_ = right.borderless_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
    }
    return *this;
}

PrinterPreferences::~PrinterPreferences() {}

void PrinterPreferences::Reset()
{
    hasDefaultDuplexMode_ = false;
    defaultDuplexMode_ = DUPLEX_MODE_NONE;
    hasDefaultPrintQuality_ = false;
    defaultPrintQuality_ = PRINT_QUALITY_NORMAL;
    hasDefaultMediaType_ = false;
    defaultMediaType_ = "";
    hasDefaultPageSizeId_ = false;
    defaultPageSizeId_ = "";
    hasDefaultOrientation_ = false;
    defaultOrientation_ = PRINT_ORIENTATION_MODE_NONE;
    hasBorderless_ = false;
    borderless_ = false;
    hasOption_ = false;
    option_ = "";
}

void PrinterPreferences::SetDefaultDuplexMode(uint32_t defaultDuplexMode)
{
    hasDefaultDuplexMode_ = true;
    defaultDuplexMode_ = defaultDuplexMode;
}

void PrinterPreferences::SetDefaultPrintQuality(uint32_t defaultPrintQuality)
{
    hasDefaultPrintQuality_ = true;
    defaultPrintQuality_ = defaultPrintQuality;
}

void PrinterPreferences::SetDefaultMediaType(const std::string &defaultMediaType)
{
    hasDefaultMediaType_ = true;
    defaultMediaType_ = defaultMediaType;
}

void PrinterPreferences::SetDefaultPageSizeId(const std::string &defaultPageSizeId)
{
    hasDefaultPageSizeId_ = true;
    defaultPageSizeId_ = defaultPageSizeId;
}

void PrinterPreferences::SetDefaultOrientation(uint32_t defaultOrientation)
{
    hasDefaultOrientation_ = true;
    defaultOrientation_ = defaultOrientation;
}

void PrinterPreferences::SetBorderless(bool borderless)
{
    hasBorderless_ = true;
    borderless_ = borderless;
}

void PrinterPreferences::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

bool PrinterPreferences::HasDefaultDuplexMode() const
{
    return hasDefaultDuplexMode_;
}

uint32_t PrinterPreferences::GetDefaultDuplexMode() const
{
    return defaultDuplexMode_;
}

bool PrinterPreferences::HasDefaultPrintQuality() const
{
    return hasDefaultPrintQuality_;
}

uint32_t PrinterPreferences::GetDefaultPrintQuality() const
{
    return defaultPrintQuality_;
}

bool PrinterPreferences::HasDefaultMediaType() const
{
    return hasDefaultMediaType_;
}

const std::string &PrinterPreferences::GetDefaultMediaType() const
{
    return defaultMediaType_;
}

bool PrinterPreferences::HasDefaultPageSizeId() const
{
    return hasDefaultPageSizeId_;
}

const std::string &PrinterPreferences::GetDefaultPageSizeId() const
{
    return defaultPageSizeId_;
}

bool PrinterPreferences::HasDefaultOrientation() const
{
    return hasDefaultOrientation_;
}

uint32_t PrinterPreferences::GetDefaultOrientation() const
{
    return defaultOrientation_;
}

bool PrinterPreferences::HasBorderless() const
{
    return hasBorderless_;
}

bool PrinterPreferences::GetBorderless() const
{
    return borderless_;
}

bool PrinterPreferences::HasOption() const
{
    return hasOption_;
}

std::string PrinterPreferences::GetOption() const
{
    return option_;
}

bool PrinterPreferences::ReadFromParcel(Parcel &parcel)
{
    PrinterPreferences right;
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    right.hasDefaultDuplexMode_ = parcel.ReadBool();
    if (right.hasDefaultDuplexMode_) {
        right.SetDefaultDuplexMode(parcel.ReadUint32());
    }

    right.hasDefaultPrintQuality_ = parcel.ReadBool();
    if (right.hasDefaultPrintQuality_) {
        right.SetDefaultPrintQuality(parcel.ReadUint32());
    }

    right.hasDefaultMediaType_ = parcel.ReadBool();
    if (right.hasDefaultMediaType_) {
        right.SetDefaultMediaType(parcel.ReadString());
    }

    right.hasDefaultPageSizeId_ = parcel.ReadBool();
    if (right.hasDefaultPageSizeId_) {
        right.SetDefaultPageSizeId(parcel.ReadString());
    }

    right.hasDefaultOrientation_ = parcel.ReadBool();
    if (right.hasDefaultOrientation_) {
        right.SetDefaultOrientation(parcel.ReadUint32());
    }

    right.hasBorderless_ = parcel.ReadBool();
    if (right.hasBorderless_) {
        right.SetBorderless(parcel.ReadBool());
    }

    right.hasOption_ = parcel.ReadBool();
    if (right.hasOption_) {
        right.SetOption(parcel.ReadString());
    }

    *this = right;
    return true;
}

bool PrinterPreferences::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(hasDefaultDuplexMode_);
    if (hasDefaultDuplexMode_) {
        parcel.WriteUint32(GetDefaultDuplexMode());
    }

    parcel.WriteBool(hasDefaultPrintQuality_);
    if (hasDefaultPrintQuality_) {
        parcel.WriteUint32(GetDefaultPrintQuality());
    }

    parcel.WriteBool(hasDefaultMediaType_);
    if (hasDefaultMediaType_) {
        parcel.WriteString(GetDefaultMediaType());
    }

    parcel.WriteBool(hasDefaultPageSizeId_);
    if (hasDefaultPageSizeId_) {
        parcel.WriteString(GetDefaultPageSizeId());
    }

    parcel.WriteBool(hasDefaultOrientation_);
    if (hasDefaultOrientation_) {
        parcel.WriteUint32(GetDefaultOrientation());
    }

    parcel.WriteBool(hasBorderless_);
    if (hasBorderless_) {
        parcel.WriteBool(GetBorderless());
    }

    parcel.WriteBool(hasOption_);
    if (hasOption_) {
        parcel.WriteString(GetOption());
    }

    return true;
}

std::shared_ptr<PrinterPreferences> PrinterPreferences::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterPreferences>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrinterPreferences::Dump() const
{
    if (hasDefaultDuplexMode_) {
        PRINT_HILOGI("defaultDuplexMode: %{public}d", defaultDuplexMode_);
    }
    if (hasDefaultPrintQuality_) {
        PRINT_HILOGI("defaultPrintQuality: %{public}d", defaultPrintQuality_);
    }
    if (hasDefaultMediaType_) {
        PRINT_HILOGI("defaultMediaType: %{public}s", defaultMediaType_.c_str());
    }
    if (hasDefaultPageSizeId_) {
        PRINT_HILOGI("defaultPageSizeId: %{public}s", defaultPageSizeId_.c_str());
    }
    if (hasDefaultOrientation_) {
        PRINT_HILOGI("defaultOrientation: %{public}d", defaultOrientation_);
    }
    if (hasBorderless_) {
        PRINT_HILOGI("borderless: %{public}d", borderless_);
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
}

Json::Value PrinterPreferences::ConvertToJson()
{
    Json::Value preferencesJson;
    preferencesJson["defaultDuplexMode"] = defaultDuplexMode_;
    preferencesJson["defaultPrintQuality"] = defaultPrintQuality_;
    preferencesJson["defaultMediaType"] = defaultMediaType_;
    preferencesJson["defaultPageSizeId"] = defaultPageSizeId_;
    preferencesJson["defaultOrientation"] = defaultOrientation_;
    preferencesJson["borderless"] = borderless_;

    if (hasOption_) {
        if (!PrintJsonUtil::Parse(option_, preferencesJson["options"])) {
            PRINT_HILOGE("json accept preferences options fail");
        }
    }
    return preferencesJson;
}

void PrinterPreferences::ConvertJsonToPrinterPreferences(Json::Value &preferencesJson)
{
    if (preferencesJson.isMember("defaultDuplexMode") && preferencesJson["defaultDuplexMode"].isInt()) {
        SetDefaultDuplexMode(preferencesJson["defaultDuplexMode"].asInt());
    }

    if (preferencesJson.isMember("defaultPrintQuality") && preferencesJson["defaultPrintQuality"].isInt()) {
        SetDefaultPrintQuality(preferencesJson["defaultPrintQuality"].asInt());
    }

    if (preferencesJson.isMember("defaultMediaType") && preferencesJson["defaultMediaType"].isString()) {
        SetDefaultMediaType(preferencesJson["defaultMediaType"].asString());
    }

    if (preferencesJson.isMember("defaultPageSizeId") && preferencesJson["defaultPageSizeId"].isString()) {
        SetDefaultPageSizeId(preferencesJson["defaultPageSizeId"].asString());
    }

    if (preferencesJson.isMember("defaultOrientation") && preferencesJson["defaultOrientation"].isInt()) {
        SetDefaultOrientation(preferencesJson["defaultOrientation"].asInt());
    }

    if (preferencesJson.isMember("borderless") && preferencesJson["borderless"].isBool()) {
        SetBorderless(preferencesJson["borderless"].asBool());
    }

    if (preferencesJson.isMember("options") && preferencesJson["options"].isObject()) {
        PRINT_HILOGD("find options");
        SetOption(PrintJsonUtil::WriteString(preferencesJson["options"]));
    }
}
}  // namespace OHOS::Print