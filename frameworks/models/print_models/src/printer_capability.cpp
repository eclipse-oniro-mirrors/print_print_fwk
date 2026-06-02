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
#include "print_constant.h"
#include "print_log.h"
#include "print_utils.h"
#include "print_json_util.h"
#include <sstream>

namespace OHOS::Print {
PrinterCapability::PrinterCapability()
    : colorMode_(0), duplexMode_(0), hasResolution_(false), hasSupportedColorMode_(false),
      hasSupportedDuplexMode_(false), hasSupportedMediaType_(false), hasSupportedQuality_(false),
      hasSupportedOrientation_(false), hasMargin_(false), hasOption_(false), option_(""),
      hasVendorPrinterPrefAbility_(false), hasVendorJobAttrAbility_(false)
{
    pageSizeList_.clear();
    resolutionList_.clear();
    minMargin_.Reset();
    supportedPageSizeList_.clear();
    supportedColorModeList_.clear();
    supportedDuplexModeList_.clear();
    supportedMediaTypeList_.clear();
    supportedQualityList_.clear();
    supportedOrientationList_.clear();
    printerAttr_group.clear();
}

PrinterCapability::PrinterCapability(const PrinterCapability &right)
{
    *this = right;
}

PrinterCapability &PrinterCapability::operator=(const PrinterCapability &right)
{
    if (this != &right) {
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        pageSizeList_.assign(right.pageSizeList_.begin(), right.pageSizeList_.end());
        hasResolution_ = right.hasResolution_;
        resolutionList_.assign(right.resolutionList_.begin(), right.resolutionList_.end());
        hasMargin_ = right.hasMargin_;
        minMargin_ = right.minMargin_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
        hasSupportedColorMode_ = right.hasSupportedColorMode_;
        hasSupportedDuplexMode_ = right.hasSupportedDuplexMode_;
        hasSupportedMediaType_ = right.hasSupportedMediaType_;
        hasSupportedQuality_ = right.hasSupportedQuality_;
        hasSupportedOrientation_ = right.hasSupportedOrientation_;
        supportedPageSizeList_.assign(right.supportedPageSizeList_.begin(), right.supportedPageSizeList_.end());
        supportedColorModeList_.assign(right.supportedColorModeList_.begin(), right.supportedColorModeList_.end());
        supportedDuplexModeList_.assign(right.supportedDuplexModeList_.begin(), right.supportedDuplexModeList_.end());
        supportedMediaTypeList_.assign(right.supportedMediaTypeList_.begin(), right.supportedMediaTypeList_.end());
        supportedQualityList_.assign(right.supportedQualityList_.begin(), right.supportedQualityList_.end());
        supportedOrientationList_.assign(
            right.supportedOrientationList_.begin(), right.supportedOrientationList_.end());
        hasVendorPrinterPrefAbility_ = right.hasVendorPrinterPrefAbility_;
        vendorPrinterPrefAbility_ = right.vendorPrinterPrefAbility_;
        hasVendorJobAttrAbility_ = right.hasVendorJobAttrAbility_;
        vendorJobAttrAbility_ = right.vendorJobAttrAbility_;
    }
    return *this;
}

PrinterCapability::~PrinterCapability()
{}

void PrinterCapability::Reset()
{
    SetColorMode(0);
    SetDuplexMode(0);
    pageSizeList_.clear();
    hasResolution_ = false;
    resolutionList_.clear();
    hasMargin_ = false;
    minMargin_.Reset();
    hasSupportedColorMode_ = false;
    hasSupportedDuplexMode_ = false;
    hasSupportedMediaType_ = false;
    hasSupportedQuality_ = false;
    hasSupportedOrientation_ = false;
    supportedPageSizeList_.clear();
    supportedColorModeList_.clear();
    supportedDuplexModeList_.clear();
    supportedMediaTypeList_.clear();
    supportedQualityList_.clear();
    supportedOrientationList_.clear();
    hasVendorPrinterPrefAbility_ = false;
    vendorPrinterPrefAbility_.clear();
    hasVendorJobAttrAbility_ = false;
    vendorJobAttrAbility_.clear();
}

void PrinterCapability::SetMinMargin(const PrintMargin &minMargin)
{
    hasMargin_ = true;
    minMargin_ = minMargin;
}

void PrinterCapability::SetResolution(const std::vector<PrintResolution> &resolutionList)
{
    hasResolution_ = true;
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

void PrinterCapability::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

bool PrinterCapability::HasMargin() const
{
    return hasMargin_;
}

void PrinterCapability::GetMinMargin(PrintMargin &margin) const
{
    margin = minMargin_;
}

void PrinterCapability::GetPageSize(std::vector<PrintPageSize> &pageSizeList) const
{
    pageSizeList.assign(pageSizeList_.begin(), pageSizeList_.end());
}

bool PrinterCapability::HasResolution() const
{
    return hasResolution_;
}

void PrinterCapability::GetResolution(std::vector<PrintResolution> &resolutionList) const
{
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

bool PrinterCapability::HasOption() const
{
    return hasOption_;
}

std::string PrinterCapability::GetOption() const
{
    return option_;
}

void PrinterCapability::SetVendorPrinterPrefAbility(const std::string &ability)
{
    hasVendorPrinterPrefAbility_ = true;
    vendorPrinterPrefAbility_ = ability;
}

void PrinterCapability::SetVendorJobAttrAbility(const std::string &ability)
{
    hasVendorJobAttrAbility_ = true;
    vendorJobAttrAbility_ = ability;
}

bool PrinterCapability::HasVendorPrinterPrefAbility() const
{
    return hasVendorPrinterPrefAbility_;
}

std::string PrinterCapability::GetVendorPrinterPrefAbility() const
{
    return vendorPrinterPrefAbility_;
}

bool PrinterCapability::HasVendorJobAttrAbility() const
{
    return hasVendorJobAttrAbility_;
}

std::string PrinterCapability::GetVendorJobAttrAbility() const
{
    return vendorJobAttrAbility_;
}

bool PrinterCapability::HasSupportedColorMode() const
{
    return hasSupportedColorMode_;
}

bool PrinterCapability::HasSupportedDuplexMode() const
{
    return hasSupportedDuplexMode_;
}

bool PrinterCapability::HasSupportedMediaType() const
{
    return hasSupportedMediaType_;
}

bool PrinterCapability::HasSupportedQuality() const
{
    return hasSupportedQuality_;
}

bool PrinterCapability::HasSupportedOrientation() const
{
    return hasSupportedOrientation_;
}

void PrinterCapability::GetSupportedPageSize(std::vector<PrintPageSize> &supportedPageSizeList) const
{
    supportedPageSizeList.assign(supportedPageSizeList_.begin(), supportedPageSizeList_.end());
}

void PrinterCapability::GetSupportedColorMode(std::vector<uint32_t> &supportedColorModeList) const
{
    supportedColorModeList.assign(supportedColorModeList_.begin(), supportedColorModeList_.end());
}

void PrinterCapability::GetSupportedDuplexMode(std::vector<uint32_t> &supportedDuplexModeList) const
{
    supportedDuplexModeList.assign(supportedDuplexModeList_.begin(), supportedDuplexModeList_.end());
}

void PrinterCapability::GetSupportedMediaType(std::vector<std::string> &supportedMediaTypeList) const
{
    supportedMediaTypeList.assign(supportedMediaTypeList_.begin(), supportedMediaTypeList_.end());
}

void PrinterCapability::GetSupportedQuality(std::vector<uint32_t> &supportedQualityList) const
{
    supportedQualityList.assign(supportedQualityList_.begin(), supportedQualityList_.end());
}

void PrinterCapability::GetSupportedOrientation(std::vector<uint32_t> &supportedOrientationList) const
{
    supportedOrientationList.assign(supportedOrientationList_.begin(), supportedOrientationList_.end());
}

void PrinterCapability::SetSupportedPageSize(const std::vector<PrintPageSize> &supportedPageSizeList)
{
    std::vector<PrintPageSize> uniquePageSizeList = RemoveDuplicatePageSize(supportedPageSizeList);
    supportedPageSizeList_.assign(uniquePageSizeList.begin(), uniquePageSizeList.end());
}

void PrinterCapability::SetSupportedColorMode(const std::vector<uint32_t> &supportedColorModeList)
{
    hasSupportedColorMode_ = true;
    supportedColorModeList_.assign(supportedColorModeList.begin(), supportedColorModeList.end());
}

void PrinterCapability::SetSupportedDuplexMode(const std::vector<uint32_t> &supportedDuplexModeList)
{
    hasSupportedDuplexMode_ = true;
    supportedDuplexModeList_.assign(supportedDuplexModeList.begin(), supportedDuplexModeList.end());
}

void PrinterCapability::SetSupportedMediaType(const std::vector<std::string> &supportedMediaTypeList)
{
    hasSupportedMediaType_ = true;
    supportedMediaTypeList_.assign(supportedMediaTypeList.begin(), supportedMediaTypeList.end());
}

void PrinterCapability::SetSupportedQuality(const std::vector<uint32_t> &supportedQualityList)
{
    hasSupportedQuality_ = true;
    supportedQualityList_.assign(supportedQualityList.begin(), supportedQualityList.end());
}

void PrinterCapability::SetSupportedOrientation(const std::vector<uint32_t> &supportedOrientationList)
{
    hasSupportedOrientation_ = true;
    supportedOrientationList_.assign(supportedOrientationList.begin(), supportedOrientationList.end());
}

bool PrinterCapability::ReadCoreAttrsFromParcel(Parcel &parcel, PrinterCapability &right)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(right.colorMode_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(right.duplexMode_), false);

    if (!PrintUtils::readListFromParcel<PrintPageSize>(parcel, right.supportedPageSizeList_,
        [](Parcel& p) -> std::optional<PrintPageSize> {
            auto ptr = PrintPageSize::Unmarshalling(p);
            if (ptr) {
                return std::optional<PrintPageSize>(*ptr);
            }
            return std::nullopt;
        })) {
        return false;
    }

    if (!PrintUtils::readListFromParcel<PrintResolution>(parcel, right.resolutionList_,
        [](Parcel& p) -> std::optional<PrintResolution> {
            auto ptr = PrintResolution::Unmarshalling(p);
            if (ptr) {
                return std::optional<PrintResolution>(*ptr);
            }
            return std::nullopt;
        }, &right.hasResolution_)) {
        return false;
    }
    return true;
}

bool PrinterCapability::ReadFromParcel(Parcel &parcel)
{
    PrinterCapability right;
    if (!ReadCoreAttrsFromParcel(parcel, right)) {
        return false;
    }
    if (!ReadSupportedListsFromParcel(parcel, right)) {
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasMargin_), false);
    if (right.hasMargin_) {
        auto marginPtr = PrintMargin::Unmarshalling(parcel);
        if (marginPtr != nullptr) {
            right.SetMinMargin(*marginPtr);
        }
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasOption_), false);
    if (right.hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.option_), false);
    }
    if (!ReadVendorAbilityFromParcel(parcel, right)) {
        return false;
    }
    *this = right;
    return true;
}

bool PrinterCapability::ReadSupportedListsFromParcel(Parcel &parcel, PrinterCapability &right)
{
    if (!PrintUtils::readListFromParcel<uint32_t>(
        parcel, right.supportedColorModeList_, [](Parcel &p) { return std::make_optional(p.ReadUint32()); },
        &right.hasSupportedColorMode_)) {
        return false;
    }

    if (!PrintUtils::readListFromParcel<uint32_t>(
        parcel, right.supportedDuplexModeList_, [](Parcel &p) { return std::make_optional(p.ReadUint32()); },
        &right.hasSupportedDuplexMode_)) {
        return false;
    }

    if (!PrintUtils::readListFromParcel<std::string>(
        parcel, right.supportedMediaTypeList_, [](Parcel &p) -> std::optional<std::string> {
            std::string val;
            if (!p.ReadString(val)) {
                return std::nullopt;
            }
            return std::make_optional(val);
        },
        &right.hasSupportedMediaType_)) {
        return false;
    }

    if (!PrintUtils::readListFromParcel<uint32_t>(
        parcel, right.supportedQualityList_, [](Parcel &p) { return std::make_optional(p.ReadUint32()); },
        &right.hasSupportedQuality_)) {
        return false;
    }

    if (!PrintUtils::readListFromParcel<uint32_t>(
        parcel, right.supportedOrientationList_, [](Parcel &p) { return std::make_optional(p.ReadUint32()); },
        &right.hasSupportedOrientation_)) {
        return false;
    }
    return true;
}

bool PrinterCapability::ReadVendorAbilityFromParcel(Parcel &parcel, PrinterCapability &right)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasVendorPrinterPrefAbility_), false);
    if (right.hasVendorPrinterPrefAbility_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.vendorPrinterPrefAbility_), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(right.hasVendorJobAttrAbility_), false);
    if (right.hasVendorJobAttrAbility_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(right.vendorJobAttrAbility_), false);
    }
    return true;
}

bool PrinterCapability::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetColorMode()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetDuplexMode()), false);
    if (!MarshallingSupportedLists(parcel)) {
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasMargin_), false);
    if (hasMargin_) {
        if (!minMargin_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for minMargin_ failed");
            return false;
        }
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasOption_), false);
    if (hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetOption()), false);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasVendorPrinterPrefAbility_), false);
    if (hasVendorPrinterPrefAbility_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVendorPrinterPrefAbility()), false);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasVendorJobAttrAbility_), false);
    if (hasVendorJobAttrAbility_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVendorJobAttrAbility()), false);
    }
    return true;
}

bool PrinterCapability::MarshallingSupportedLists(Parcel &parcel) const
{
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedPageSizeList_, [](Parcel &p, const PrintPageSize &item) { item.Marshalling(p); })) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, resolutionList_, [](Parcel &p, const PrintResolution &item) { item.Marshalling(p); }, hasResolution_)) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedColorModeList_, [](Parcel &p, const int &item) { p.WriteUint32(item); },
        hasSupportedColorMode_)) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedDuplexModeList_, [](Parcel &p, const int &item) { p.WriteUint32(item); },
        hasSupportedDuplexMode_)) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedMediaTypeList_, [](Parcel &p, const std::string &item) { p.WriteString(item); },
        hasSupportedMediaType_)) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedQualityList_, [](Parcel &p, const int &item) { p.WriteUint32(item); }, hasSupportedQuality_)) {
        return false;
    }
    if (!PrintUtils::WriteListToParcel(
        parcel, supportedOrientationList_, [](Parcel &p, const int &item) { p.WriteUint32(item); },
        hasSupportedOrientation_)) {
        return false;
    }
    return true;
}

std::shared_ptr<PrinterCapability> PrinterCapability::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterCapability>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return nativeObj;
}

void PrinterCapability::Dump() const
{
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

    for (auto pageItem : supportedPageSizeList_) {
        pageItem.Dump();
    }

    if (hasResolution_) {
        for (auto resolutionItem : resolutionList_) {
            resolutionItem.Dump();
        }
    }

    if (hasSupportedColorMode_) {
        for (auto item : supportedColorModeList_) {
            PRINT_HILOGD("supportedColorModeItem = %{public}d", item);
        }
    }

    if (hasSupportedDuplexMode_) {
        for (auto item : supportedDuplexModeList_) {
            PRINT_HILOGD("supportedDuplexModeItem = %{public}d", item);
        }
    }

    if (hasSupportedMediaType_) {
        for (auto item : supportedMediaTypeList_) {
            PRINT_HILOGD("supportedMediaTypeItem = %{public}s", item.c_str());
        }
    }

    if (hasSupportedQuality_) {
        for (auto item : supportedQualityList_) {
            PRINT_HILOGD("supportedQualityItem = %{public}d", item);
        }
    }

    if (hasSupportedOrientation_) {
        for (auto item : supportedOrientationList_) {
            PRINT_HILOGD("supportedOrientationItem = %{public}d", item);
        }
    }

    if (hasMargin_) {
        minMargin_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
    if (hasVendorPrinterPrefAbility_) {
        PRINT_HILOGD("vendorPrinterPrefAbility: %{public}s", vendorPrinterPrefAbility_.c_str());
    }
    if (hasVendorJobAttrAbility_) {
        PRINT_HILOGD("vendorJobAttrAbility: %{public}s", vendorJobAttrAbility_.c_str());
    }
}

void PrinterCapability::DumpInfo() const
{
    PRINT_HILOGI("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGI("duplexMode_ = %{public}d", duplexMode_);

    for (auto pageItem : supportedPageSizeList_) {
        PRINT_HILOGI("id_ = %{public}s", pageItem.GetId().c_str());
    }

    if (hasSupportedColorMode_) {
        for (auto item : supportedColorModeList_) {
            PRINT_HILOGI("supportedColorModeItem = %{public}d", item);
        }
    }

    if (hasSupportedDuplexMode_) {
        for (auto item : supportedDuplexModeList_) {
            PRINT_HILOGI("supportedDuplexModeItem = %{public}d", item);
        }
    }

    if (hasSupportedMediaType_) {
        for (auto item : supportedMediaTypeList_) {
            PRINT_HILOGI("supportedMediaTypeItem = %{public}s", item.c_str());
        }
    }

    if (hasSupportedQuality_) {
        for (auto item : supportedQualityList_) {
            PRINT_HILOGI("supportedQualityItem = %{public}d", item);
        }
    }
}

const char *PrinterCapability::GetPrinterAttrValue(const char *name)
{
    auto iter = printerAttr_group.find(name);
    if (iter != printerAttr_group.end()) {
        return iter->second.c_str();
    } else {
        return "";
    }
}

void PrinterCapability::SetPrinterAttrNameAndValue(const char *name, const char *value)
{
    printerAttr_group[name] = value;
}

Json::Value PrinterCapability::GetPrinterAttrGroupJson()
{
    if (printerAttr_group.size() < 1) {
        PRINT_HILOGI("no printerAttr_group");
        return "";
    }
    Json::Value printerAttrGroupJson;
    for (auto iter = printerAttr_group.begin(); iter != printerAttr_group.end(); iter++) {
        printerAttrGroupJson[iter->first] = iter->second;
    }
    return printerAttrGroupJson;
}

void PrinterCapability::ClearCurPrinterAttrGroup()
{
    PRINT_HILOGI("printerAttr_group reset");
    printerAttr_group.clear();
}

bool PrinterCapability::GetAdvanceOptionsJson(Json::Value &advanceOptionsJson) const
{
    if (!hasOption_ || option_.empty()) {
        PRINT_HILOGE("capability option is empty");
        return false;
    }

    Json::Value capJson;
    if (!PrintJsonUtil::Parse(option_, capJson)) {
        PRINT_HILOGE("failed to parse capability option json");
        return false;
    }

    if (!capJson.isObject()) {
        PRINT_HILOGE("capability option json is not an object");
        return false;
    }

    if (!capJson["cupsOptions"].isObject()) {
        PRINT_HILOGE("capability option is not valid cupsOptions json");
        return false;
    }

    Json::Value cupsOptions = capJson["cupsOptions"];
    if (!cupsOptions["advanceOptions"].isString()) {
        PRINT_HILOGE("advanceOptions is not a string");
        return false;
    }

    std::string advanceOptionsStr = cupsOptions["advanceOptions"].asString();
    if (!PrintJsonUtil::Parse(advanceOptionsStr, advanceOptionsJson) || !advanceOptionsJson.isArray()) {
        PRINT_HILOGE("failed to parse advanceOptions json or not an array");
        return false;
    }

    return true;
}

std::set<std::string> PrinterCapability::GetCustomOptionKeys() const
{
    Json::Value advanceOptionsJson;
    if (!GetAdvanceOptionsJson(advanceOptionsJson)) {
        PRINT_HILOGE("failed to get advanceOptions json from capability");
        return {};
    }

    std::set<std::string> customOptionKeys;
    for (const auto &opt : advanceOptionsJson) {
        if (opt.isObject() && opt["customParamType"].isInt()) {
            std::string keyword = opt["keyword"].asString();
            customOptionKeys.insert(keyword);
        }
    }
    return customOptionKeys;
}

std::vector<PrintPageSize> PrinterCapability::RemoveDuplicatePageSize(
    const std::vector<PrintPageSize> &supportedPageSizeList)
{
    std::vector<PrintPageSize> uniquePageSizeList = supportedPageSizeList;
    // Move custom to the end to show standard sizes preferentially
    std::stable_partition(uniquePageSizeList.begin(), uniquePageSizeList.end(), [](const PrintPageSize &p) {
        return p.GetName().find(CUSTOM_PREFIX) == std::string::npos;
    });
    std::unordered_set<std::string> uniquePageSizeSet;
    auto it = uniquePageSizeList.begin();
    while (it != uniquePageSizeList.end()) {
        std::stringstream widthAndHeight;
        widthAndHeight << round(it->GetWidth() / HUNDRED_OF_MILLIMETRE_TO_INCH) << "x"
                       << round(it->GetHeight() / HUNDRED_OF_MILLIMETRE_TO_INCH);
        PRINT_HILOGI("SetSupportedPageSize: %{public}s, uniqueFlag: %{public}s",
            it->GetName().c_str(),
            widthAndHeight.str().c_str());
        if (uniquePageSizeSet.insert(widthAndHeight.str()).second) {
            ++it;
        } else {
            // if already has the same withAndHeight, replace it with the last element, and shorten the list
            PRINT_HILOGI("SetSupportedPageSize find duplicate!");
            it = uniquePageSizeList.erase(it);
        }
    }
    return uniquePageSizeList;
}
}  // namespace OHOS::Print
