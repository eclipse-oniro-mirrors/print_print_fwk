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
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";
static constexpr const char *PARAM_CAPABILITY_PAGESIZE = "pageSize";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";

PrinterCapability::PrinterCapability() : minMargin_(), colorMode_(0), duplexMode_(0) {
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

PrinterCapability::~PrinterCapability()
{
}

void PrinterCapability::SetMinMargin(const PrintMargin &minMargin)
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

bool PrinterCapability::ReadFromParcel(Parcel &parcel)
{
    auto marginPtr = PrintMargin::Unmarshalling(parcel);
    if (marginPtr == nullptr) {
        PRINT_HILOGE("Failed to read page margin from parcel");
        return false;
    }
    SetMinMargin(*marginPtr);
    std::vector<PrintPageSize> pageSizeList;
    std::vector<PrintResolution> resolutionList;
    uint32_t vecSize = parcel.ReadUint32();
    for (uint32_t index = 0; index < vecSize; index++) {
        auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
        if (pageSizePtr == nullptr) {
            PRINT_HILOGE("Failed to read page size from parcel");
            return false;
        }
        pageSizeList.emplace_back(*pageSizePtr);
    }
    SetPageSize(pageSizeList);

    vecSize = parcel.ReadUint32();
    for (uint32_t index = 0; index < vecSize; index++) {
        auto resolutionPtr = PrintResolution::Unmarshalling(parcel);
        if (resolutionPtr == nullptr) {
            PRINT_HILOGE("Failed to read print resolution from parcel");
            return false;
        }
        resolutionList.emplace_back(*resolutionPtr);
    }
    SetResolution(resolutionList);
    SetColorMode(parcel.ReadUint32());
    SetDuplexMode(parcel.ReadUint32());
    return true;
}

bool PrinterCapability::Marshalling(Parcel &parcel) const
{
    if (!minMargin_.Marshalling(parcel)) {
        return false;
    }

    uint32_t vecSize = static_cast<uint32_t>(pageSizeList_.size());
    parcel.WriteUint32(vecSize);
    for (uint32_t index = 0; index < vecSize; index++) {
        pageSizeList_[index].Marshalling(parcel);
    }

    vecSize = static_cast<uint32_t>(resolutionList_.size());
    parcel.WriteUint32(vecSize);
    for (uint32_t index = 0; index < vecSize; index++) {
        resolutionList_[index].Marshalling(parcel);
    }
    parcel.WriteUint32(GetColorMode());
    parcel.WriteUint32(GetDuplexMode());
    return true;
}

std::shared_ptr<PrinterCapability> PrinterCapability::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterCapability>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create printer capability object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling Printer capability");
        return nullptr;
    }
    return nativeObj;
}

bool PrinterCapability::CreatePageSizeList(napi_env env, napi_value &jsPrinterCap) const
{
    napi_value jsPageSizes = nullptr;
    NAPI_CALL_BASE(env, napi_create_array(env, &jsPageSizes), false);
    uint32_t arrLength = pageSizeList_.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = pageSizeList_[index].ToJsObject(env);
        NAPI_CALL_BASE(env, napi_set_element(env, jsPageSizes, index, value), false);
    }
    NAPI_CALL_BASE(env, napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_PAGESIZE, jsPageSizes), false);
    return true;
}

bool PrinterCapability::CreateResolutionList(napi_env env, napi_value &jsPrinterCap) const
{
    napi_value jsResolutionList = nullptr;
    NAPI_CALL_BASE(env, napi_create_array(env, &jsResolutionList), false);
    uint32_t arrLength = resolutionList_.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = resolutionList_[index].ToJsObject(env);
        NAPI_CALL_BASE(env, napi_set_element(env, jsResolutionList, index, value), false);
    }
    NAPI_CALL_BASE(env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_RESOLUTION, jsResolutionList), false);
    return true;
}

napi_value PrinterCapability::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsObj));

    napi_value jsMargin = minMargin_.ToJsObject(env);   
    NAPI_CALL(env, napi_set_named_property(env, jsObj, PARAM_CAPABILITY_MINMARGIN, jsMargin));

    if (!CreatePageSizeList(env, jsObj)) {
        PRINT_HILOGE("Failed to create page size list property of printer capability");
        return nullptr;
    }

    if (!CreateResolutionList(env, jsObj)) {
        PRINT_HILOGE("Failed to create resolution list property of printer capability");
        return nullptr;
    }    
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_COLORMODE, GetColorMode());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_DUPLEXMODE, GetDuplexMode());    
    return jsObj;
}

std::shared_ptr<PrinterCapability> PrinterCapability::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterCapability>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create printer capability object");
        return nullptr;
    }

    auto names = NapiPrintUtils::GetPropertyNames(env, jsValue);
    for (auto name : names) {
        PRINT_HILOGD("Property: %{public}s", name.c_str());
    }    

    napi_value jsMargin = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_MINMARGIN);
    auto marginPtr = PrintMargin::BuildFromJs(env, jsMargin);
    if (marginPtr == nullptr) {
        PRINT_HILOGE("Failed to build printer capability object from js");
        return nullptr;
    }
    nativeObj->SetMinMargin(*marginPtr);

    napi_value jsPageSizes = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_PAGESIZE);
    bool isArray = false;
    napi_is_array(env, jsPageSizes, &isArray);
    if (isArray) {
        std::vector<PrintPageSize> pageSizes;
        uint32_t arrayLength = 0;
        napi_get_array_length(env, jsPageSizes, &arrayLength);
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsPageSize;
            napi_get_element(env, jsPageSizes, index, &jsPageSize);
            auto pageSizePtr = PrintPageSize::BuildFromJs(env, jsPageSize);
            if (pageSizePtr == nullptr) {
                PRINT_HILOGE("Failed to build printer capability object from js");
                return nullptr;
            }
            pageSizes.emplace_back(*pageSizePtr);
        }
        nativeObj->SetPageSize(pageSizes);
    }

    napi_value jsResolutionList = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_RESOLUTION);
    isArray = false;
    napi_is_array(env, jsResolutionList, &isArray);
    if (isArray) {
        std::vector<PrintResolution> resolutionList;
        uint32_t arrayLength = 0;
        napi_get_array_length(env, jsPageSizes, &arrayLength);
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsResolution;
            napi_get_element(env, jsResolutionList, index, &jsResolution);
            auto resolutionPtr = PrintResolution::BuildFromJs(env, jsResolution);
            if (resolutionPtr == nullptr) {
                PRINT_HILOGE("Failed to build printer capability object from js");
                return nullptr;
            }
            resolutionList.emplace_back(*resolutionPtr);
        }
        nativeObj->SetResolution(resolutionList);
    }

    uint32_t colorMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_COLORMODE);
    uint32_t duplexMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_DUPLEXMODE);
    nativeObj->SetColorMode(colorMode);
    nativeObj->SetDuplexMode(duplexMode);
    PRINT_HILOGE("Build Print Capability succeed");
    return nativeObj;
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
