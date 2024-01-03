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
#include "printer_capability_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_margin_helper.h"
#include "print_page_size_helper.h"
#include "print_resolution_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_CAPABILITY_PAGESIZE = "pageSize";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";
static constexpr const char *PARAM_CAPABILITY_OPTION = "options";

napi_value PrinterCapabilityHelper::MakeJsObject(napi_env env, const PrinterCapability &cap)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));

    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_COLORMODE, cap.GetColorMode());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_DUPLEXMODE, cap.GetDuplexMode());

    CreatePageSizeList(env, jsObj, cap);
    if (cap.HasResolution()) {
        CreateResolutionList(env, jsObj, cap);
    }

    if (cap.HasMargin()) {
        PrintMargin margin;
        cap.GetMinMargin(margin);
        napi_value jsMargin = PrintMarginHelper::MakeJsObject(env, margin);
        PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_CAPABILITY_MINMARGIN, jsMargin));
    }
    if (cap.HasOption()) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_CAPABILITY_OPTION, cap.GetOption());
    }
    return jsObj;
}

std::shared_ptr<PrinterCapability> PrinterCapabilityHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterCapability>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of printer capability");
        return nullptr;
    }

    uint32_t colorMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_COLORMODE);
    uint32_t duplexMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_DUPLEXMODE);
    nativeObj->SetColorMode(colorMode);
    nativeObj->SetDuplexMode(duplexMode);

    napi_value jsPageSizes = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_PAGESIZE);
    bool isArray = false;
    napi_is_array(env, jsPageSizes, &isArray);
    if (!isArray) {
        PRINT_HILOGE("Invalid list of page size");
        return nullptr;
    }

    std::vector<PrintPageSize> pageSizes;
    uint32_t arrayLength = 0;
    napi_get_array_length(env, jsPageSizes, &arrayLength);
    for (uint32_t index = 0; index < arrayLength; index++) {
        napi_value jsPageSize;
        napi_get_element(env, jsPageSizes, index, &jsPageSize);
        auto pageSizePtr = PrintPageSizeHelper::BuildFromJs(env, jsPageSize);
        if (pageSizePtr == nullptr) {
            PRINT_HILOGE("Failed to build printer capability object from js");
            return nullptr;
        }
        pageSizes.emplace_back(*pageSizePtr);
    }
    nativeObj->SetPageSize(pageSizes);
    auto jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_CAPABILITY_OPTION));
    }
    PRINT_HILOGI("Build Print Capability succeed");
    return BuildFromJsSecond(env, jsValue, jsPageSizes, nativeObj);
}

std::shared_ptr<PrinterCapability> PrinterCapabilityHelper::BuildFromJsSecond(napi_env env, napi_value jsValue,
    napi_value jsPageSizes, std::shared_ptr<PrinterCapability> nativeObj)
{
    napi_value jsResolutionList = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_RESOLUTION);
    if (jsResolutionList != nullptr) {
        bool isArray = false;
        napi_is_array(env, jsResolutionList, &isArray);
        if (!isArray) {
            PRINT_HILOGE("Invalid list of print resolution");
            return nullptr;
        }
        std::vector<PrintResolution> resolutionList;
        uint32_t arrayLength = 0;
        napi_get_array_length(env, jsPageSizes, &arrayLength);
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsResolution;
            napi_get_element(env, jsResolutionList, index, &jsResolution);
            auto resolutionPtr = PrintResolutionHelper::BuildFromJs(env, jsResolution);
            if (resolutionPtr == nullptr) {
                PRINT_HILOGE("Failed to build printer capability object from js");
                return nullptr;
            }
            resolutionList.emplace_back(*resolutionPtr);
        }
        nativeObj->SetResolution(resolutionList);
    }

    napi_value jsMargin = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_MINMARGIN);
    if (jsMargin != nullptr) {
        auto marginPtr = PrintMarginHelper::BuildFromJs(env, jsMargin);
        if (marginPtr == nullptr) {
            PRINT_HILOGE("Failed to build printer capability object from js");
            return nullptr;
        }
        nativeObj->SetMinMargin(*marginPtr);
    }
    return nativeObj;
}

bool PrinterCapabilityHelper::CreatePageSizeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap)
{
    napi_value jsPageSizes = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsPageSizes), false);
    std::vector<PrintPageSize> pageSizeList;
    cap.GetPageSize(pageSizeList);
    uint32_t arrLength = pageSizeList.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = PrintPageSizeHelper::MakeJsObject(env, pageSizeList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsPageSizes, index, value), false);
    }
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_PAGESIZE, jsPageSizes), false);
    return true;
}

bool PrinterCapabilityHelper::CreateResolutionList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap)
{
    napi_value jsResolutionList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsResolutionList), false);
    std::vector<PrintResolution> resolutionList;
    uint32_t arrLength = resolutionList.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = PrintResolutionHelper::MakeJsObject(env, resolutionList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsResolutionList, index, value), false);
    }
    PRINT_CALL_BASE(env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_RESOLUTION, jsResolutionList), false);
    return true;
}

bool PrinterCapabilityHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_CAPABILITY_COLORMODE, PRINT_PARAM_NOT_SET},
        {PARAM_CAPABILITY_DUPLEXMODE, PRINT_PARAM_NOT_SET},
        {PARAM_CAPABILITY_PAGESIZE, PRINT_PARAM_NOT_SET},
        {PARAM_CAPABILITY_RESOLUTION, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_MINMARGIN, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_OPTION, PRINT_PARAM_OPT},
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
}  // namespace OHOS::Print
