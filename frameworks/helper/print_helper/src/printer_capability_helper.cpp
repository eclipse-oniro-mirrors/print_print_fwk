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
#include "print_utils.h"
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
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_PAGESIZES = "supportedPageSizes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_COLORMODES = "supportedColorModes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES = "supportedDuplexModes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES = "supportedMediaTypes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_QUALITIES = "supportedQualities";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS = "supportedOrientations";

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

    if (cap.HasSupportedColorMode()) {
        CreateSupportedColorModeList(env, jsObj, cap);
    }

    if (cap.HasSupportedDuplexMode()) {
        CreateSupportedDuplexModeList(env, jsObj, cap);
    }

    if (cap.HasSupportedMediaType()) {
        CreateSupportedMediaTypeList(env, jsObj, cap);
    }

    if (cap.HasSupportedQuality()) {
        CreateSupportedQualityList(env, jsObj, cap);
    }

    if (cap.HasSupportedOrientation()) {
        CreateSupportedOrientationList(env, jsObj, cap);
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


bool PrinterCapabilityHelper::CreatePageSizeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap)
{
    napi_value jsPageSizes = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsPageSizes), false);
    std::vector<PrintPageSize> pageSizeList;
    cap.GetSupportedPageSize(pageSizeList);
    uint32_t arrLength = pageSizeList.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = PrintPageSizeHelper::MakeJsObject(env, pageSizeList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsPageSizes, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_PAGESIZES, jsPageSizes),
        false);
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

bool PrinterCapabilityHelper::CreateSupportedColorModeList(napi_env env, napi_value& jsPrinterCap,
    const PrinterCapability& cap)
{
    napi_value jsSupportedColorModeList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsSupportedColorModeList), false);
    std::vector<uint32_t> supportedColorModeList;
    cap.GetSupportedColorMode(supportedColorModeList);
    uint32_t arrLength = static_cast<uint32_t>(supportedColorModeList.size());
    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = NapiPrintUtils::CreateUint32(env, supportedColorModeList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsSupportedColorModeList, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_COLORMODES, jsSupportedColorModeList),
        false);
    return true;
}

bool PrinterCapabilityHelper::CreateSupportedDuplexModeList(napi_env env, napi_value& jsPrinterCap,
    const PrinterCapability& cap)
{
    napi_value jsSupportedDuplexModeList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsSupportedDuplexModeList), false);
    std::vector<uint32_t> supportedDuplexModeList;
    cap.GetSupportedDuplexMode(supportedDuplexModeList);
    uint32_t arrLength = static_cast<uint32_t>(supportedDuplexModeList.size());
    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = NapiPrintUtils::CreateUint32(env, supportedDuplexModeList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsSupportedDuplexModeList, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES, jsSupportedDuplexModeList),
        false);
    return true;
}

bool PrinterCapabilityHelper::CreateSupportedMediaTypeList(napi_env env, napi_value& jsPrinterCap,
    const PrinterCapability& cap)
{
    napi_value jsSupportedMediaTypeList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsSupportedMediaTypeList), false);
    std::vector<std::string> supportedMediaTypeList;
    cap.GetSupportedMediaType(supportedMediaTypeList);
    uint32_t arrLength = static_cast<uint32_t>(supportedMediaTypeList.size());
    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = NapiPrintUtils::CreateStringUtf8(env, supportedMediaTypeList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsSupportedMediaTypeList, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES, jsSupportedMediaTypeList),
        false);
    return true;
}

bool PrinterCapabilityHelper::CreateSupportedQualityList(napi_env env, napi_value& jsPrinterCap,
    const PrinterCapability& cap)
{
    napi_value jsSupportedQualitiesList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsSupportedQualitiesList), false);
    std::vector<uint32_t> supportedQualitiesList;
    cap.GetSupportedQuality(supportedQualitiesList);
    uint32_t arrLength = static_cast<uint32_t>(supportedQualitiesList.size());
    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = NapiPrintUtils::CreateUint32(env, supportedQualitiesList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsSupportedQualitiesList, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_QUALITIES, jsSupportedQualitiesList),
        false);
    return true;
}

bool PrinterCapabilityHelper::CreateSupportedOrientationList(napi_env env, napi_value& jsPrinterCap,
    const PrinterCapability& cap)
{
    napi_value jsSupportedOrientationList = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsSupportedOrientationList), false);
    std::vector<uint32_t> supportedOrientationList;
    cap.GetSupportedQuality(supportedOrientationList);
    uint32_t arrLength = static_cast<uint32_t>(supportedOrientationList.size());
    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = NapiPrintUtils::CreateUint32(env, supportedOrientationList[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsSupportedOrientationList, index, value), false);
    }
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrinterCap, PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS, jsSupportedOrientationList),
        false);
    return true;
}

std::shared_ptr<PrinterCapability> PrinterCapabilityHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterCapability>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of printer capability");
        return nullptr;
    }
    if (!BuildSimplePropertyFromJs(env, jsValue, nativeObj)) {
        PRINT_HILOGE("BuildSimplePropertyFromJs error");
        return nullptr;
    }
    if (!BuildArrayPropertyFromJs(env, jsValue, nativeObj)) {
        PRINT_HILOGE("BuildArrayPropertyFromJs error");
        return nullptr;
    }
    PRINT_HILOGI("Build Print Capability succeed");
    return nativeObj;
}

bool PrinterCapabilityHelper::BuildSimplePropertyFromJs(napi_env env, napi_value jsValue,
    std::shared_ptr<PrinterCapability> nativeObj)
{
    uint32_t colorMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_COLORMODE);
    if (colorMode) {
        nativeObj->SetColorMode(colorMode);
    }

    uint32_t duplexMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CAPABILITY_DUPLEXMODE);
    if (duplexMode) {
        nativeObj->SetDuplexMode(duplexMode);
    }

    napi_value jsMargin = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_MINMARGIN);
    if (jsMargin != nullptr) {
        auto marginPtr = PrintMarginHelper::BuildFromJs(env, jsMargin);
        if (marginPtr == nullptr) {
            PRINT_HILOGE("Failed to build printer capability object from js");
            return false;
        }
        nativeObj->SetMinMargin(*marginPtr);
    }

    auto jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_CAPABILITY_OPTION));
    }
    return true;
}

bool PrinterCapabilityHelper::BuildArrayPropertyFromJs(napi_env env, napi_value jsValue,
    std::shared_ptr<PrinterCapability> nativeObj)
{
    if (!buildSupportedPageSizes(env, jsValue, nativeObj) ||
        !buildSupportedResolutions(env, jsValue, nativeObj) ||
        !buildSupportedColorModes(env, jsValue, nativeObj) ||
        !buildSupportedDuplexModes(env, jsValue, nativeObj) ||
        !buildSupportedQualities(env, jsValue, nativeObj) ||
        !buildSupportedMediaTypes(env, jsValue, nativeObj) ||
        !buildSupportedOrientations(env, jsValue, nativeObj)) {
        return false;
    }
    return true;
}

bool PrinterCapabilityHelper::buildSupportedPageSizes(napi_env env, napi_value jsValue,
                                                      std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<PrintPageSize>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_PAGESIZES,
        [&](const std::vector<PrintPageSize>& pageSizes) {
            nativeObj->SetSupportedPageSize(pageSizes);
        },
        PrintPageSizeHelper::BuildFromJs);
}

bool PrinterCapabilityHelper::buildSupportedResolutions(napi_env env, napi_value jsValue,
                                                        std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<PrintResolution>(env, jsValue, PARAM_CAPABILITY_RESOLUTION,
        [&](const std::vector<PrintResolution>& resolutions) {
            nativeObj->SetResolution(resolutions);
        },
        PrintResolutionHelper::BuildFromJs);
}

bool PrinterCapabilityHelper::buildSupportedColorModes(napi_env env, napi_value jsValue,
                                                       std::shared_ptr <PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<uint32_t>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_COLORMODES,
        [&](const std::vector<uint32_t>& colorModes) { nativeObj->SetSupportedColorMode(colorModes); },
        [](napi_env env, napi_value jsValue) -> std::shared_ptr<uint32_t> {
            uint32_t colorMode = NapiPrintUtils::GetUint32FromValue(env, jsValue);
            return std::make_shared<uint32_t>(colorMode);
        });
}

bool PrinterCapabilityHelper::buildSupportedDuplexModes(napi_env env, napi_value jsValue,
                                                        std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<uint32_t>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES,
        [&](const std::vector<uint32_t>& duplexModes) {
            nativeObj->SetSupportedDuplexMode(duplexModes);
        },
        [](napi_env env, napi_value jsValue) -> std::shared_ptr<uint32_t> {
            return std::make_shared<uint32_t>(NapiPrintUtils::GetUint32FromValue(env, jsValue));
        });
}

bool PrinterCapabilityHelper::buildSupportedQualities(napi_env env, napi_value jsValue,
                                                      std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<uint32_t>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_QUALITIES,
        [&](const std::vector<uint32_t>& qualities) {
            nativeObj->SetSupportedQuality(qualities);
        },
        [](napi_env env, napi_value jsValue) -> std::shared_ptr<uint32_t> {
            return std::make_shared<uint32_t>(NapiPrintUtils::GetUint32FromValue(env, jsValue));
        });
}

bool PrinterCapabilityHelper::buildSupportedMediaTypes(napi_env env, napi_value jsValue,
                                                       std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<std::string>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES,
        [&](const std::vector<std::string>& mediaTypes) {
            nativeObj->SetSupportedMediaType(mediaTypes);
        },
        [](napi_env env, napi_value jsValue) -> std::shared_ptr<std::string> {
            return std::make_shared<std::string>(NapiPrintUtils::GetStringFromValueUtf8(env, jsValue));
        });
}

bool PrinterCapabilityHelper::buildSupportedOrientations(napi_env env, napi_value jsValue,
                                                         std::shared_ptr<PrinterCapability> nativeObj)
{
    return ProcessJsArrayProperty<uint32_t>(env, jsValue, PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS,
        [&](const std::vector<uint32_t>& orientations) {
            nativeObj->SetSupportedOrientation(orientations);
        },
        [](napi_env env, napi_value jsValue) -> std::shared_ptr<uint32_t> {
            return std::make_shared<uint32_t>(NapiPrintUtils::GetUint32FromValue(env, jsValue));
        });
}

bool PrinterCapabilityHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_CAPABILITY_COLORMODE, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_DUPLEXMODE, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_PAGESIZE, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_RESOLUTION, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_MINMARGIN, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_OPTION, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_PAGESIZES, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_COLORMODES, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_QUALITIES, PRINT_PARAM_OPT},
        {PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    return NapiPrintUtils::VerifyProperty(names, propertyList);
}
} // namespace OHOS::Print
