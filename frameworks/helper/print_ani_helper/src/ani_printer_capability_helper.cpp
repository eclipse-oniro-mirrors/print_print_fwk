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

#include <ani.h>
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_printer_capability_helper.h"
#include "print_log.h"
#include "ani_print_page_size_helper.h"
#include "ani_print_margin_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";
static constexpr const char *PARAM_CAPABILITY_OPTION = "options";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_COLORMODES = "supportedColorModes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES = "supportedDuplexModes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES = "supportedMediaTypes";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_QUALITIES = "supportedQualities";
static constexpr const char *PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS = "supportedOrientations";
static constexpr const char *CLASS_NAME = "L@ohos/print/print/PrinterCapabilityImpl;";

PrinterCapability PrinterCapabilityAniHelper::ParsePrinterCapability(ani_env *env, ani_ref capability)
{
    PRINT_HILOGI("enter ParsePrinterCapability");
    PrinterCapability cap;
    double colorMode;
    if (GetDoubleProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_COLORMODE, colorMode)) {
        cap.SetColorMode(static_cast<uint32_t>(colorMode));
    }

    double duplexMode;
    if (GetDoubleProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_DUPLEXMODE, duplexMode)) {
        cap.SetDuplexMode(static_cast<uint32_t>(duplexMode));
    }

    ani_ref minMarginRef;
    if (GetRefProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_MINMARGIN, minMarginRef)) {
        PrintMargin printMargin = AniPrintMarginHelper::ParsePrintMargin(env, static_cast<ani_object>(minMarginRef));
        cap.SetMinMargin(printMargin);
    }

    std::string options;
    if (GetStringProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_OPTION, options)) {
        cap.SetOption(options);
    }

    std::vector<uint32_t> colorModeList;
    if (GetEnumArrayProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_SUPPORTED_COLORMODES,
        colorModeList)) {
        cap.SetSupportedColorMode(colorModeList);
    }

    std::vector<uint32_t> duplexModeList;
    if (GetEnumArrayProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES,
        duplexModeList)) {
        cap.SetSupportedDuplexMode(duplexModeList);
    }

    std::vector<uint32_t> qualityList;
    if (GetEnumArrayProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_SUPPORTED_QUALITIES,
        qualityList)) {
        cap.SetSupportedQuality(qualityList);
    }

    std::vector<uint32_t> orientationList;
    if (GetEnumArrayProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS,
        orientationList)) {
        cap.SetSupportedOrientation(orientationList);
    }

    std::vector<std::string> mediaTypeList;
    if (GetStringArrayProperty(env, static_cast<ani_object>(capability), PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES,
        mediaTypeList)) {
        cap.SetSupportedMediaType(mediaTypeList);
    }
    return cap;
}

ani_object PrinterCapabilityAniHelper::CreatePrinterCapability(ani_env *env, const PrinterCapability& cap)
{
    PRINT_HILOGI("enter CreatePrinterCapability");
    ani_object obj = CreateObject(env, nullptr, CLASS_NAME);
    SetDoubleProperty(env, obj, PARAM_CAPABILITY_COLORMODE, cap.GetColorMode());
    SetDoubleProperty(env, obj, PARAM_CAPABILITY_DUPLEXMODE, cap.GetDuplexMode());

    std::vector<PrintPageSize> supportPageSizeList;
    cap.GetSupportedPageSize(supportPageSizeList);

    std::vector<PrintResolution> resolutionList;
    cap.GetResolution(resolutionList);

    PrintMargin minMargin;
    cap.GetMinMargin(minMargin);
    SetRefProperty(env, obj, PARAM_CAPABILITY_RESOLUTION, AniPrintMarginHelper::CreatePrintMargin(env, minMargin));

    std::vector<uint32_t> colorModeList;
    cap.GetSupportedColorMode(colorModeList);
    ani_object colorModeItems = CreateEnumArray(env, "L@ohos/print/print/PrintColorMode;", colorModeList);
    SetRefProperty(env, obj, PARAM_CAPABILITY_SUPPORTED_COLORMODES, colorModeItems);

    std::vector<uint32_t> duplexModeLIst;
    cap.GetSupportedDuplexMode(duplexModeLIst);
    ani_object duplexModeItems = CreateEnumArray(env, "L@ohos/print/print/PrintDuplexMode;", duplexModeLIst);
    SetRefProperty(env, obj, PARAM_CAPABILITY_SUPPORTED_DUPLEXMODES, duplexModeItems);

    std::vector<uint32_t> qualityList;
    cap.GetSupportedQuality(qualityList);
    ani_object qualityListItems = CreateEnumArray(env, "L@ohos/print/print/PrintQuality;", qualityList);
    SetRefProperty(env, obj, PARAM_CAPABILITY_SUPPORTED_QUALITIES, qualityListItems);

    std::vector<uint32_t> orientationList;
    cap.GetSupportedOrientation(orientationList);
    ani_object orientationItems = CreateEnumArray(env, "L@ohos/print/print/PrintOrientationMode;", orientationList);
    SetRefProperty(env, obj, PARAM_CAPABILITY_SUPPORTED_ORIENTATIONS, orientationItems);

    std::vector<std::string> mediaTypeList;
    cap.GetSupportedMediaType(mediaTypeList);
    SetStringArrayProperty(env, obj, PARAM_CAPABILITY_SUPPORTED_MEDIA_TYPES, mediaTypeList);

    SetStringProperty(env, obj, PARAM_CAPABILITY_OPTION, cap.GetOption());

    return nullptr;
}
}  // namespace OHOS::Print