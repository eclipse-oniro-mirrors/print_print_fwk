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

#include "ani_printer_preferences_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"

namespace OHOS::Print {
static constexpr const char *PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE = "defaultDuplexMode";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY = "defaultPrintQuality";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE = "defaultMediaType";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID = "defaultPageSizeId";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_ORIENTATION = "defaultOrientation";
static constexpr const char *PARAM_PREFERENCES_BORDERLESS = "borderless";
static constexpr const char *PARAM_PREFERENCES_OPTION = "options";

ani_object PrinterPreferencesAniHelper::CreatePrinterPreferences(ani_env *env, const PrinterPreferences &preferences)
{
    PRINT_HILOGI("enter PrinterPreferences");

    static const char *className = "L@ohos/print/print/PrinterPreferencesImpl;";
    ani_object obj = CreateObject(env, nullptr, className);

    ani_enum_item printDuplexModeEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrintDuplexMode;",
                                                          static_cast<int32_t>(preferences.GetDefaultDuplexMode()));
    SetEnumProperty(env, obj, "<set>defaultDuplexMode", "L@ohos/print/print/PrintDuplexMode;:V", printDuplexModeEnum);

    ani_enum_item printQualityEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrintQuality;",
                                                       static_cast<int32_t>(preferences.GetDefaultPrintQuality()));
    SetEnumProperty(env, obj, "<set>defaultPrintQuality", "C{@ohos.print.print.PrintQuality}:", printQualityEnum);

    ani_enum_item orientationModeEnum = CreateEnumByIndex(env, "@ohos.print.print.PrintOrientationMode",
                                                          static_cast<int32_t>(preferences.GetDefaultPrintQuality()));
    SetEnumProperty(env, obj, "<set>defaultOrientation", "C{@ohos.print.print.PrintOrientationMode}:",
        orientationModeEnum);

    SetStringProperty(env, obj, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, preferences.GetDefaultMediaType());
    SetStringProperty(env, obj, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, preferences.GetDefaultPageSizeId());
    SetBoolProperty(env, obj, PARAM_PREFERENCES_BORDERLESS, preferences.GetBorderless());
    SetStringProperty(env, obj, PARAM_PREFERENCES_OPTION, preferences.GetOption());

    return obj;
}

PrinterPreferences PrinterPreferencesAniHelper::ParsePreferences(ani_env *env, ani_ref preferencesRef)
{
    PRINT_HILOGI("enter ParsePrinterInfo");
    PrinterPreferences preferences;
    ParseStringPreferences(env, preferences, preferencesRef);
    ParseRefPreferences(env, preferences, preferencesRef);
    return preferences;
}

void PrinterPreferencesAniHelper::ParseStringPreferences(ani_env *env, PrinterPreferences& preferences,
    ani_ref preferencesRef)
{
    std::string defaultMediaType;
    if (GetStringProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, defaultMediaType)) {
        preferences.SetDefaultMediaType(defaultMediaType);
    }
    std::string defaultPageSizeId;
    if (GetStringProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, defaultPageSizeId)) {
        preferences.SetDefaultPageSizeId(defaultPageSizeId);
    }
    bool borderless = false;
    if (GetBoolProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_BORDERLESS, borderless)) {
        preferences.SetBorderless(borderless);
    }
    std::string options;
    if (GetStringProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_OPTION, options)) {
        preferences.SetOption(options);
    }
}

void PrinterPreferencesAniHelper::ParseRefPreferences(ani_env *env, PrinterPreferences& preferences,
    ani_ref preferencesRef)
{
    ani_ref duplexEnum;
    uint32_t duplexModeValue = 0;
    if (GetRefProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE, duplexEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(duplexEnum), duplexModeValue)) {
        preferences.SetDefaultDuplexMode(duplexModeValue);
    }
    ani_ref printQualityEnum;
    uint32_t printQualityValue = 0;
    if (GetRefProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY, printQualityEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(printQualityEnum), printQualityValue)) {
        preferences.SetDefaultDuplexMode(printQualityValue);
    }
    ani_ref orientationEnum;
    uint32_t orientationValue = 0;
    if (GetRefProperty(env, static_cast<ani_object>(preferencesRef),
        PARAM_PREFERENCES_DEFAULT_ORIENTATION, orientationEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(orientationEnum), orientationValue)) {
        preferences.SetDefaultOrientation(orientationValue);
    }
}

bool PrinterPreferencesAniHelper::ValidateProperty(ani_env *env, ani_ref preferencesRef)
{
    std::map<std::string, PrintParamStatus> propertyList = {
            {PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_DEFAULT_ORIENTATION, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_BORDERLESS, PRINT_PARAM_OPT},
            {PARAM_PREFERENCES_OPTION, PRINT_PARAM_OPT},
    };
    return true;
}
}  // namespace OHOS::Print
