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

    ani_object obj = {};
    static const char *className = "L@ohos/print/print/PrinterPreferencesImpl;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        PRINT_HILOGE("[ANI] find class fail");
        return obj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        PRINT_HILOGE("[ANI] find method fail");
        return obj;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        PRINT_HILOGE("Create Object Failed");
        return obj;
    }

    ani_enum_item printDuplexModeEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrintDuplexMode;",
                                                          static_cast<int32_t>(preferences.GetDefaultDuplexMode()));
    SetFieldEnum(env, obj, "<set>defaultDuplexMode", "L@ohos/print/print/PrintDuplexMode;:V", printDuplexModeEnum);

    ani_enum_item printQualityEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrintQuality;",
                                                       static_cast<int32_t>(preferences.GetDefaultPrintQuality()));
    SetFieldEnum(env, obj, "<set>defaultPrintQuality", "L@ohos/print/print/PrintQuality;:V", printQualityEnum);

    ani_enum_item orientationModeEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrintOrientationMode;",
                                                          static_cast<int32_t>(preferences.GetDefaultPrintQuality()));
    SetFieldEnum(env, obj, "<set>defaultOrientation", "L@ohos/print/print/PrintOrientationMode;:V",
                 orientationModeEnum);

    SetFieldString(env, cls, obj, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, preferences.GetDefaultMediaType());
    SetFieldString(env, cls, obj, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, preferences.GetDefaultPageSizeId());
    SetFieldBoolean(env, cls, obj, PARAM_PREFERENCES_BORDERLESS, preferences.GetBorderless());
    SetFieldString(env, cls, obj, PARAM_PREFERENCES_OPTION, preferences.GetOption());

    return obj;
}

PrinterPreferences PrinterPreferencesAniHelper::ParsePreferences(ani_env *env, ani_ref preferencesRef)
{
    PRINT_HILOGI("enter ParsePrinterInfo");
    PrinterPreferences preferences;

    ani_int duplexIndex;
    if (GetIntByName(env, preferencesRef, PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE, duplexIndex)) {
        uint32_t duplexModeValue = GetEnumValueInt(env, "PrintDuplexMode", duplexIndex);
        preferences.SetDefaultDuplexMode(duplexModeValue);
    }

    ani_int printQualityIndex;
    if (GetIntByName(env, preferencesRef, PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY, printQualityIndex)) {
        uint32_t printQualityValue = GetEnumValueInt(env, "PrintQuality", printQualityIndex);
        preferences.SetDefaultDuplexMode(printQualityValue);
    }

    ani_int orientationIndex;
    if (GetIntByName(env, preferencesRef, PARAM_PREFERENCES_DEFAULT_ORIENTATION, orientationIndex)) {
        uint32_t orientationValue = GetEnumValueInt(env, "PrintOrientationMode", orientationIndex);
        preferences.SetDefaultOrientation(orientationValue);
    }

    std::string defaultMediaType;
    if (GetStringOrUndefined(env, preferencesRef, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, defaultMediaType)) {
        preferences.SetDefaultMediaType(defaultMediaType);
    }

    std::string defaultPageSizeId;
    if (GetStringOrUndefined(env, preferencesRef, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, defaultPageSizeId)) {
        preferences.SetDefaultPageSizeId(defaultPageSizeId);
    }

    bool borderless = GetBoolOrUndefined(env, static_cast<ani_object>(preferencesRef), PARAM_PREFERENCES_BORDERLESS);
    preferences.SetBorderless(borderless);

    std::string options;
    if (GetStringOrUndefined(env, preferencesRef, PARAM_PREFERENCES_OPTION, options)) {
        preferences.SetOption(options);
    }

    return preferences;
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
