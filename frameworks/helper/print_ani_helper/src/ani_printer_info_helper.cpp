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
#include "ani_printer_info_helper.h"
#include "ani_printer_capability_helper.h"
#include "print_log.h"
#include "print_constant.h"
#include "ani_printer_preferences_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_INFO_PRINTERID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState"; // Property in API 10, deprecated in API 12
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";
static constexpr const char *PARAM_JOB_OPTION = "options";
static constexpr const char *PARAM_INFO_IS_DAFAULT_PRINTER = "isDefaultPrinter";
static constexpr const char *PARAM_INFO_IS_LAST_USED_PRINTER = "isLastUsedPrinter";
static constexpr const char *PARAM_INFO_PRINTER_STATUS = "printerStatus";
static constexpr const char *PARAM_INFO_PRINTER_MAKE = "printerMake";
static constexpr const char *PARAM_INFO_URI = "uri";
static constexpr const char *PARAM_INFO_PRINTER_PREFERENCES = "preferences";
static constexpr const char *PARAM_INFO_ALIAS = "alias";
PrinterInfo PrinterInfoAniHelper::ParsePrinterInfo(ani_env *env, ani_ref printerInfo)
{
    PRINT_HILOGI("enter ParsePrinterInfo");
    PrinterInfo info;
    ParsePrinterInfoStringField(env, printerInfo, info);
    ani_int stateIndex;
    if (GetIntByName(env, printerInfo, PARAM_INFO_PRINTERSTATE, stateIndex)) {
        uint32_t stateValue = GetEnumValueInt(env, "PrinterState", stateIndex);
        info.SetPrinterState(stateValue);
    }
    ani_int statusIndex;
    if (GetIntByName(env, printerInfo, PARAM_INFO_PRINTER_STATUS, statusIndex)) {
        uint32_t statusValue = GetEnumValueInt(env, "PrinterStatus", statusIndex);
        info.SetPrinterState(statusValue);
    }
    double printerIcon;
    if (GetDoubleOrUndefined(env, static_cast<ani_object>(printerInfo), PARAM_INFO_PRINTERICON, printerIcon)) {
        info.SetPrinterIcon(static_cast<uint32_t>(printerIcon));
    }
    ani_ref capabilityRef;
    if (GetRefFieldByName(env, printerInfo, PARAM_INFO_CAPABILITY, capabilityRef)) {
        PrinterCapability capability = PrinterCapabilityAniHelper::ParsePrinterCapability(env, capabilityRef);
        info.SetCapability(capability);
    }
    return info;
}

void PrinterInfoAniHelper::ParsePrinterInfoStringField(ani_env *env, ani_ref printerInfoAni, PrinterInfo& printerInfo)
{
    std::string printerId;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_PRINTERID, printerId)) {
        printerInfo.SetPrinterId(printerId);
    }
    std::string printerName;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_PRINTERNAME, printerName)) {
        printerInfo.SetPrinterName(printerName);
    }
    std::string description;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_DESCRIPTION, description)) {
        printerInfo.SetDescription(description);
    }
    std::string uri;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_URI, uri)) {
        printerInfo.SetUri(uri);
    }
    std::string printerMake;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_PRINTER_MAKE, printerMake)) {
        printerInfo.SetPrinterMake(printerMake);
    }
    std::string alias;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_INFO_ALIAS, uri)) {
        printerInfo.SetUri(uri);
    }
    std::string options;
    if (GetStringOrUndefined(env, printerInfoAni, PARAM_JOB_OPTION, options)) {
        printerInfo.SetOption(options);
    }
}

PrinterInfo PrinterInfoAniHelper::ParsePrinterInformation(ani_env *env, ani_object printerInformation)
{
    PRINT_HILOGI("enter AniPrinterInConvert");
    PrinterInfo info;
    const char* printerIdStr = "printerId";
    std::string printerId;
    if (GetStringOrUndefined(env, printerInformation, printerIdStr, printerId)) {
        info.SetPrinterId(printerId);
    }
    const char* printerNameStr = "printerName";
    std::string printerName;
    if (GetStringOrUndefined(env, printerInformation, printerNameStr, printerName)) {
        info.SetPrinterName(printerName);
    }
    const char* printerStatusStr = "printerStatus";
    ani_int statusIndex;
    if (GetIntByName(env, printerInformation, printerStatusStr, statusIndex)) {
        uint32_t statusValue = GetEnumValueInt(env, "PrinterStatus", statusIndex);
        info.SetPrinterState(statusValue);
    }
    const char* descriptionStr = "description";
    std::string description;
    if (GetStringOrUndefined(env, printerInformation, descriptionStr, description)) {
        info.SetDescription(description);
    }
    const char* capabilityStr = "capability";
    ani_ref capabilityRef;
    if (GetRefFieldByName(env, printerInformation, capabilityStr, capabilityRef)) {
        PrinterCapability capability = PrinterCapabilityAniHelper::ParsePrinterCapability(env, capabilityRef);
        info.SetCapability(capability);
    }
    const char* uriStr = "uri";
    std::string uri;
    if (GetStringOrUndefined(env, printerInformation, uriStr, uri)) {
        info.SetUri(uri);
    }
    const char* printerMakeStr = "printerMake";
    std::string printerMake;
    if (GetStringOrUndefined(env, printerInformation, printerMakeStr, printerMake)) {
        info.SetPrinterMake(printerMake);
    }
    const char* optionsStr = "options";
    std::string options;
    if (GetStringOrUndefined(env, printerInformation, optionsStr, options)) {
        info.SetOption(options);
    }

    return info;
}

ani_object PrinterInfoAniHelper::CreatePrinterInfo(ani_env *env, const PrinterInfo& info)
{
    PRINT_HILOGI("enter CreatePrinterInfo");

    ani_object obj = {};
    static const char *className = "L@ohos/print/print/PrinterInfoImpl;";
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

    SetFieldString(env, cls, obj, PARAM_INFO_PRINTERID, info.GetPrinterId());
    SetFieldString(env, cls, obj, PARAM_INFO_PRINTERNAME, info.GetPrinterName());
    SetFieldDouble(env, cls, obj, PARAM_INFO_PRINTERICON, info.GetPrinterIcon());
    SetFieldString(env, cls, obj, PARAM_INFO_DESCRIPTION, info.GetDescription());
    SetFieldString(env, cls, obj, PARAM_INFO_URI, info.GetUri());
    SetFieldString(env, cls, obj, PARAM_INFO_PRINTER_MAKE, info.GetPrinterMake());
    SetFieldString(env, cls, obj, PARAM_INFO_ALIAS, info.GetAlias());
    SetFieldString(env, cls, obj, PARAM_JOB_OPTION, info.GetOption());
    SetFieldBoolean(env, cls, obj, PARAM_INFO_IS_DAFAULT_PRINTER, info.GetIsDefaultPrinter());
    SetFieldBoolean(env, cls, obj, PARAM_INFO_IS_LAST_USED_PRINTER, info.GetIsLastUsedPrinter());

    ani_enum_item printerStateEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrinterState;",
                                                       static_cast<int32_t>(info.GetPrinterState()));
    SetFieldEnum(env, obj, "<set>printerState", "L@ohos/print/print/PrinterState;:V", printerStateEnum);
    ani_enum_item printerStatusEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrinterStatus;",
                                                        static_cast<int32_t>(info.GetPrinterStatus()));
    SetFieldEnum(env, obj, "<set>printerStatus", "L@ohos/print/print/PrinterStatus;:V", printerStatusEnum);

    PrinterCapability cap;
    info.GetCapability(cap);
    ani_ref capabilityRef = PrinterCapabilityAniHelper::CreatePrinterCapability(env, cap);
    SetFieldRef(env, cls, obj, PARAM_INFO_CAPABILITY, capabilityRef);

    PrinterPreferences preferences;
    info.GetPreferences(preferences);
    ani_ref preferencesRef = PrinterPreferencesAniHelper::CreatePrinterPreferences(env, preferences);
    SetFieldRef(env, cls, obj, PARAM_INFO_PRINTER_PREFERENCES, preferencesRef);
    return obj;
}

ani_object PrinterInfoAniHelper::CreatePrinterInformation(ani_env *env, const PrinterInfo& info)
{
    PRINT_HILOGI("enter CreatePrinterInformation");

    ani_object obj = {};
    static const char *className = "L@ohos/print/PrinterInformation;";
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

    const std::string printerIdStr = "printerId";
    SetFieldString(env, cls, obj, printerIdStr, info.GetPrinterId());

    const std::string printerNameStr = "printerName";
    SetFieldString(env, cls, obj, printerNameStr, info.GetPrinterName());

    const std::string printerStatusStr = "printerStatus";
    SetFieldInt(env, cls, obj, printerStatusStr, static_cast<int32_t>(info.GetPrinterState()));

    const std::string descriptionStr = "description";
    SetFieldString(env, cls, obj, descriptionStr, info.GetDescription());

    const std::string capabilityStr = "capability";
    PrinterCapability cap;
    info.GetCapability(cap);
    ani_ref capabilityRef = PrinterCapabilityAniHelper::CreatePrinterCapability(env, cap);
    SetFieldRef(env, cls, obj, capabilityStr, capabilityRef);

    const std::string uriStr = "uri";
    SetFieldString(env, cls, obj, uriStr, info.GetUri());

    const std::string printerMakeStr = "printerMake";
    SetFieldString(env, cls, obj, printerMakeStr, info.GetPrinterMake());

    const std::string optionsStr = "options";
    SetFieldString(env, cls, obj, optionsStr, info.GetOption());

    return obj;
}

bool PrinterInfoAniHelper::GetPrinterInfoArray(ani_env *env, ani_object param, std::vector<PrinterInfo> &res)
{
    ani_double length;
    ani_status status = ANI_ERROR;
    status = env->Object_GetPropertyByName_Double(param, "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_GetPropertyByName_Double fail, status = %{public}u", status);
        return false;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_ref aniPrinterInfo;
        status = env->Object_CallMethodByName_Ref(param, "$_get",
            "L@ohos/print/PrinterInfo;", &aniPrinterInfo, static_cast<ani_int>(i));
        if (status != ANI_OK) {
            PRINT_HILOGE("Object_CallMethodByName_Ref fail, status = %{public}u", status);
            return false;
        }
        PrinterInfo info = ParsePrinterInfo(env, aniPrinterInfo);
        res.push_back(info);
    }
    return true;
}

bool PrinterInfoAniHelper::ValidateProperty(ani_env *env, ani_ref printerInfo)
{
    std::map<std::string, PrintParamStatus> propertyList = {
            {PARAM_INFO_PRINTERID, PRINT_PARAM_NOT_SET},
            {PARAM_INFO_PRINTERNAME, PRINT_PARAM_NOT_SET},
            {PARAM_INFO_PRINTERSTATE, PRINT_PARAM_OPT},
            {PARAM_INFO_PRINTERICON, PRINT_PARAM_OPT},
            {PARAM_INFO_DESCRIPTION, PRINT_PARAM_OPT},
            {PARAM_INFO_CAPABILITY, PRINT_PARAM_OPT},
            {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
            {PARAM_INFO_PRINTER_MAKE, PRINT_PARAM_OPT},
            {PARAM_INFO_URI, PRINT_PARAM_OPT},
            {PARAM_INFO_PRINTER_STATUS, PRINT_PARAM_OPT},
            {PARAM_INFO_PRINTER_PREFERENCES, PRINT_PARAM_OPT},
            {PARAM_INFO_ALIAS, PRINT_PARAM_OPT},
            {PARAM_INFO_IS_DAFAULT_PRINTER, PRINT_PARAM_OPT},
            {PARAM_INFO_IS_LAST_USED_PRINTER, PRINT_PARAM_OPT},
    };
    return true;
}
}  // namespace OHOS::Print