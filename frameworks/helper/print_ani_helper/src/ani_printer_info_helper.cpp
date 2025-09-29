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
    ani_ref stateEnum = nullptr;
    uint32_t stateValue = 0;
    if (GetRefProperty(env, static_cast<ani_object>(printerInfo), PARAM_INFO_PRINTERSTATE, stateEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(stateEnum), stateValue)) {
        info.SetPrinterState(stateValue);
    }
    ani_ref statusEnum;
    uint32_t statusValue = 0;
    if (GetRefProperty(env, static_cast<ani_object>(printerInfo), PARAM_INFO_PRINTER_STATUS, statusEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(statusEnum), statusValue)) {
        info.SetPrinterState(statusValue);
    }
    int32_t printerIcon = 0;
    if (GetIntProperty(env, static_cast<ani_object>(printerInfo), PARAM_INFO_PRINTERICON, printerIcon)) {
        info.SetPrinterIcon(static_cast<uint32_t>(printerIcon));
    }
    ani_ref capabilityRef;
    if (GetRefProperty(env,  static_cast<ani_object>(printerInfo), PARAM_INFO_CAPABILITY, capabilityRef)) {
        PrinterCapability capability = PrinterCapabilityAniHelper::ParsePrinterCapability(env, capabilityRef);
        info.SetCapability(capability);
    }
    return info;
}

void PrinterInfoAniHelper::ParsePrinterInfoStringField(ani_env *env, ani_ref printerInfoAni, PrinterInfo& printerInfo)
{
    std::string printerId;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_PRINTERID, printerId)) {
        printerInfo.SetPrinterId(printerId);
    }
    std::string printerName;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_PRINTERNAME, printerName)) {
        printerInfo.SetPrinterName(printerName);
    }
    std::string description;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_DESCRIPTION, description)) {
        printerInfo.SetDescription(description);
    }
    std::string uri;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_URI, uri)) {
        printerInfo.SetUri(uri);
    }
    std::string printerMake;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_PRINTER_MAKE, printerMake)) {
        printerInfo.SetPrinterMake(printerMake);
    }
    std::string alias;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_INFO_ALIAS, uri)) {
        printerInfo.SetUri(uri);
    }
    std::string options;
    if (GetStringProperty(env, static_cast<ani_object>(printerInfoAni), PARAM_JOB_OPTION, options)) {
        printerInfo.SetOption(options);
    }
}

PrinterInfo PrinterInfoAniHelper::ParsePrinterInformation(ani_env *env, ani_object printerInformation)
{
    PRINT_HILOGI("enter AniPrinterInConvert");
    PrinterInfo info;
    std::string printerId;
    if (GetStringProperty(env, printerInformation, PARAM_INFO_PRINTERID, printerId)) {
        info.SetPrinterId(printerId);
    }
    std::string printerName;
    if (GetStringProperty(env, printerInformation, PARAM_INFO_PRINTERNAME, printerName)) {
        info.SetPrinterName(printerName);
    }
    ani_ref statusEnum;
    uint32_t statusValue = 0;
    if (GetRefProperty(env,  static_cast<ani_object>(printerInformation), PARAM_INFO_PRINTER_STATUS, statusEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(statusEnum), statusValue)) {
        info.SetPrinterState(statusValue);
    }
    std::string description;
    if (GetStringProperty(env, printerInformation, PARAM_INFO_DESCRIPTION, description)) {
        info.SetDescription(description);
    }
    ani_ref capabilityRef;
    if (GetRefProperty(env,  static_cast<ani_object>(printerInformation), PARAM_INFO_CAPABILITY, capabilityRef)) {
        PrinterCapability capability = PrinterCapabilityAniHelper::ParsePrinterCapability(env, capabilityRef);
        info.SetCapability(capability);
    }
    std::string uri;
    if (GetStringProperty(env, printerInformation, PARAM_INFO_URI, uri)) {
        info.SetUri(uri);
    }
    std::string printerMake;
    if (GetStringProperty(env, printerInformation, PARAM_INFO_PRINTER_MAKE, printerMake)) {
        info.SetPrinterMake(printerMake);
    }
    std::string options;
    if (GetStringProperty(env, printerInformation, PARAM_JOB_OPTION, options)) {
        info.SetOption(options);
    }

    return info;
}

ani_object PrinterInfoAniHelper::CreatePrinterInfo(ani_env *env, const PrinterInfo& info)
{
    PRINT_HILOGI("enter CreatePrinterInfo");

    static const char *className = "L@ohos/print/print/PrinterInfoImpl;";
    ani_object obj = CreateObject(env, nullptr, className);
    SetStringProperty(env, obj, PARAM_INFO_PRINTERID, info.GetPrinterId());
    SetStringProperty(env, obj, PARAM_INFO_PRINTERNAME, info.GetPrinterName());
    SetIntPropertyObject(env, obj, PARAM_INFO_PRINTERICON, static_cast<int32_t>(info.GetPrinterIcon()));
    SetStringProperty(env, obj, PARAM_INFO_DESCRIPTION, info.GetDescription());
    SetStringProperty(env, obj, PARAM_INFO_URI, info.GetUri());
    SetStringProperty(env, obj, PARAM_INFO_PRINTER_MAKE, info.GetPrinterMake());
    SetStringProperty(env, obj, PARAM_INFO_ALIAS, info.GetAlias());
    SetStringProperty(env, obj, PARAM_JOB_OPTION, info.GetOption());
    ani_enum_item printerStateEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrinterState;",
        static_cast<int32_t>(info.GetPrinterState()));
    SetRefProperty(env, obj, PARAM_INFO_PRINTERSTATE, static_cast<ani_ref>(printerStateEnum));
    ani_enum_item printerStatusEnum = CreateEnumByIndex(env, "L@ohos/print/print/PrinterStatus;",
        static_cast<int32_t>(info.GetPrinterStatus()));
    SetRefProperty(env, obj, PARAM_INFO_PRINTER_STATUS, static_cast<ani_ref>(printerStatusEnum));
    PrinterCapability cap;
    info.GetCapability(cap);
    ani_ref capabilityRef = PrinterCapabilityAniHelper::CreatePrinterCapability(env, cap);
    SetRefProperty(env, obj, PARAM_INFO_CAPABILITY, capabilityRef);
    PrinterPreferences preferences;
    info.GetPreferences(preferences);
    ani_ref preferencesRef = PrinterPreferencesAniHelper::CreatePrinterPreferences(env, preferences);
    SetRefProperty(env, obj, PARAM_INFO_PRINTER_PREFERENCES, preferencesRef);
    return obj;
}

ani_object PrinterInfoAniHelper::CreatePrinterInformation(ani_env *env, const PrinterInfo& info)
{
    PRINT_HILOGI("enter CreatePrinterInformation");

    static const char *className = "L@ohos/print/print/PrinterInformationImp;";
    ani_object obj = CreateObject(env, nullptr, className);

    SetStringProperty(env, obj, PARAM_INFO_PRINTERID, info.GetPrinterId());

    SetStringProperty(env, obj, PARAM_INFO_PRINTERNAME, info.GetPrinterName());

    SetIntProperty(env, obj, PARAM_INFO_PRINTER_STATUS, static_cast<int32_t>(info.GetPrinterState()));

    SetStringProperty(env, obj, PARAM_INFO_DESCRIPTION, info.GetDescription());

    PrinterCapability cap;
    info.GetCapability(cap);
    ani_ref capabilityRef = PrinterCapabilityAniHelper::CreatePrinterCapability(env, cap);
    SetRefProperty(env, obj, PARAM_INFO_CAPABILITY, capabilityRef);

    SetStringProperty(env, obj, PARAM_INFO_URI, info.GetUri());

    SetStringProperty(env, obj, PARAM_INFO_PRINTER_MAKE, info.GetPrinterMake());

    SetStringProperty(env, obj, PARAM_JOB_OPTION, info.GetOption());

    return obj;
}

bool PrinterInfoAniHelper::GetPrinterInfoArray(ani_env *env, ani_object param, std::vector<PrinterInfo> &res)
{
    ani_size length = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(param), &length)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return false;
    }

    PRINT_HILOGD("printerInfo array size = %{public}d", static_cast<int32_t>(length));
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_ref aniPrinterInfo;
        status = env->Object_CallMethodByName_Ref(param, "$_get",
            "L@ohos/print/print/PrinterInfoImpl;", &aniPrinterInfo, static_cast<ani_int>(i));
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
    };
    return true;
}
}  // namespace OHOS::Print