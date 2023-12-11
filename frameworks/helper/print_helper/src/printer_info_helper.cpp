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

#include "printer_info_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "printer_capability_helper.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_INFO_PRINTERID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState";
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";
static constexpr const char *PARAM_JOB_OPTION = "options";

napi_value PrinterInfoHelper::MakeJsObject(napi_env env, const PrinterInfo &info)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_PRINTERID, info.GetPrinterId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_PRINTERNAME, info.GetPrinterName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_INFO_PRINTERSTATE, info.GetPrinterState());

    if (info.GetPrinterIcon() != PRINT_INVALID_ID) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_INFO_PRINTERICON, info.GetPrinterIcon());
    }

    if (info.GetDescription() != "") {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DESCRIPTION, info.GetDescription());
    }

    if (info.HasCapability()) {
        PrinterCapability cap;
        info.GetCapability(cap);
        napi_value jsCapability = PrinterCapabilityHelper::MakeJsObject(env, cap);
        PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_INFO_CAPABILITY, jsCapability));
    }

    if (info.HasOption()) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_OPTION, info.GetOption());
    }
    return jsObj;
}

std::shared_ptr<PrinterInfo> PrinterInfoHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterInfo>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of printer info");
        return nullptr;
    }

    std::string printerId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_PRINTERID);
    std::string printerName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_PRINTERNAME);
    if (printerId == "" || printerName == "") {
        PRINT_HILOGE("Invalid printer id[%{private}s] or printer name[%{private}s]",
            printerId.c_str(), printerName.c_str());
        return nullptr;
    }
    nativeObj->SetPrinterId(printerId);
    nativeObj->SetPrinterName(printerName);

    uint32_t printerState = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_INFO_PRINTERSTATE);
    if (printerState >= PRINTER_UNKNOWN) {
        PRINT_HILOGE("Invalid printer state");
        return nullptr;
    }
    nativeObj->SetPrinterState(printerState);

    auto jsIcon = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_PRINTERICON);
    if (jsIcon != nullptr) {
        nativeObj->SetPrinterIcon(NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_INFO_PRINTERICON));
    }

    auto jsDesc = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_DESCRIPTION);
    if (jsDesc != nullptr) {
        nativeObj->SetDescription(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_DESCRIPTION));
    }

    auto jsCapability = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_INFO_CAPABILITY);
    if (jsCapability != nullptr) {
        auto capabilityPtr = PrinterCapabilityHelper::BuildFromJs(env, jsCapability);
        if (capabilityPtr == nullptr) {
            PRINT_HILOGE("Failed to build printer info object from js");
            return nullptr;
        }
        nativeObj->SetCapability(*capabilityPtr);
    }

    auto jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_OPTION));
    }
    return nativeObj;
}

bool PrinterInfoHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_INFO_PRINTERID, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERNAME, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERSTATE, PRINT_PARAM_NOT_SET},
        {PARAM_INFO_PRINTERICON, PRINT_PARAM_OPT},
        {PARAM_INFO_DESCRIPTION, PRINT_PARAM_OPT},
        {PARAM_INFO_CAPABILITY, PRINT_PARAM_OPT},
        {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
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
