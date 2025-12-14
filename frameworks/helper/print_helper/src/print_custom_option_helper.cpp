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

#include "print_custom_option_helper.h"
#include "print_menu_option_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_CUSTOMOPTION_OPTIONNAME = "optionName";
static constexpr const char *PARAM_CUSTOMOPTION_TYPE = "type";
static constexpr const char *PARAM_CUSTOMOPTION_BUNDLENAME = "bundleName";
static constexpr const char *PARAM_CUSTOMOPTION_OPTIONRESOURCENAME = "optionResourceName";
static constexpr const char *PARAM_CUSTOMOPTION_VALUE = "value";
static constexpr const char *PARAM_CUSTOMOPTION_ERRORRESOURCENAME = "errorResourceName";
napi_value PrintCustomOptionHelper::MakeJsObject(napi_env env,  const PrintCustomOption &customOption)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_CUSTOMOPTION_OPTIONNAME, customOption.GetOptionName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CUSTOMOPTION_TYPE, customOption.GetType());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_CUSTOMOPTION_BUNDLENAME, customOption.GetBundleName());
    NapiPrintUtils::SetStringPropertyUtf8(
        env, jsObj, PARAM_CUSTOMOPTION_OPTIONRESOURCENAME, customOption.GetOptionResourceName());
    if (customOption.HasValue()) {
        if (static_cast<ComponentType>(customOption.GetType()) == ComponentType::SWITCH) {
            NapiPrintUtils::SetBooleanProperty(env, jsObj, PARAM_CUSTOMOPTION_VALUE, customOption.GetIsSelect());
        } else if (static_cast<ComponentType>(customOption.GetType()) == ComponentType::MENU) {
            if (!CreateMenuOption(env, jsObj, customOption)) {
                PRINT_HILOGE("Failed to create menuOption property of print customOption");
                return nullptr;
            }
        }
    }
    if (customOption.HasErrorResourceName()) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_CUSTOMOPTION_ERRORRESOURCENAME, customOption.GetErrorResourceName());
    }
    return jsObj;
}

std::shared_ptr<PrintCustomOption> PrintCustomOptionHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintCustomOption>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print customOption");
        return nullptr;
    }

    std::string jsOptionName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_CUSTOMOPTION_OPTIONNAME);
    uint32_t jsType = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_CUSTOMOPTION_TYPE);
    std::string jsBundleName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_CUSTOMOPTION_BUNDLENAME);
    std::string jsOptionResourceName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_CUSTOMOPTION_OPTIONRESOURCENAME);
    nativeObj->SetOptionName(jsOptionName);
    nativeObj->SetType(jsType);
    nativeObj->SetBundleName(jsBundleName);
    nativeObj->SetOptionResourceName(jsOptionResourceName);

    napi_value jsCustomOptionValue = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CUSTOMOPTION_VALUE);
    if (jsCustomOptionValue != nullptr) {
        if (static_cast<ComponentType>(jsType) == ComponentType::MENU) {
            NapiPrintUtils::ProcessJsArrayProperty<PrintMenuOption>(env, jsValue, PARAM_CUSTOMOPTION_VALUE,
            [nativeObj](const std::vector<PrintMenuOption>& menuOption) {
                nativeObj->SetMenuOption(menuOption);
            },
            PrintMenuOptionHelper::BuildFromJs);
        }
    } else if (static_cast<ComponentType>(jsType) == ComponentType::SWITCH) {
        if (!CreateMenuOption(env, jsObj, customOption)) {
            nativeObj->SetIsSelect(NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_CUSTOMOPTION_VALUE));
        }
    }

    BuildJsWorkerIsLegal(env, jsValue, nativeObj);
    PRINT_HILOGI("Build Print CustomOption succeed");
    return nativeObj;
}

void PrintCustomOptionHelper::BuildJsWorkerIsLegal(napi_env env, napi_value jsValue,
    std::shared_ptr<PrintAttributes> &nativeObj)
{
    if (nativeObj == nullptr) {
        PRINT_HILOGE("nativeObj is nullptr");
        return;
    }
    auto jsErrorResourceName = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CUSTOMOPTION_ERRORRESOURCENAME);
    if (jsErrorResourceName != nullptr) {
        nativeObj->SetErrorResourceName(NapiPrintUtils::GetStringFromValueUtf8(env, jsErrorResourceName));
    }
}

bool PrintCustomOptionHelper::CreateMenuOption(napi_env env, napi_value &jsPrintCustomOption,
    const PrintCustomOption &customOption)
{
    napi_value jsMenuOption = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &jsMenuOption), false);
    std::vector<PrintMenuOption> menuOption;
    customOption.GetMenuOption(menuOption);
    uint32_t arrLength = menuOption.size();

    for (uint32_t index = 0; index < arrLength; index++) {
        napi_value value = PrintMenuOptionHelper::MakeJsObject(env, menuOption[index]);
        PRINT_CALL_BASE(env, napi_set_element(env, jsMenuOption, index, value), false);
    }
    PRINT_CALL_BASE(env,
        napi_set_named_property(env, jsPrintCustomOption, PARAM_CUSTOMOPTION_VALUE, jsMenuOption), false);
    return true;
}

bool PrintCustomOptionHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_CUSTOMOPTION_OPTIONNAME, PRINT_PARAM_NOT_SET},
        {PARAM_CUSTOMOPTION_TYPE, PRINT_PARAM_NOT_SET},
        {PARAM_CUSTOMOPTION_BUNDLENAME, PRINT_PARAM_NOT_SET},
        {PARAM_CUSTOMOPTION_OPTIONRESOURCENAME, PRINT_PARAM_NOT_SET},
        {PARAM_CUSTOMOPTION_VALUE, PRINT_PARAM_OPT},
        {PARAM_CUSTOMOPTION_ERRORRESOURCENAME, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    return true;
}
}  // namespace OHOS::Print
