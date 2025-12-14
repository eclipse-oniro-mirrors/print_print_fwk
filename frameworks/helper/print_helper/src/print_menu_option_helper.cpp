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

#include "print_menu_option_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_MENU_OPTION_MENUITEMRESOURCENAME = "menuItemResourceName";
static constexpr const char *PARAM_MENU_OPTION_ISSELECT = "isSelect";
napi_value PrintCustomOptionHelper::MakeJsObject(napi_env env,  const PrintCustomOption &customOption)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_MENU_OPTION_MENUITEMRESOURCENAME, menuOption.GetMenuItemResourceName());
    NapiPrintUtils::SetBooleanProperty(env, jsObj, PARAM_MENU_OPTION_ISSELECT, menuOption.GetIsSelect());
    return jsObj;
}

std::shared_ptr<PrintMenuOption> PrintMenuOptionHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    std::shared_ptr<PrintMenuOption> nativeObj;

    if (ValidateProperty(env, jsValue)) {
        nativeObj = std::shared_ptr<PrintMenuOption>;
        std::string menuItemResourceName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_MENU_OPTION_MENUITEMRESOURCENAME);
        bool isSelect = NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_MENU_OPTION_ISSELECT);
        if (nativeObj == nullptr) {
            PRINT_HILOGE("nativeObj is nullptr");
            return nullptr;
        }
        nativeObj->SetMenuItemResourceName(menuItemResourceName);
        nativeObj->SetIsSelect(isSelect);
        }
    }
    return nativeObj;
}

bool PrintMenuOptionHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_MENU_OPTION_MENUITEMRESOURCENAME, PRINT_PARAM_NOT_SET},
        {PARAM_MENU_OPTION_ISSELECT, PRINT_PARAM_NOT_SET},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    return NapiPrintUtils::VerifyProperty(names, propertyList);
}
}  // namespace OHOS::Print
