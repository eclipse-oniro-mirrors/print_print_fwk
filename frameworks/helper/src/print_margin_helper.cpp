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

#include "print_margin_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_MARGIN_TOP = "top";
static constexpr const char *PARAM_MARGIN_BOTTOM = "bottom";
static constexpr const char *PARAM_MARGIN_LEFT = "left";
static constexpr const char *PARAM_MARGIN_RIGHT = "right";
napi_value PrintMarginHelper::MakeJsObject(napi_env env,  const PrintMargin &margin)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    if (margin.HasTop()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_TOP, margin.GetTop());
    }

    if (margin.HasBottom()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_BOTTOM, margin.GetBottom());
    }

    if (margin.HasLeft()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_LEFT, margin.GetLeft());
    }

    if (margin.HasRight()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_RIGHT, margin.GetRight());
    }
    return jsObj;
}

std::shared_ptr<PrintMargin> PrintMarginHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintMargin>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print margin");
        return nullptr;
    }

    auto jsTop = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_MARGIN_TOP);
    if (jsTop != nullptr) {
        nativeObj->SetTop(NapiPrintUtils::GetUint32FromValue(env, jsTop));
    }

    auto jsBottom = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_MARGIN_BOTTOM);
    if (jsBottom != nullptr) {
        nativeObj->SetBottom(NapiPrintUtils::GetUint32FromValue(env, jsBottom));
    }

    auto jsLeft = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_MARGIN_LEFT);
    if (jsLeft != nullptr) {
        nativeObj->SetLeft(NapiPrintUtils::GetUint32FromValue(env, jsLeft));
    }

    auto jsRight = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_MARGIN_RIGHT);
    if (jsRight != nullptr) {
        nativeObj->SetRight(NapiPrintUtils::GetUint32FromValue(env, jsRight));
    }

    PRINT_HILOGI("Build Print Margin succeed");
    return nativeObj;
}

bool PrintMarginHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_MARGIN_TOP, PRINT_PARAM_OPT},
        {PARAM_MARGIN_BOTTOM, PRINT_PARAM_OPT},
        {PARAM_MARGIN_LEFT, PRINT_PARAM_OPT},
        {PARAM_MARGIN_RIGHT, PRINT_PARAM_OPT},
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
