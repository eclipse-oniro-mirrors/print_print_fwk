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
#include "print_resolution_helper.h"
#include "print_constant.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_RESOLUTION_ID = "id";
static constexpr const char *PARAM_RESOLUTION_HORIZONTALDPI = "horizontalDpi";
static constexpr const char *PARAM_RESOLUTION_VERTICALDPI = "verticalDpi";
napi_value PrintResolutionHelper::MakeJsObject(napi_env env, const PrintResolution &resolution)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_RESOLUTION_ID, resolution.GetId());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RESOLUTION_HORIZONTALDPI, resolution.GetHorizontalDpi());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RESOLUTION_VERTICALDPI, resolution.GetVerticalDpi());
    return jsObj;
}

std::shared_ptr<PrintResolution> PrintResolutionHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    std::shared_ptr<PrintResolution> nativeObj = nullptr;
    if (ValidateProperty(env, jsValue)) {
        nativeObj = std::make_shared<PrintResolution>();
        std::string id = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_RESOLUTION_ID);
        uint32_t horizontalDpi = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RESOLUTION_HORIZONTALDPI);
        uint32_t verticalDpi = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RESOLUTION_VERTICALDPI);
        if (id == "") {
            PRINT_HILOGE("Invalid resolution id");
            return nullptr;
        }
        nativeObj->SetId(id);
        nativeObj->SetHorizontalDpi(horizontalDpi);
        nativeObj->SetVerticalDpi(verticalDpi);
    }
    return nativeObj;
}

bool PrintResolutionHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_RESOLUTION_ID, PRINT_PARAM_NOT_SET},
        {PARAM_RESOLUTION_HORIZONTALDPI, PRINT_PARAM_NOT_SET},
        {PARAM_RESOLUTION_VERTICALDPI, PRINT_PARAM_NOT_SET},
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
