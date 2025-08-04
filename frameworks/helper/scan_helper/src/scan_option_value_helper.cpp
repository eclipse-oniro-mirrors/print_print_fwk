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

#include "scan_option_value_helper.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
static constexpr const char *PARAM_SCAN_OPTION_VALUE_TYPE = "valueType";
static constexpr const char *PARAM_SCAN_OPTION_NUM_VALUE = "numValue";
static constexpr const char *PARAM_SCAN_OPTION_STR_VALUE = "strValue";
static constexpr const char *PARAM_SCAN_OPTION_BOOL_VALUE = "boolValue";

napi_value ScanOptionValueHelper::MakeJsObject(napi_env env, const ScanOptionValue &optionValue)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));

    ScanOptionValueType valueType = optionValue.GetScanOptionValueType();
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_SCAN_OPTION_VALUE_TYPE, valueType);

    if (valueType == SCAN_VALUE_NUM) {
        NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_OPTION_NUM_VALUE, optionValue.GetNumValue());
    } else if (valueType == SCAN_VALUE_STR) {
        NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SCAN_OPTION_STR_VALUE, optionValue.GetStrValue());
    } else if (valueType == SCAN_VALUE_BOOL) {
        NapiScanUtils::SetBooleanProperty(env, jsObj, PARAM_SCAN_OPTION_BOOL_VALUE, optionValue.GetBoolValue());
    }
    return jsObj;
}

std::shared_ptr<ScanOptionValue> ScanOptionValueHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<ScanOptionValue>();
    if (!ValidateProperty(env, jsValue)) {
        SCAN_HILOGE("Invalid property of scan option value object");
        return nullptr;
    }
    ScanOptionValueType valueType = (ScanOptionValueType
        ) NapiScanUtils::GetUint32Property(env, jsValue, PARAM_SCAN_OPTION_VALUE_TYPE);
    nativeObj->SetScanOptionValueType(valueType);
    if (valueType == SCAN_VALUE_NUM) {
        int32_t numValue = NapiScanUtils::GetInt32Property(env, jsValue, PARAM_SCAN_OPTION_NUM_VALUE);
        nativeObj->SetNumValue(numValue);
    } else if (valueType == SCAN_VALUE_STR) {
        std::string strValue = NapiScanUtils::GetStringPropertyUtf8(env, jsValue, PARAM_SCAN_OPTION_STR_VALUE);
        nativeObj->SetStrValue(strValue);
    } else if (valueType == SCAN_VALUE_BOOL) {
        bool boolValue = NapiScanUtils::GetBooleanProperty(env, jsValue, PARAM_SCAN_OPTION_BOOL_VALUE);
        nativeObj->SetBoolValue(boolValue);
    }
    SCAN_HILOGD("Build scan option value succeed");
    return nativeObj;
}

bool ScanOptionValueHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, ScanParamStatus> propertyList = {
        {PARAM_SCAN_OPTION_VALUE_TYPE, SCAN_PARAM_OPT},
        {PARAM_SCAN_OPTION_NUM_VALUE, SCAN_PARAM_OPT},
        {PARAM_SCAN_OPTION_STR_VALUE, SCAN_PARAM_OPT},
        {PARAM_SCAN_OPTION_BOOL_VALUE, SCAN_PARAM_OPT},
    };
    auto names = NapiScanUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            SCAN_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = SCAN_PARAM_SET;
    }
    bool hasValueType = propertyList[PARAM_SCAN_OPTION_VALUE_TYPE] == SCAN_PARAM_SET;
    if (!hasValueType) {
        return false;
    }
    return true;
}
} // namespace OHOS::Scan
