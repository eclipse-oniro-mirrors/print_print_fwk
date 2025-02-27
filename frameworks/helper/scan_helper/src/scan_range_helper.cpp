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

#include "scan_range_helper.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
static constexpr const char *PARAM_RANGE_MINVALUE = "minValue";
static constexpr const char *PARAM_RANGE_MAXVALUE = "maxValue";
static constexpr const char *PARAM_RANGE_QUANTVALUE = "quantValue";

napi_value ScanRangeHelper::MakeJsObject(napi_env env, const ScanRange &range)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));

    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_RANGE_MINVALUE, range.GetMinValue());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_RANGE_MAXVALUE, range.GetMaxValue());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_RANGE_QUANTVALUE, range.GetQuantValue());
    
    return jsObj;
}

std::shared_ptr<ScanRange> ScanRangeHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<ScanRange>();

    if (!ValidateProperty(env, jsValue)) {
        SCAN_HILOGE("Invalid property of scan range");
        return nullptr;
    }

    auto jsMinValue = NapiScanUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_MINVALUE);
    if (jsMinValue != nullptr) {
        nativeObj->SetMinValue(NapiScanUtils::GetInt32FromValue(env, jsMinValue));
    }

    auto jsMaxValue = NapiScanUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_MAXVALUE);
    if (jsMaxValue != nullptr) {
        nativeObj->SetMaxValue(NapiScanUtils::GetInt32FromValue(env, jsMaxValue));
    }

    auto jsQuantValue = NapiScanUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_QUANTVALUE);
    if (jsQuantValue != nullptr) {
        nativeObj->SetQuantValue(NapiScanUtils::GetInt32FromValue(env, jsQuantValue));
    }

    SCAN_HILOGD("Build Scan Range succeed");
    return nativeObj;
}

bool ScanRangeHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, ScanParamStatus> propertyList = {
        {PARAM_RANGE_MINVALUE, SCAN_PARAM_OPT},
        {PARAM_RANGE_MAXVALUE, SCAN_PARAM_OPT},
        {PARAM_RANGE_QUANTVALUE, SCAN_PARAM_OPT},
    };

    auto names = NapiScanUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            SCAN_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = SCAN_PARAM_SET;
    }
    bool hasMinValue = propertyList[PARAM_RANGE_MINVALUE] == SCAN_PARAM_SET;
    bool hasMaxValue = propertyList[PARAM_RANGE_MAXVALUE] == SCAN_PARAM_SET;
    bool hasQuantValue = propertyList[PARAM_RANGE_QUANTVALUE] == SCAN_PARAM_SET;
    if (!hasMinValue || !hasMaxValue || !hasQuantValue) {
        return false;
    }
    return true;
}
} // namespace OHOS::Scan
