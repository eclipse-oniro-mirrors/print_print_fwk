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

#include "scan_option_descriptor_helper.h"
#include "scan_range_helper.h"
#include "napi_scan_utils.h"
#include "scan_log.h"

namespace OHOS::Scan {
static constexpr const char *PARAM_OPTION_NAME = "optionName";
static constexpr const char *PARAM_OPTION_INDEX = "optionIndex";
static constexpr const char *PARAM_OPTION_TITLE = "optionTitle";
static constexpr const char *PARAM_OPTION_DESC = "optionDesc";
static constexpr const char *PARAM_OPTION_TYPE = "optionType";
static constexpr const char *PARAM_OPTION_UNIT = "optionUnit";
static constexpr const char *PARAM_OPTION_CONSTRAINT_TYPE = "optionConstraintType";
static constexpr const char *PARAM_OPTION_CONSTRAINT_STRING = "optionConstraintString";
static constexpr const char *PARAM_OPTION_CONSTRAINT_NUMBER = "optionConstraintInt";

napi_value ScanOptionDescriptorHelper::MakeJsObject(napi_env env, const ScanOptionDescriptor &desc)
{
    napi_value jsObj = nullptr;

    if (napi_create_object(env, &jsObj) != napi_ok) {
        SCAN_HILOGE("Failed to create JavaScript object");
        return nullptr;
    }
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_OPTION_NAME, desc.GetOptionName());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_OPTION_INDEX, desc.GetOptionIndex());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_OPTION_TITLE, desc.GetOptionTitle());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_OPTION_DESC, desc.GetOptionDesc());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_OPTION_TYPE, desc.GetOptionType());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_OPTION_UNIT, desc.GetOptionUnit());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_OPTION_CONSTRAINT_TYPE, desc.GetOptionConstraintType());

    std::vector<std::string> optionConstraintString;
    desc.GetOptionConstraintString(optionConstraintString);
    napi_value arrOptionConstraintString = nullptr;
    SCAN_CALL(env, napi_create_array(env, &arrOptionConstraintString));
    uint32_t arrOptionConstraintStringLength = optionConstraintString.size();
    for (uint32_t i = 0; i < arrOptionConstraintStringLength; i++) {
        napi_value value = NapiScanUtils::CreateStringUtf8(env, optionConstraintString[i]);
        SCAN_CALL(env, napi_set_element(env, arrOptionConstraintString, i, value));
    }
    SCAN_CALL(env, napi_set_named_property(env, jsObj, PARAM_OPTION_CONSTRAINT_STRING, arrOptionConstraintString));

    std::vector<int32_t> optionConstraintNumber;
    desc.GetOptionConstraintNumber(optionConstraintNumber);
    napi_value arrOptionConstraintNumber = nullptr;
    SCAN_CALL(env, napi_create_array(env, &arrOptionConstraintNumber));
    uint32_t arrOptionConstraintNumberLength = optionConstraintNumber.size();
    for (uint32_t i = 0; i < arrOptionConstraintNumberLength; i++) {
        napi_value value;
        SCAN_CALL(env, napi_create_int32(env, optionConstraintNumber[i], &value));
        SCAN_CALL(env, napi_set_element(env, arrOptionConstraintNumber, i, value));
    }
    SCAN_CALL(env, napi_set_named_property(env, jsObj, PARAM_OPTION_CONSTRAINT_NUMBER, arrOptionConstraintNumber));

    return jsObj;
}

napi_value ScanOptionDescriptorHelper::GetValueFromJs(napi_env env, napi_value jsValue,
                                                      std::shared_ptr<ScanOptionDescriptor> &nativeObj)
{
    std::string optionName = NapiScanUtils::GetStringPropertyUtf8(env, jsValue, PARAM_OPTION_NAME);
    nativeObj->SetOptionName(optionName);

    uint32_t optionIndex = NapiScanUtils::GetUint32Property(env, jsValue, PARAM_OPTION_INDEX);
    nativeObj->SetOptionIndex(optionIndex);

    std::string optionTitle = NapiScanUtils::GetStringPropertyUtf8(env, jsValue, PARAM_OPTION_TITLE);
    nativeObj->SetOptionTitle(optionTitle);

    std::string optionDesc = NapiScanUtils::GetStringPropertyUtf8(env, jsValue, PARAM_OPTION_DESC);
    nativeObj->SetOptionDesc(optionDesc);

    uint32_t optionType = NapiScanUtils::GetUint32Property(env, jsValue, PARAM_OPTION_TYPE);
    nativeObj->SetOptionType(optionType);

    uint32_t optionUnit = NapiScanUtils::GetUint32Property(env, jsValue, PARAM_OPTION_UNIT);
    nativeObj->SetOptionUnit(optionUnit);

    uint32_t optionConstraintType = NapiScanUtils::GetUint32Property(env, jsValue, PARAM_OPTION_CONSTRAINT_TYPE);
    nativeObj->SetOptionConstraintType(optionConstraintType);
    return nullptr;
}

napi_value ScanOptionDescriptorHelper::ObjSetOptionConstraintString(napi_env env, napi_value jsValue,
                                                                    std::shared_ptr<ScanOptionDescriptor> &nativeObj)
{
    napi_value jsOptionConstraintString = NapiScanUtils::GetNamedProperty(env, jsValue, PARAM_OPTION_CONSTRAINT_STRING);
    bool isArray = false;
    if (jsOptionConstraintString != nullptr) {
        std::vector<std::string> optionConstraintString;
        SCAN_CALL(env, napi_is_array(env, jsOptionConstraintString, &isArray));
        if (!isArray) {
            SCAN_HILOGE("Invalid list of option constraint string");
            return nullptr;
        }
        uint32_t arrayLength = 0;
        SCAN_CALL(env, napi_get_array_length(env, jsOptionConstraintString, &arrayLength));
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsConstraintString;
            std::string constraintString;
            SCAN_CALL(env, napi_get_element(env, jsOptionConstraintString, index, &jsConstraintString));
            constraintString = NapiScanUtils::GetValueString(env, jsConstraintString);
            optionConstraintString.emplace_back(constraintString);
        }
        nativeObj->SetOptionConstraintString(optionConstraintString);
    }
    return nullptr;
}

napi_value ScanOptionDescriptorHelper::ObjSetOptionConstraintNumber(napi_env env, napi_value jsValue,
                                                                    std::shared_ptr<ScanOptionDescriptor> &nativeObj)
{
    napi_value jsOptionConstraintNumber = NapiScanUtils::GetNamedProperty(env, jsValue, PARAM_OPTION_CONSTRAINT_NUMBER);
    bool isArray = false;
    if (jsOptionConstraintNumber != nullptr) {
        std::vector<int32_t> optionConstraintNumber;
        SCAN_CALL(env, napi_is_array(env, jsOptionConstraintNumber, &isArray));
        if (!isArray) {
            SCAN_HILOGE("Invalid list of option constraint number");
            return nullptr;
        }
        uint32_t arrayLength = 0;
        SCAN_CALL(env, napi_get_array_length(env, jsOptionConstraintNumber, &arrayLength));
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsConstraintNumber;
            int32_t constraintNumber;
            SCAN_CALL(env, napi_get_element(env, jsOptionConstraintNumber, index, &jsConstraintNumber));
            SCAN_CALL(env, napi_get_value_int32(env, jsConstraintNumber, &constraintNumber));
            optionConstraintNumber.emplace_back(constraintNumber);
        }
        nativeObj->SetOptionConstraintNumber(optionConstraintNumber);
    }
    return nullptr;
}

std::shared_ptr<ScanOptionDescriptor> ScanOptionDescriptorHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<ScanOptionDescriptor>();
    
    auto names = NapiScanUtils::GetPropertyNames(env, jsValue);
    for (const auto& name : names) {
        SCAN_HILOGD("Property: %{public}s", name.c_str());
    }

    GetValueFromJs(env, jsValue, nativeObj);
    ObjSetOptionConstraintString(env, jsValue, nativeObj);
    ObjSetOptionConstraintNumber(env, jsValue, nativeObj);
    return nativeObj;
}
}  // namespace OHOS::Scan
