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

#include "print_preview_attribute_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_range_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_PREATTRIBUTE_RANGE = "previewRange";
static constexpr const char *PARAM_PREATTRIBUTE_RESULT = "result";

napi_value PrintPreviewAttributeHelper::MakeJsObject(napi_env env, const PrintPreviewAttribute &preview)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));

    if (preview.HasResult()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PREATTRIBUTE_RESULT, preview.GetResult());
    }
    PrintRange range;
    preview.GetPreviewRange(range);

    napi_value jsPreviewRange = PrintRangeHelper::MakeJsObject(env,  range);
    PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_PREATTRIBUTE_RANGE, jsPreviewRange));
    return jsObj;
}

std::shared_ptr<PrintPreviewAttribute> PrintPreviewAttributeHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintPreviewAttribute>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print preview attribute");
        return nullptr;
    }

    napi_value jsPreviewRange = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREATTRIBUTE_RANGE);
    auto previewRangePtr = PrintRangeHelper::BuildFromJs(env, jsPreviewRange);
    if (previewRangePtr == nullptr) {
        PRINT_HILOGE("Failed to build print preview attribute object from js");
        return nullptr;
    }
    nativeObj->SetPreviewRange(*previewRangePtr);

    napi_value jsResult = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREATTRIBUTE_RESULT);
    if (jsResult != nullptr) {
        auto result = NapiPrintUtils::GetUint32FromValue(env, jsResult);
        nativeObj->SetResult(result);
    }
    PRINT_HILOGE("Build Print Preview Attribute succeed");
    return nativeObj;
}

bool PrintPreviewAttributeHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_PREATTRIBUTE_RANGE, PRINT_PARAM_NOT_SET},
        {PARAM_PREATTRIBUTE_RESULT, PRINT_PARAM_OPT},
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
