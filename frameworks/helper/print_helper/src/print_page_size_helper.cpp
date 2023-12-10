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

#include "print_page_size_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_PAGESIZE_ID = "id";
static constexpr const char *PARAM_PAGESIZE_NAME = "name";
static constexpr const char *PARAM_PAGESIZE_WIDTH = "width";
static constexpr const char *PARAM_PAGESIZE_HEIGHT = "height";
napi_value PrintPageSizeHelper::MakeJsObject(napi_env env, const PrintPageSize &pageSize)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));

    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_PAGESIZE_ID, pageSize.GetId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_PAGESIZE_NAME, pageSize.GetName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PAGESIZE_WIDTH, pageSize.GetWidth());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PAGESIZE_HEIGHT, pageSize.GetHeight());
    return jsObj;
}

std::shared_ptr<PrintPageSize> PrintPageSizeHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintPageSize>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print page size");
        return nullptr;
    }

    std::string id = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PAGESIZE_ID);
    std::string name = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PAGESIZE_NAME);
    uint32_t width = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PAGESIZE_WIDTH);
    uint32_t height = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PAGESIZE_HEIGHT);

    if (id == "") {
        PRINT_HILOGE("Invalid resolution id");
        return nullptr;
    }

    nativeObj->SetId(id);
    nativeObj->SetName(name);
    nativeObj->SetWidth(width);
    nativeObj->SetHeight(height);
    PRINT_HILOGI("Build Page Size succeed");
    return nativeObj;
}

bool PrintPageSizeHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_PAGESIZE_ID, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_NAME, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_WIDTH, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_HEIGHT, PRINT_PARAM_NOT_SET},
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
} // namespace OHOS::Print
