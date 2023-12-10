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

#include "print_extension_info_helper.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_EXTINFO_EXTENSION_ID = "extensionId";
static constexpr const char *PARAM_EXTINFO_VENDOR_ID = "vendorId";
static constexpr const char *PARAM_EXTINFO_VENDOR_NAME = "vendorName";
static constexpr const char *PARAM_EXTINFO_ICON = "vendorIcon";
static constexpr const char *PARAM_EXTINFO_VERSION = "version";
napi_value PrintExtensionInfoHelper::MakeJsObject(napi_env env, const PrintExtensionInfo &info)
{
    napi_value jsObj = nullptr;

    napi_create_object(env, &jsObj);
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_EXTINFO_EXTENSION_ID, info.GetExtensionId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_EXTINFO_VENDOR_ID, info.GetVendorId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_EXTINFO_VENDOR_NAME, info.GetVendorName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_EXTINFO_ICON, info.GetVendorIcon());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_EXTINFO_VERSION, info.GetVersion());
    return jsObj;
}

std::shared_ptr<PrintExtensionInfo> PrintExtensionInfoHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintExtensionInfo>();

    auto names = NapiPrintUtils::GetPropertyNames(env, jsValue);
    for (auto name : names) {
        PRINT_HILOGD("Property: %{public}s", name.c_str());
    }

    std::string extensionId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_EXTINFO_EXTENSION_ID);
    std::string vendorId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_EXTINFO_VENDOR_ID);
    std::string vendorName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_EXTINFO_VENDOR_NAME);
    uint32_t iconId = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_EXTINFO_ICON);
    std::string version = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_EXTINFO_VERSION);
    nativeObj->SetExtensionId(extensionId);
    nativeObj->SetVendorId(vendorId);
    nativeObj->SetVendorName(vendorName);
    nativeObj->SetVendorIcon(iconId);
    nativeObj->SetVersion(version);

    return nativeObj;
}
}  // namespace OHOS::Print
