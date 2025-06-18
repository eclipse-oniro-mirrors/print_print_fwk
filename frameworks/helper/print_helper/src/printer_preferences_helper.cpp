/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "printer_preferences_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE = "defaultDuplexMode";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY = "defaultPrintQuality";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE = "defaultMediaType";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID = "defaultPageSizeId";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_ORIENTATION = "defaultOrientation";
static constexpr const char *PARAM_PREFERENCES_DEFAULT_COLORMODE = "defaultColorMode";
static constexpr const char *PARAM_PREFERENCES_BORDERLESS = "borderless";
static constexpr const char *PARAM_PREFERENCES_COLLATE = "defaultCollate";
static constexpr const char *PARAM_PREFERENCES_REVERSE = "defaultReverse";
static constexpr const char *PARAM_PREFERENCES_OPTION = "options";

napi_value PrinterPreferencesHelper::MakeJsObject(napi_env env, const PrinterPreferences &preferences)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    if (preferences.HasDefaultDuplexMode()) {
        NapiPrintUtils::SetUint32Property(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE, preferences.GetDefaultDuplexMode());
    }

    if (preferences.HasDefaultPrintQuality()) {
        NapiPrintUtils::SetUint32Property(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY, preferences.GetDefaultPrintQuality());
    }

    if (preferences.HasDefaultMediaType()) {
        NapiPrintUtils::SetStringPropertyUtf8(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, preferences.GetDefaultMediaType());
    }

    if (preferences.HasDefaultPageSizeId()) {
        NapiPrintUtils::SetStringPropertyUtf8(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, preferences.GetDefaultPageSizeId());
    }

    if (preferences.HasDefaultOrientation()) {
        NapiPrintUtils::SetUint32Property(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_ORIENTATION, preferences.GetDefaultOrientation());
    }

    if (preferences.HasDefaultColorMode()) {
        NapiPrintUtils::SetUint32Property(
            env, jsObj, PARAM_PREFERENCES_DEFAULT_COLORMODE, preferences.GetDefaultColorMode());
    }

    if (preferences.HasBorderless()) {
        NapiPrintUtils::SetBooleanProperty(env, jsObj, PARAM_PREFERENCES_BORDERLESS, preferences.GetBorderless());
    }

    if (preferences.HasDefaultCollate()) {
        NapiPrintUtils::SetBooleanProperty(env, jsObj, PARAM_PREFERENCES_COLLATE, preferences.GetDefaultCollate());
    }

    if (preferences.HasDefaultReverse()) {
        NapiPrintUtils::SetBooleanProperty(env, jsObj, PARAM_PREFERENCES_REVERSE, preferences.GetDefaultReverse());
    }

    if (preferences.HasOption()) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_PREFERENCES_OPTION, preferences.GetOption());
    }

    return jsObj;
}

void PrinterPreferencesHelper::BuildFromBoolOptionJs(napi_env env, napi_value jsValue,
    std::shared_ptr<PrinterPreferences> nativeObj)
{
    auto jsBorderless = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_BORDERLESS);
    if (jsBorderless != nullptr) {
        nativeObj->SetBorderless(NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_PREFERENCES_BORDERLESS));
    }

    auto jsCollate = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_COLLATE);
    if (jsCollate != nullptr) {
        nativeObj->SetDefaultCollate(NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_PREFERENCES_COLLATE));
    }

    auto jsReverse = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_REVERSE);
    if (jsReverse != nullptr) {
        nativeObj->SetDefaultReverse(NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_PREFERENCES_REVERSE));
    }
}

std::shared_ptr<PrinterPreferences> PrinterPreferencesHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrinterPreferences>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of printer preferences");
        return nullptr;
    }

    auto jsDefaultDuplexMode = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE);
    if (jsDefaultDuplexMode != nullptr) {
        nativeObj->SetDefaultDuplexMode(
            NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE));
    }

    auto jsDefaultPrintQuality =
        NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY);
    if (jsDefaultPrintQuality != nullptr) {
        nativeObj->SetDefaultPrintQuality(
            NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY));
    }

    auto jsDefaultMediaType = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE);
    if (jsDefaultMediaType != nullptr) {
        nativeObj->SetDefaultMediaType(
            NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE));
    }

    auto jsDefaultPageSizeId = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID);
    if (jsDefaultPageSizeId != nullptr) {
        nativeObj->SetDefaultPageSizeId(
            NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID));
    }

    auto jsDefaultOrientation = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_ORIENTATION);
    if (jsDefaultOrientation != nullptr) {
        nativeObj->SetDefaultOrientation(
            NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PREFERENCES_DEFAULT_ORIENTATION));
    }

    auto jsDefaultColorMode = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_DEFAULT_COLORMODE);
    if (jsDefaultColorMode != nullptr) {
        nativeObj->SetDefaultColorMode(
            NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PREFERENCES_DEFAULT_COLORMODE));
    }
    auto jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREFERENCES_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PREFERENCES_OPTION));
    }

    BuildFromBoolOptionJs(env, jsValue, nativeObj);
    return nativeObj;
}

bool PrinterPreferencesHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_PREFERENCES_DEFAULT_DEPLEX_MODE, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_DEFAULT_PRINT_QUALITY, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_DEFAULT_MEDIA_TYPE, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_DEFAULT_PAFESIZE_ID, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_DEFAULT_ORIENTATION, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_DEFAULT_COLORMODE, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_BORDERLESS, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_COLLATE, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_REVERSE, PRINT_PARAM_OPT},
        {PARAM_PREFERENCES_OPTION, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    return NapiPrintUtils::VerifyProperty(names, propertyList);
}
}  // namespace OHOS::Print
