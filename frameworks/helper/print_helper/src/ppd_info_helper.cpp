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

#include "printer_info_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "printer_capability_helper.h"
#include "printer_preferences_helper.h"
#include "print_log.h"
#include "ppd_info_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_INFO_MANUFACTURER = "manufacturer";
static constexpr const char *PARAM_INFO_NICKNAME = "nickName";
static constexpr const char *PARAM_INFO_PPDNAME = "ppdName";

napi_value PpdInfoHelper::MakeJsSimpleObject(napi_env env, const PpdInfo &info)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_MANUFACTURER, info.GetManufacturer());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_NICKNAME, info.GetNickName());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_PPDNAME, info.GetPpdName());
    return jsObj;
}

std::shared_ptr<PpdInfo> PpdInfoHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PpdInfo>();
    std::string manufacturer = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_MANUFACTURER);
    std::string nickName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_NICKNAME);
    std::string ppdName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_INFO_PPDNAME);
    if (manufacturer.empty() || nickName.empty() || ppdName.empty()) {
        PRINT_HILOGE("illegal PpdInfo");
        return nullptr;
    }
    nativeObj->SetManufacturer(manufacturer);
    nativeObj->SetNickName(nickName);
    nativeObj->SetPpdName(ppdName);
    return nativeObj;
}
}  // namespace OHOS::Print
