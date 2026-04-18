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
#include "print_shared_host_helper.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_IP = "ip";
static constexpr const char *PARAM_SHARE_NAME = "shareName";
static constexpr const char *PARAM_WORKGROUP_NAME = "workgroupName";
napi_value PrintSharedHostHelper::MakeJsObject(napi_env env, const PrintSharedHost &SharedHost)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_IP, SharedHost.GetIp());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SHARE_NAME, SharedHost.GetShareName());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_WORKGROUP_NAME, SharedHost.GetWorkgroupName());
    return jsObj;
}

napi_value PrintSharedHostHelper::MakeJsObjectArray(napi_env env, const std::vector<PrintSharedHost> &sharedHosts)
{
    napi_value array = nullptr;
    napi_status status = napi_create_array(env, &array);
    if (status != napi_ok) {
        PRINT_HILOGE("Failed to create array");
        return nullptr;
    }
    
    uint32_t index = 0;
    for (const auto& host : sharedHosts) {
        napi_value jsHost = MakeJsObject(env, host);
        status = napi_set_element(env, array, index++, jsHost);
        if (status != napi_ok) {
            PRINT_HILOGE("Failed to set array element");
        }
    }
    return array;
}

std::shared_ptr<PrintSharedHost> PrintSharedHostHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintSharedHost>();

    std::string ip = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_IP);
    std::string shareName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_SHARE_NAME);
    std::string workgroupName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_WORKGROUP_NAME);
    nativeObj->SetIp(ip);
    nativeObj->SetShareName(shareName);
    nativeObj->SetWorkgroupName(workgroupName);
    return nativeObj;
}

}  // namespace OHOS::Print
