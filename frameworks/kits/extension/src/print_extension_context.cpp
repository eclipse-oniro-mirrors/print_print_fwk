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

#include "print_extension_context.h"

#include "ability_connection.h"
#include "ability_manager_client.h"
#include "print_log.h"
#include "print_error_converter.h"

namespace OHOS {
namespace AbilityRuntime {
const size_t PrintExtensionContext::CONTEXT_TYPE_ID(std::hash<const char *> {}("PrintExtensionContext"));
int PrintExtensionContext::ILLEGAL_REQUEST_CODE(-1);

ErrCode PrintExtensionContext::StartAbility(const AAFwk::Want &want) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    auto client = AAFwk::AbilityManagerClient::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(client, Print::E_PRINT_SERVER_FAILURE);
    ErrCode innerErr = client->StartAbility(want, token_, ILLEGAL_REQUEST_CODE);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::StartAbility is failed, err=%{public}d", printErr);
    }
    return printErr;
}

ErrCode PrintExtensionContext::StartAbility(const AAFwk::Want &want, const AAFwk::StartOptions &startOptions) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    auto client = AAFwk::AbilityManagerClient::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(client, Print::E_PRINT_SERVER_FAILURE);
    ErrCode innerErr = client->StartAbility(want, startOptions, token_, ILLEGAL_REQUEST_CODE);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::StartAbility is failed, err=%{public}d", printErr);
    }
    return printErr;
}

bool PrintExtensionContext::ConnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode innerErr = ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::ConnectAbility is failed, err=%{public}d", printErr);
    }
    return printErr == Print::E_PRINT_NONE;
}

ErrCode PrintExtensionContext::StartAbilityWithAccount(const AAFwk::Want &want, int accountId) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    PRINT_HILOGD("%{private}d accountId:", accountId);
    auto client = AAFwk::AbilityManagerClient::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(client, Print::E_PRINT_SERVER_FAILURE);
    ErrCode innerErr = client->StartAbility(want, token_, ILLEGAL_REQUEST_CODE, accountId);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::StartAbilityWithAccount is failed, err=%{public}d", printErr);
    }
    return printErr;
}

ErrCode PrintExtensionContext::StartAbilityWithAccount(
    const AAFwk::Want &want, int accountId, const AAFwk::StartOptions &startOptions) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    auto client = AAFwk::AbilityManagerClient::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(client, Print::E_PRINT_SERVER_FAILURE);
    ErrCode innerErr = client->StartAbility(want, startOptions, token_, ILLEGAL_REQUEST_CODE, accountId);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::StartAbilityWithAccount is failed, err=%{public}d", printErr);
    }
    return printErr;
}

bool PrintExtensionContext::ConnectAbilityWithAccount(
    const AAFwk::Want &want, int accountId, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode innerErr = ConnectionManager::GetInstance().ConnectAbilityWithAccount(token_, want, accountId,
        connectCallback);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::ConnectAbilityWithAccount is failed, err=%{public}d", printErr);
    }
    return printErr == Print::E_PRINT_NONE;
}

ErrCode PrintExtensionContext::DisconnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode innerErr = ConnectionManager::GetInstance().DisconnectAbility(token_, want.GetElement(), connectCallback);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("%{public}s end DisconnectAbility error, err=%{public}d", __func__, printErr);
    }
    PRINT_HILOGD("%{public}s end DisconnectAbility", __func__);
    return printErr;
}

ErrCode PrintExtensionContext::TerminateAbility()
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    auto client = AAFwk::AbilityManagerClient::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(client, Print::E_PRINT_SERVER_FAILURE);
    ErrCode innerErr = client->TerminateAbility(token_, -1, nullptr);
    ErrCode printErr = Print::PrintErrorConverter::FromAafwkError(innerErr);
    if (printErr != Print::E_PRINT_NONE) {
        PRINT_HILOGE("PrintExtensionContext::TerminateAbility is failed, err=%{public}d", printErr);
    }
    PRINT_HILOGD("%{public}s end.", __func__);
    return printErr;
}

AppExecFwk::AbilityType PrintExtensionContext::GetAbilityInfoType() const
{
    std::shared_ptr<AppExecFwk::AbilityInfo> info = GetAbilityInfo();
    if (info == nullptr) {
        PRINT_HILOGE("PrintExtensionContext::GetAbilityInfoType info == nullptr");
        return AppExecFwk::AbilityType::UNKNOWN;
    }

    return info->type;
}
} // namespace AbilityRuntime
} // namespace OHOS