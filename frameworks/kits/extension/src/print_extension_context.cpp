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

namespace OHOS {
namespace AbilityRuntime {
const size_t PrintExtensionContext::CONTEXT_TYPE_ID(std::hash<const char *> {}("PrintExtensionContext"));
int PrintExtensionContext::ILLEGAL_REQUEST_CODE(-1);

ErrCode PrintExtensionContext::StartAbility(const AAFwk::Want &want) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, ILLEGAL_REQUEST_CODE);
    PRINT_HILOGD("%{public}s. End calling StartAbility. ret=%{public}d", __func__, err);
    if (err != ERR_OK) {
        PRINT_HILOGE("PrintExtensionContext::StartAbility is failed %{public}d", err);
    }
    return err;
}

ErrCode PrintExtensionContext::StartAbility(const AAFwk::Want &want, const AAFwk::StartOptions &startOptions) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode err =
        AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, startOptions, token_, ILLEGAL_REQUEST_CODE);
    PRINT_HILOGD("%{public}s. End calling StartAbility. ret=%{public}d", __func__, err);
    if (err != ERR_OK) {
        PRINT_HILOGE("PrintExtensionContext::StartAbility is failed %{public}d", err);
    }
    return err;
}

bool PrintExtensionContext::ConnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode ret = ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    PRINT_HILOGD("PrintExtensionContext::ConnectAbility ErrorCode = %{public}d", ret);
    return ret == ERR_OK;
}

ErrCode PrintExtensionContext::StartAbilityWithAccount(const AAFwk::Want &want, int accountId) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    PRINT_HILOGD("%{public}d accountId:", accountId);
    ErrCode err =
        AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, ILLEGAL_REQUEST_CODE, accountId);
    PRINT_HILOGD("%{public}s. End calling StartAbilityWithAccount. ret=%{public}d", __func__, err);
    if (err != ERR_OK) {
        PRINT_HILOGE("PrintExtensionContext::StartAbilityWithAccount is failed %{public}d", err);
    }
    return err;
}

ErrCode PrintExtensionContext::StartAbilityWithAccount(
    const AAFwk::Want &want, int accountId, const AAFwk::StartOptions &startOptions) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(
        want, startOptions, token_, ILLEGAL_REQUEST_CODE, accountId);
    PRINT_HILOGD("%{public}s. End calling StartAbilityWithAccount. ret=%{public}d", __func__, err);
    if (err != ERR_OK) {
        PRINT_HILOGE("PrintExtensionContext::StartAbilityWithAccount is failed %{public}d", err);
    }
    return err;
}

bool PrintExtensionContext::ConnectAbilityWithAccount(
    const AAFwk::Want &want, int accountId, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode ret = ConnectionManager::GetInstance().ConnectAbilityWithAccount(token_, want, accountId, connectCallback);
    PRINT_HILOGD("PrintExtensionContext::ConnectAbilityWithAccount ErrorCode = %{public}d", ret);
    return ret == ERR_OK;
}

ErrCode PrintExtensionContext::DisconnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode ret = ConnectionManager::GetInstance().DisconnectAbility(token_, want.GetElement(), connectCallback);
    if (ret != ERR_OK) {
        PRINT_HILOGE("%{public}s end DisconnectAbility error, ret=%{public}d", __func__, ret);
    }
    PRINT_HILOGD("%{public}s end DisconnectAbility", __func__);
    return ret;
}

ErrCode PrintExtensionContext::TerminateAbility()
{
    PRINT_HILOGD("%{public}s begin.", __func__);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, -1, nullptr);
    if (err != ERR_OK) {
        PRINT_HILOGE("PrintExtensionContext::TerminateAbility is failed %{public}d", err);
    }
    PRINT_HILOGD("%{public}s end.", __func__);
    return err;
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