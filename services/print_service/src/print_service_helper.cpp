/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "print_service_helper.h"
#include <thread>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "print_constant.h"
#include "print_log.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
const uint32_t MAX_RETRY_TIMES = 3;
const uint32_t START_ABILITY_INTERVAL = 2;
using namespace Security::AccessToken;

PrintServiceHelper::~PrintServiceHelper()
{
}

bool PrintServiceHelper::CheckPermission(const std::string &name)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        PRINT_HILOGE("invalid token id %{public}d", tokenId);
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, name);
    if (result != PERMISSION_GRANTED) {
        PRINT_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
}

bool PrintServiceHelper::StartAbility(const AAFwk::Want &want)
{
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        PRINT_HILOGD("PrintServiceHelper::StartAbility %{public}s %{public}s",
            element.GetBundleName().c_str(), element.GetAbilityName().c_str());
        if (AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want) == 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(START_ABILITY_INTERVAL));
        PRINT_HILOGD("PrintServiceHelper::StartAbility %{public}d", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceHelper::StartAbility --> failed ");
        return false;
    }
    return true;
}

bool PrintServiceHelper::KillAbility(const std::string &bundleName)
{
    for (uint32_t retry = 0; retry < MAX_RETRY_TIMES; ++retry) {
        if (AAFwk::AbilityManagerClient::GetInstance()->KillProcess(bundleName) == ERR_OK) {
            return true;
        }
        PRINT_HILOGD("PrintServiceHelper::KillAbility %{public}d %{public}s",
            retry, bundleName.c_str());
    }
    PRINT_HILOGE("PrintServiceHelper::KillAbility %{public}s failed", bundleName.c_str());
    return false;
}

bool PrintServiceHelper::StartPrintServiceExtension(const AAFwk::Want &want, int32_t requestCode_)
{
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        PRINT_HILOGD("PrintServiceHelper::StartPrintServiceExtension %{public}s %{public}s",
            element.GetBundleName().c_str(), element.GetAbilityName().c_str());
        if (AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, requestCode_) == 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(START_ABILITY_INTERVAL));
        PRINT_HILOGD("PrintServiceHelper::StartPrintServiceExtension %{public}d", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceHelper::StartPrintServiceExtension --> failed ");
        return false;
    }
    return true;
}

sptr<IRemoteObject> PrintServiceHelper::GetBundleMgr()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        PRINT_HILOGE("Failed to get system ability mgr.");
        return nullptr;
    }

    return systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

bool PrintServiceHelper::QueryAccounts(std::vector<int> &accountList)
{
    if (AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountList) != ERR_OK) {
        PRINT_HILOGE("failed to QueryActiveOsAccountIds!");
        return false;
    }
    if (accountList.size() == 0) {
        PRINT_HILOGE("no os account acquired!");
        return false;
    }
    return true;
}

bool PrintServiceHelper::QueryExtension(sptr<AppExecFwk::IBundleMgr> mgr, int userId,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    if (mgr != nullptr) {
        mgr->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::PRINT, userId, extensionInfos);
        return true;
    }
    PRINT_HILOGE("Invalid bundle manager");
    return false;
}

bool PrintServiceHelper::QueryNameForUid(sptr<AppExecFwk::IBundleMgr> mgr, int32_t userId, std::string& name)
{
    if (mgr != nullptr) {
        mgr->GetNameForUid(userId, name);
        return true;
    }
    PRINT_HILOGE("Invalid bundle manager");
    return false;
}

bool PrintServiceHelper::IsSyncMode()
{
    return false;
}
}  // namespace OHOS
