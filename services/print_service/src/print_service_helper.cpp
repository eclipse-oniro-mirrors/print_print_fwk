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
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS::Print {
const uint32_t MAX_RETRY_TIMES = 2;
const uint32_t START_ABILITY_INTERVAL = 200;
using namespace Security::AccessToken;

std::mutex PrintServiceHelper::connectionListLock_;

PrintServiceHelper::~PrintServiceHelper()
{
}

bool PrintServiceHelper::CheckPermission(const std::string &name)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        PRINT_HILOGE("invalid token id %{private}d", tokenId);
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, name);
    if (result != PERMISSION_GRANTED) {
        if (name == PERMISSION_NAME_PRINT) {
            result = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NAME_PRINT_JOB);
        }
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
        auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        if (!ret) {
            break;
        } else {
            PRINT_HILOGE("PrintServiceHelper::StartAbility failed, err is %{public}d, retry is %{public}u", ret, retry);
            std::this_thread::sleep_for(std::chrono::milliseconds(START_ABILITY_INTERVAL));
        }
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceHelper::StartAbility --> failed ");
        return false;
    }
    return true;
}

bool PrintServiceHelper::StartExtensionAbility(const AAFwk::Want &want)
{
    PRINT_HILOGD("enter PrintServiceHelper::StartExtensionAbility");
    PRINT_HILOGD("want: %{public}s", want.ToUri().c_str());
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    sptr<PrintAbilityConnection> printAbilityConnection = new (std::nothrow) PrintAbilityConnection();
    if (printAbilityConnection == nullptr) {
        PRINT_HILOGE("fail to create printAbilityConnection");
        return false;
    }
    PRINT_HILOGD("PrintServiceHelper::StartExtensionAbility %{public}s %{public}s",
        element.GetBundleName().c_str(),
        element.GetAbilityName().c_str());
    while (retry++ < MAX_RETRY_TIMES) {
        if (AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, printAbilityConnection, -1) == 0) {
            PRINT_HILOGI("PrintServiceHelper::StartExtensionAbility ConnectAbility success");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(START_ABILITY_INTERVAL));
        PRINT_HILOGE("PrintServiceHelper::StartExtensionAbility %{public}u", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceHelper::StartExtensionAbility --> failed ");
        return false;
    }
    std::lock_guard<std::mutex> autoLock(connectionListLock_);
    extConnectionMap_[ExtensionAbilityType::PRINT_EXTENSION_ABILITY].push_back(printAbilityConnection);
    return true;
}

bool PrintServiceHelper::StartPluginPrintExtAbility(const AAFwk::Want &want)
{
    PRINT_HILOGD("enter PrintServiceHelper::StartPluginPrintExtAbility");
    PRINT_HILOGD("want: %{public}s", want.ToUri().c_str());
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    sptr<PrintAbilityConnection> printAbilityConnection = new (std::nothrow) PrintAbilityConnection();
    if (printAbilityConnection == nullptr) {
        PRINT_HILOGE("fail to create printAbilityConnection");
        return false;
    }
    PRINT_HILOGD("PrintServiceHelper::StartPluginPrintExtAbility %{public}s %{public}s",
        element.GetBundleName().c_str(),
        element.GetAbilityName().c_str());
    while (retry++ < MAX_RETRY_TIMES) {
        if (AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, printAbilityConnection, -1) == 0) {
            PRINT_HILOGI("PrintServiceHelper::StartPluginPrintExtAbility ConnectAbility success");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(START_ABILITY_INTERVAL));
        PRINT_HILOGE("PrintServiceHelper::StartPluginPrintExtAbility %{public}u", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceHelper::StartPluginPrintExtAbility --> failed ");
        return false;
    }
    std::lock_guard<std::mutex> autoLock(connectionListLock_);
    extConnectionMap_[ExtensionAbilityType::SERVICE_EXTENSION_ABILITY].push_back(printAbilityConnection);
    return true;
}

bool PrintServiceHelper::DisconnectAbility(ExtensionAbilityType extensionAbilityType)
{
    PRINT_HILOGD("enter PrintServiceHelper::DisconnectAbility");
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    std::lock_guard<std::mutex> connectionLock(connectionListLock_);
    auto connectionListIt = extConnectionMap_.find(extensionAbilityType);
    if (connectionListIt == extConnectionMap_.end() || connectionListIt->second.size() == 0) {
        PRINT_HILOGW("cannot find connect list of this type");
        return false;
    }

    while (!connectionListIt->second.empty()) {
        if (retry++ >= MAX_RETRY_TIMES) {
            PRINT_HILOGW("PrintServiceHelper::DisconnectAbility --> failed ");
            break;
        }
        for (auto connIt = connectionListIt->second.begin(); connIt != connectionListIt->second.end();) {
            if (AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(*connIt) == 0) {
                PRINT_HILOGI("PrintServiceHelper::DisconnectAbility success");
                connIt = connectionListIt->second.erase(connIt);
            } else {
                ++connIt;
            }
        }
    }

    extConnectionMap_.erase(connectionListIt);
    return true;
}

bool PrintServiceHelper::CheckPluginPrintConnected()
{
    bool pluginConnected = true;
    std::lock_guard<std::mutex> connectionLock(connectionListLock_);
    auto connectionListIt = extConnectionMap_.find(ExtensionAbilityType::SERVICE_EXTENSION_ABILITY);
    if (connectionListIt == extConnectionMap_.end() || connectionListIt->second.size() == 0) {
        PRINT_HILOGW("cannot find connect list of this type");
        return false;
    }

    for (auto connIt = connectionListIt->second.begin(); connIt != connectionListIt->second.end();) {
        if ((*connIt) != nullptr && !(*connIt)->IsConnected()) {
            pluginConnected = false;
            connIt = connectionListIt->second.erase(connIt);
        } else {
            ++connIt;
        }
    }
    return pluginConnected;
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

void PrintServiceHelper::PrintSubscribeCommonEvent()
{
    if (isSubscribeCommonEvent) {
        return;
    }
    isSubscribeCommonEvent = true;
    PRINT_HILOGI("listen common event.");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_ENTER_HIBERNATE);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_EXIT_HIBERNATE);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_ENTER_FORCE_SLEEP);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_EXIT_FORCE_SLEEP);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    userStatusListener = std::make_shared<PrintEventSubscriber>(subscribeInfo);
    if (userStatusListener == nullptr) {
        PRINT_HILOGE("create userStatusListener failed.");
        return;
    }
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(userStatusListener)) {
        PRINT_HILOGE("subscribe common event failed");
    }
}
}  // namespace OHOS
