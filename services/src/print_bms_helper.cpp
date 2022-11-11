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

#include "print_bms_helper.h"

#include "bundle_constants.h"
#include "bundle_mgr_client.h"
#include "print_log.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS::Print {

using namespace OHOS::AppExecFwk::Constants;

PrintBMSHelper::PrintBMSHelper() : sptrBundleMgr_(nullptr), printBMSDeath_(nullptr)
{}

PrintBMSHelper::~PrintBMSHelper()
{}

bool PrintBMSHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    std::lock_guard<std::mutex> lock(mutex_);
    /*
    if (!GetProxy()) {
        return false;
    }
    */
    std::vector<int> osAccountIds;
    if (AccountSA::OsAccountManager::QueryActiveOsAccountIds(osAccountIds) != ERR_OK) {
        PRINT_HILOGE("failed to QueryActiveOsAccountIds!");
        return false;
    }
    if (osAccountIds.size() == 0) {
        PRINT_HILOGE("no os account acquired!");
        return false;
    }
    for (auto userId : osAccountIds) {
        PRINT_HILOGE("active userId = %{public}d", userId);
        AppExecFwk::ExtensionAbilityInfo extInfo;
        extInfo.bundleName = "com.open.harmony.packagemag";
        extInfo.name = "com.open.harmony.packagemag.ServiceAbility2";
        extensionInfos.emplace_back(extInfo);
        //sptrBundleMgr_->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::PRINT,
        //    userId, extensionInfos);
    }
    return true;
}

bool PrintBMSHelper::GetProxy()
{
    if (sptrBundleMgr_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            PRINT_HILOGE("Failed to get system ability mgr.");
            return false;
        }

        sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObject == nullptr) {
            PRINT_HILOGE("Failed to get bundle manager service.");
            return false;
        }

        sptrBundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        if (sptrBundleMgr_ == nullptr) {
            PRINT_HILOGE("Failed to get system bundle manager services ability");
            return false;
        }

        printBMSDeath_ = new PrintBMSDeathRecipient();
        if (printBMSDeath_ == nullptr) {
            PRINT_HILOGE("Failed to create death Recipient ptr BMSDeathRecipient");
            return false;
        }
        if (!sptrBundleMgr_->AsObject()->AddDeathRecipient(printBMSDeath_)) {
            PRINT_HILOGW("Failed to add death recipient");
        }
    }

    return true;
}

void PrintBMSHelper::ResetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if ((sptrBundleMgr_ != nullptr) && (sptrBundleMgr_->AsObject() != nullptr)) {
        sptrBundleMgr_->AsObject()->RemoveDeathRecipient(printBMSDeath_);
    }
    sptrBundleMgr_ = nullptr;
}
}  // namespace OHOS