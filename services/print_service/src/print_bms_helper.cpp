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
#include "ipc_skeleton.h"
#include "print_log.h"

namespace OHOS::Print {
using namespace OHOS::AppExecFwk::Constants;

PrintBMSHelper::PrintBMSHelper() : sptrBundleMgr_(nullptr), printBMSDeath_(nullptr), helper_(nullptr)
{}

PrintBMSHelper::~PrintBMSHelper()
{}

void PrintBMSHelper::SetHelper(const std::shared_ptr<PrintServiceHelper> &helper)
{
    helper_ = helper;
    sptrBundleMgr_ = nullptr;
}

bool PrintBMSHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (helper_ == nullptr || !GetProxy()) {
        return false;
    }
    std::vector<int> osAccountIds;
    if (!helper_->QueryAccounts(osAccountIds)) {
        return false;
    }

    for (auto userId : osAccountIds) {
        PRINT_HILOGI("active userId = %{public}d", userId);
        helper_->QueryExtension(sptrBundleMgr_, userId, extensionInfos);
    }
    return true;
}

std::string PrintBMSHelper::QueryCallerBundleName()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!GetProxy()) {
        return "";
    }
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = "";
    helper_->QueryNameForUid(sptrBundleMgr_, callerUid, bundleName);
    PRINT_HILOGD("callerUid = %{public}d, bundleName = %{public}s", callerUid, bundleName.c_str());
    return bundleName;
}

bool PrintBMSHelper::GetProxy()
{
    if (sptrBundleMgr_ == nullptr) {
        if (helper_ == nullptr) {
            PRINT_HILOGE("Invalid printer helper.");
            return false;
        }
        auto remoteObject = helper_->GetBundleMgr();
        if (remoteObject == nullptr) {
            PRINT_HILOGE("Failed to get bundle manager service.");
            return false;
        }

        sptrBundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        if (sptrBundleMgr_ == nullptr) {
            PRINT_HILOGE("Failed to get system bundle manager services ability");
            return false;
        }

        printBMSDeath_ = new (std::nothrow) PrintBMSDeathRecipient();
        if (printBMSDeath_ == nullptr) {
            PRINT_HILOGE("Failed to create death Recipient ptr BMSDeathRecipient");
            return false;
        }
        remoteObject->AddDeathRecipient(printBMSDeath_);
    }
    return true;
}

void PrintBMSHelper::ResetProxy(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        PRINT_HILOGE("remote is nullptr");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (sptrBundleMgr_ == nullptr) {
        PRINT_HILOGE("sptrBundleMgr_ is null");
        return;
    }

    auto serviceRemote = sptrBundleMgr_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        PRINT_HILOGD("need reset");
        serviceRemote->RemoveDeathRecipient(printBMSDeath_);
        sptrBundleMgr_ = nullptr;
        printBMSDeath_ = nullptr;
    }
}
}  // namespace OHOS
