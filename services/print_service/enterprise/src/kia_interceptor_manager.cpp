/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "../include/kia_interceptor_manager.h"
#include "print_log.h"
#include "print_constant.h"
#include "ipc_skeleton.h"
#include "print_common_death_recipient.h"
#include "bundle_mgr_client.h"
#include "bundle_info.h"

namespace OHOS::Print {

KiaInterceptorManager& KiaInterceptorManager::GetInstance()
{
    static KiaInterceptorManager instance;
    return instance;
}

int32_t KiaInterceptorManager::RegisterCallback(const sptr<IKiaInterceptorCallback> &callback)
{
    PRINT_HILOGI("KiaInterceptorManager::RegisterCallback start");
    if (callback == nullptr) {
        PRINT_HILOGE("callback is null");
        return E_PRINT_INVALID_PARAMETER;
    }

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    PRINT_HILOGD("RegisterCallback from PID: %{public}d", callerPid);

    std::lock_guard<std::mutex> lock(mutex_);

    if (callback_ != nullptr) {
        PRINT_HILOGW("KIA interceptor callback already registered, replacing it");
        auto remoteObject = callback_->AsObject();
        if (remoteObject != nullptr && deathRecipient_ != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
        callback_ = nullptr;
        deathRecipient_ = nullptr;
    }

    callback_ = callback;
    
    auto remoteObject = callback_->AsObject();
    if (remoteObject != nullptr) {
        deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
            new PrintCommonDeathRecipient([this](const sptr<IRemoteObject> &remote) {
                PRINT_HILOGI("KIA interceptor callback died, auto-unregistering");
                this->UnregisterCallback();
            }));
        remoteObject->AddDeathRecipient(deathRecipient_);
    }
    
    PRINT_HILOGI("RegisterCallback success");
    return E_PRINT_NONE;
}

int32_t KiaInterceptorManager::UnregisterCallback()
{
    PRINT_HILOGI("KiaInterceptorManager::UnregisterCallback start");
    
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    PRINT_HILOGD("UnregisterCallback from PID: %{public}d", callerPid);

    std::lock_guard<std::mutex> lock(mutex_);

    if (callback_ == nullptr) {
        PRINT_HILOGW("No callback registered for PID: %{public}d", callerPid);
        return E_PRINT_INVALID_PARAMETER;
    }

    auto remoteObject = callback_->AsObject();
    if (remoteObject != nullptr && deathRecipient_ != nullptr) {
        remoteObject->RemoveDeathRecipient(deathRecipient_);
    }

    callback_ = nullptr;
    deathRecipient_ = nullptr;
    
    PRINT_HILOGI("UnregisterCallback success");
    return E_PRINT_NONE;
}

bool KiaInterceptorManager::IsCallbackRegistered()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return callback_ != nullptr;
}

bool KiaInterceptorManager::CheckPrintJobNeedReject(const std::string &jobId)
{
    PRINT_HILOGI("KiaInterceptorManager::CheckPrintJobNeedReject jobId=%{private}s", jobId.c_str());

    int32_t pid = IPCSkeleton::GetCallingPid();
    std::string callerAppId = GetCallerAppId(jobId);

    std::lock_guard<std::mutex> lock(mutex_);
    if (callback_ == nullptr) {
        PRINT_HILOGD("No KIA interceptor callback registered, allow print events");
        return false;
    }
    bool shouldReject = callback_->OnCheckPrintJobNeedReject(pid, callerAppId);
    return shouldReject;
}

int32_t KiaInterceptorManager::RegisterCallerAppId(const std::string &jobId,
    const std::string &callerBundleName, const int32_t &userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    bundleMgrClient.GetBundleInfo(callerBundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    PRINT_HILOGD("callerBundleName: %{public}s, callerAppId: %{public}s",
        callerBundleName.c_str(), bundleInfo.appId.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    jobIdToAppIdMap_.insert(std::make_pair(jobId, bundleInfo.appId));
    return E_PRINT_NONE;
}

void KiaInterceptorManager::RemoveCallerAppId(const std::string &jobId)
{
    PRINT_HILOGI("KiaInterceptorManager::RemoveCallerAppId jobId=%{private}s", jobId.c_str());

    std::lock_guard<std::mutex> lock(mutex_);
    jobIdToAppIdMap_.erase(jobId);
}

std::string KiaInterceptorManager::GetCallerAppId(const std::string &jobId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jobIdToAppIdMap_.find(jobId);
    return (it != jobIdToAppIdMap_.end()) ? it->second : "";
}

} // namespace OHOS::Print
