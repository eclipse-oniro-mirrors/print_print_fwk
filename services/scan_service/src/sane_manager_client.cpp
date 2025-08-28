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

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "sane_service_load_callback.h"
#include "sane_manager_client.h"

namespace OHOS::Scan {
constexpr int32_t SANE_SERVICE_ID = 3709;
constexpr int32_t LOAD_SA_TIMEOUT_MS = 15000;
std::mutex SaneManagerClient::instanceLock_;
std::shared_mutex SaneManagerClient::serviceLock_;
sptr<SaneManagerClient> SaneManagerClient::instance_;

SaneManagerClient::SaneManagerClient() : proxy_(nullptr)
{
    deathRecipient_ = new SaneSaDeathRecipient();
}
SaneManagerClient::~SaneManagerClient()
{
    proxy_ = nullptr;
    deathRecipient_ = nullptr;
}

sptr<SaneManagerClient> SaneManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new SaneManagerClient;
        }
    }
    return instance_;
}

sptr<ISaneBackends> SaneManagerClient::GetSaneServiceProxy()
{
    {
        std::unique_lock<std::shared_mutex> lock(serviceLock_);
        if (proxy_ != nullptr) {
            SCAN_HILOGD("already get proxy_");
            return proxy_;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("samgrProxy is a nullptr");
            return nullptr;
        }
        auto object = samgrProxy->CheckSystemAbility(SANE_SERVICE_ID);
        if (object != nullptr) {
            object->AddDeathRecipient(deathRecipient_);
            proxy_ = iface_cast<ISaneBackends>(object);
            return proxy_;
        }
    }
    if (LoadSaneService()) {
        std::unique_lock<std::shared_mutex> lock(serviceLock_);
        return proxy_;
    }
    return nullptr;
}

bool SaneManagerClient::LoadSaneService()
{
    std::unique_lock<std::shared_mutex> lock(serviceLock_);
    sptr<SaneServiceLoadCallback> lockCallback = new SaneServiceLoadCallback();
    if (lockCallback == nullptr) {
        SCAN_HILOGE("lockCallback is a nullptr");
        return false;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        SCAN_HILOGE("get samgr failed");
        return false;
    }
    int32_t ret = samgrProxy->LoadSystemAbility(SANE_SERVICE_ID, lockCallback);
    if (ret != ERR_OK) {
        SCAN_HILOGE("LoadSystemAbility failed");
        return false;
    }
    auto waitStatus =
        syncCon_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS), [this]() { return proxy_ != nullptr; });
    if (!waitStatus) {
        return false;
    }
    return true;
}

void SaneManagerClient::LoadSystemAbilitysuccess(const sptr<IRemoteObject> &remoteObject)
{
    std::unique_lock<std::shared_mutex> lock(serviceLock_);
    SCAN_HILOGI("sane_service LoadSystemAbilitysuccess");
    if (remoteObject != nullptr) {
        remoteObject->AddDeathRecipient(deathRecipient_);
        proxy_ = iface_cast<ISaneBackends>(remoteObject);
        syncCon_.notify_one();
    }
}

void SaneManagerClient::LoadSystemAbilityFail()
{
    std::unique_lock<std::shared_mutex> lock(serviceLock_);
    SCAN_HILOGI("sane_service LoadSystemAbilityFail");
    proxy_ = nullptr;
}

void SaneManagerClient::OnRemoteSaDied(const wptr<IRemoteObject> &object)
{
    std::unique_lock<std::shared_mutex> lock(serviceLock_);
    proxy_ = nullptr;
}

SaneStatus SaneManagerClient::SaneInit()
{
    SCAN_HILOGI("SaneManagerClient SaneInit start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneInit(saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneInit error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneInit end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneExit()
{
    SCAN_HILOGI("SaneManagerClient SaneExit start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t ret = proxy_->SaneExit();
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneExit error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneExit end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneOpen(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneOpen start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneOpen(scannerId, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneOpen error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneOpen end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneClose(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneClose start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t ret = proxy_->SaneClose(scannerId);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneClose error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneClose end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneStart(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneStart start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneStart(scannerId, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneStart error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneStart end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneCancel(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneCancel start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t ret = proxy_->SaneCancel(scannerId);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneCancel error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneCancel end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneGetOptionDescriptor(
    const std::string &scannerId, const int32_t &option, SaneOptionDescriptor &desc)
{
    SCAN_HILOGI("SaneManagerClient SaneGetOptionDescriptor start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneGetOptionDescriptor(scannerId, option, desc, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneGetOptionDescriptor error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetOptionDescriptor end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneGetParameters(const std::string &scannerId, SaneParameters &params)
{
    SCAN_HILOGI("SaneManagerClient SaneGetParameters start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneGetParameters(scannerId, params, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneGetParameters error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetParameters end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneGetDevices(std::vector<SaneDevice> &deviceInfos)
{
    SCAN_HILOGI("SaneManagerClient SaneGetDevices start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneGetDevices(deviceInfos, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneGetDevices error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetDevices end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneControlOption(
    const std::string &scannerId, SaneControlParam &controlParam, SaneOutParam &outParam)
{
    SCAN_HILOGI("SaneManagerClient SaneControlOption start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneControlOption(scannerId, controlParam, outParam, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneControlOption error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneControlOption end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneRead(const std::string &scannerId, const int32_t buflen, SanePictureData &pictureData)
{
    SCAN_HILOGI("SaneManagerClient SaneRead start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy_->SaneRead(scannerId, buflen, pictureData, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->SaneRead error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneRead end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::UnloadSystemAbility()
{
    SCAN_HILOGI("SaneManagerClient UnloadSystemAbility start.");
    if (proxy_ == nullptr) {
        SCAN_HILOGW("do GetSaneServiceProxy");
        proxy_ = GetSaneServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(serviceLock_);
    if (proxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetSaneServiceProxy failed..");
        return SANE_STATUS_SERVER_FAILURE;
    }
    int32_t ret = proxy_->UnloadSystemAbility();
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy_->UnloadSystemAbility error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient UnloadSystemAbility end.");
    return SANE_STATUS_GOOD;
}
}  // namespace OHOS::Scan