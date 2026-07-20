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
std::shared_mutex SaneManagerClient::serviceLock_;

SaneManagerClient::SaneManagerClient() : proxy_(nullptr)
{
    deathRecipient_ = new SaneSaDeathRecipient();
}
SaneManagerClient::~SaneManagerClient()
{
    proxy_ = nullptr;
    deathRecipient_ = nullptr;
}

SaneManagerClient &SaneManagerClient::GetInstance()
{
    static SaneManagerClient instance_;
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
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneInit(saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneInit error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneInit end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneExit()
{
    SCAN_HILOGI("SaneManagerClient SaneExit start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t ret = proxy->SaneExit();
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneExit error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneExit end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneOpen(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneOpen start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneOpen(scannerId, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneOpen error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneOpen end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneClose(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneClose start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t ret = proxy->SaneClose(scannerId);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneClose error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneClose end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneStart(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneStart start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneStart(scannerId, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneStart error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneStart end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneCancel(const std::string &scannerId)
{
    SCAN_HILOGI("SaneManagerClient SaneCancel start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t ret = proxy->SaneCancel(scannerId);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneCancel error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneCancel end.");
    return SANE_STATUS_GOOD;
}

SaneStatus SaneManagerClient::SaneGetOptionDescriptor(
    const std::string &scannerId, const int32_t &option, SaneOptionDescriptor &desc)
{
    SCAN_HILOGI("SaneManagerClient SaneGetOptionDescriptor start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneGetOptionDescriptor(scannerId, option, desc, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneGetOptionDescriptor error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetOptionDescriptor end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneGetParameters(const std::string &scannerId, SaneParameters &params)
{
    SCAN_HILOGI("SaneManagerClient SaneGetParameters start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneGetParameters(scannerId, params, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneGetParameters error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetParameters end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneGetDevices(std::vector<SaneDevice> &deviceInfos)
{
    SCAN_HILOGI("SaneManagerClient SaneGetDevices start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneGetDevices(deviceInfos, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneGetDevices error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneGetDevices end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneControlOption(
    const std::string &scannerId, SaneControlParam &controlParam, SaneOutParam &outParam)
{
    SCAN_HILOGI("SaneManagerClient SaneControlOption start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneControlOption(scannerId, controlParam, outParam, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneControlOption error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneControlOption end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::SaneRead(const std::string &scannerId, const int32_t buflen, SanePictureData &pictureData)
{
    SCAN_HILOGI("SaneManagerClient SaneRead start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t saneStatus = SANE_STATUS_GOOD;
    int32_t ret = proxy->SaneRead(scannerId, buflen, pictureData, saneStatus);
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->SaneRead error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient SaneRead end, saneStatus = [%{public}d].", saneStatus);
    return static_cast<SaneStatus>(saneStatus);
}

SaneStatus SaneManagerClient::UnloadSystemAbility()
{
    SCAN_HILOGI("SaneManagerClient UnloadSystemAbility start.");
    auto proxy = GetSaneServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetSaneServiceProxy failed.");
        return SANE_STATUS_RPC_FAILURE;
    }
    int32_t ret = proxy->UnloadSystemAbility();
    if (ret != ERR_NONE) {
        SCAN_HILOGE("proxy->UnloadSystemAbility error exit, ret = [%{public}d]", ret);
        return SANE_STATUS_RPC_FAILURE;
    }
    SCAN_HILOGI("SaneManagerClient UnloadSystemAbility end.");
    return SANE_STATUS_GOOD;
}
}  // namespace OHOS::Scan