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

#include "scan_manager_client.h"
#include "scan_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::Scan {
std::mutex ScanManagerClient::instanceLock_;
sptr<ScanManagerClient> ScanManagerClient::instance_ = nullptr;

ScanManagerClient::ScanManagerClient() : scanServiceProxy_(nullptr)
{
    deathRecipient_ = new ScanSaDeathRecipient();
}

ScanManagerClient::~ScanManagerClient()
{
    std::unique_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ != nullptr) {
        auto serviceRemote = scanServiceProxy_->AsObject();
        if (serviceRemote != nullptr) {
            serviceRemote->RemoveDeathRecipient(deathRecipient_);
        }
    }
    scanServiceProxy_ = nullptr;
    deathRecipient_ = nullptr;
}

sptr<ScanManagerClient> ScanManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new ScanManagerClient;
        }
    }
    return instance_;
}
sptr<IScanService> ScanManagerClient::GetScanServiceProxy()
{
    {
        std::shared_lock<std::shared_mutex> sharedLock(proxyLock_);
        if (scanServiceProxy_ != nullptr) {
            SCAN_HILOGD("already get scanServiceProxy_");
            return scanServiceProxy_;
        }
    }
    {
        std::unique_lock<std::shared_mutex> uniqueLock(proxyLock_);
        if (scanServiceProxy_ != nullptr) {
            SCAN_HILOGD("already get scanServiceProxy_ (second check)");
            return scanServiceProxy_;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("samgrProxy is a nullptr");
            return nullptr;
        }
        auto object = samgrProxy->CheckSystemAbility(SCAN_SERVICE_ID);
        if (object != nullptr) {
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new (std::nothrow) ScanSaDeathRecipient();
            }
            if (deathRecipient_ != nullptr) {
                object->AddDeathRecipient(deathRecipient_);
            }
            scanServiceProxy_ = iface_cast<IScanService>(object);
            return scanServiceProxy_;
        }
    }
    if (LoadScanService()) {
        std::shared_lock<std::shared_mutex> sharedLock(proxyLock_);
        return scanServiceProxy_;
    }
    return nullptr;
}

bool ScanManagerClient::LoadScanService()
{
    {
        std::lock_guard<std::mutex> conditionLock(conditionMutex_);
        ready_ = false;
    }
    {
        std::unique_lock<std::shared_mutex> lock(proxyLock_);
        sptr<ScanSyncLoadCallback> lockCallback = new (std::nothrow) ScanSyncLoadCallback();
        if (lockCallback == nullptr) {
            SCAN_HILOGE("lockCallback is a nullptr");
            return false;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("get samgr failed");
            return false;
        }
        int32_t ret = samgrProxy->LoadSystemAbility(SCAN_SERVICE_ID, lockCallback);
        if (ret != ERR_OK) {
            SCAN_HILOGE("LoadSystemAbility failed");
            return false;
        }
    }
    {
        std::unique_lock<std::mutex> conditionLock(conditionMutex_);
        auto waitStatus = syncCon_.wait_for(conditionLock,
            std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS), [this]() { return ready_; });
        if (!waitStatus) {
            SCAN_HILOGE("scan server load sa timeout");
            return false;
        }
    }
    std::shared_lock<std::shared_mutex> proxySharedLock(proxyLock_);
    return scanServiceProxy_ != nullptr;
}

void ScanManagerClient::LoadServerSuccess(const sptr<IRemoteObject> &remoteObject)
{
    {
        std::unique_lock<std::shared_mutex> lock(proxyLock_);
        SCAN_HILOGI("scan_service LoadServerSuccess");
        if (remoteObject != nullptr) {
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new (std::nothrow) ScanSaDeathRecipient();
            }
            if (deathRecipient_ != nullptr) {
                remoteObject->AddDeathRecipient(deathRecipient_);
            }
            scanServiceProxy_ = iface_cast<IScanService>(remoteObject);
        }
    }
    {
        std::unique_lock<std::mutex> lock(conditionMutex_);
        ready_ = true;
        syncCon_.notify_one();
    }
}

void ScanManagerClient::LoadServerFail()
{
    {
        std::unique_lock<std::shared_mutex> lock(proxyLock_);
        SCAN_HILOGI("scan_service LoadServerFail");
        scanServiceProxy_ = nullptr;
    }
    {
        std::unique_lock<std::mutex> lock(conditionMutex_);
        ready_ = true;
        syncCon_.notify_one();
    }
}

void ScanManagerClient::OnRemoteSaDied(const wptr<IRemoteObject>& object)
{
    std::unique_lock<std::shared_mutex> lock(proxyLock_);
    if (object == nullptr) {
        SCAN_HILOGE("object is nullptr");
        return;
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("scanServiceProxy_ is null");
        return;
    }
    auto serviceRemote = scanServiceProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == object.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        scanServiceProxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

int32_t ScanManagerClient::InitScan()
{
    SCAN_HILOGI("ScanManagerClient InitScan start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->InitScan();
    SCAN_HILOGI("ScanManagerClient InitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::ExitScan()
{
    SCAN_HILOGI("ScanManagerClient ExitScan start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->ExitScan();
    SCAN_HILOGI("ScanManagerClient ExitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScannerList()
{
    SCAN_HILOGI("ScanManagerClient GetScannerList start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->GetScannerList();
    SCAN_HILOGI("ScanManagerClient GetScannerList end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpenScanner(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient OpenScanner start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->OpenScanner(scannerId);
    SCAN_HILOGI("ScanManagerClient OpenScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CloseScanner(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient CloseScanner start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->CloseScanner(scannerId);
    SCAN_HILOGI("ScanManagerClient CloseScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    SCAN_HILOGI("ScanManagerClient GetScanOptionDesc start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->GetScanOptionDesc(scannerId, optionIndex, desc);
    SCAN_HILOGD("ScanManagerClient GetScanOptionDesc end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value)
{
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->OpScanOptionValue(scannerId, optionIndex, op, value);
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    SCAN_HILOGD("ScanManagerClient GetScanParameters start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->GetScanParameters(scannerId, para);
    SCAN_HILOGD("ScanManagerClient GetScanParameters end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::StartScan(const std::string scannerId, const bool &batchMode)
{
    SCAN_HILOGI("ScanManagerClient StartScan start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->StartScan(scannerId, batchMode);
    SCAN_HILOGI("ScanManagerClient StartScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CancelScan(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient CancelScan start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->CancelScan(scannerId);
    SCAN_HILOGI("ScanManagerClient CancelScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::On(const std::string &taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    SCAN_HILOGI("ScanManagerClient On start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->On(taskId, type, listener);
    SCAN_HILOGI("ScanManagerClient On out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::Off(const std::string &taskId, const std::string &type)
{
    SCAN_HILOGD("ScanManagerClient Off start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->Off(taskId, type);
    SCAN_HILOGD("ScanManagerClient Off out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    SCAN_HILOGI("ScanManagerClient GetScanProgress start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->GetScanProgress(scannerId, prog);
    SCAN_HILOGI("ScanManagerClient GetScanProgress end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGI("ScanManagerClient AddScanner start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->AddScanner(serialNumber, discoverMode);
    SCAN_HILOGI("ScanManagerClient AddScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGI("ScanManagerClient DeleteScanner start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->DeleteScanner(serialNumber, discoverMode);
    SCAN_HILOGI("ScanManagerClient DeleteScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    SCAN_HILOGD("ScanManagerClient GetAddedScanner start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->GetAddedScanner(allAddedScanner);
    SCAN_HILOGD("ScanManagerClient GetAddedScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::ExportScanPicture(const std::string scannerId,
    const std::vector<int32_t>& pictureFdList, int32_t format,
    std::vector<int32_t>& exportedFdList)
{
    SCAN_HILOGI("ScanManagerClient ExportScanPicture start.");
    auto proxy = GetScanServiceProxy();
    if (proxy == nullptr) {
        SCAN_HILOGE("GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = proxy->ExportScanPicture(scannerId, pictureFdList, format, exportedFdList);
    SCAN_HILOGI("ScanManagerClient ExportScanPicture end ret = [%{public}d].", ret);
    return ret;
}

}  // namespace OHOS::Scan
