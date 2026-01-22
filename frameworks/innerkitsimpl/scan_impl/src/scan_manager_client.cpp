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
        std::unique_lock<std::shared_mutex> lock(proxyLock_);
        if (scanServiceProxy_ != nullptr) {
            SCAN_HILOGD("already get scanServiceProxy_");
            return scanServiceProxy_;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("samgrProxy is a nullptr");
            return nullptr;
        }
        auto object = samgrProxy->CheckSystemAbility(SCAN_SERVICE_ID);
        if (object != nullptr) {
            object->AddDeathRecipient(deathRecipient_);
            scanServiceProxy_ = iface_cast<IScanService>(object);
            return scanServiceProxy_;
        }
    }
    if (LoadScanService()) {
        std::unique_lock<std::shared_mutex> lock(proxyLock_);
        return scanServiceProxy_;
    }
    return nullptr;
}

bool ScanManagerClient::LoadScanService()
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
    auto waitStatus = syncCon_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
        [this]() { return scanServiceProxy_ != nullptr; });
    if (!waitStatus) {
        return false;
    }
    return true;
}

void ScanManagerClient::LoadServerSuccess(const sptr<IRemoteObject> &remoteObject)
{
    std::unique_lock<std::shared_mutex> lock(proxyLock_);
    SCAN_HILOGI("scan_service LoadServerSuccess");
    if (remoteObject != nullptr) {
        remoteObject->AddDeathRecipient(deathRecipient_);
        scanServiceProxy_ = iface_cast<IScanService>(remoteObject);
        syncCon_.notify_one();
    }
}

void ScanManagerClient::LoadServerFail()
{
    std::unique_lock<std::shared_mutex> lock(proxyLock_);
    SCAN_HILOGI("scan_service LoadServerFail");
    scanServiceProxy_ = nullptr;
}

void ScanManagerClient::OnRemoteSaDied(const wptr<IRemoteObject>& object)
{
    std::unique_lock<std::shared_mutex> lock(proxyLock_);
    scanServiceProxy_ = nullptr;
}

int32_t ScanManagerClient::InitScan()
{
    SCAN_HILOGI("ScanManagerClient InitScan start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("do GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->InitScan();
    SCAN_HILOGI("ScanManagerClient InitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::ExitScan()
{
    SCAN_HILOGI("ScanManagerClient ExitScan start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("do GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->ExitScan();
    SCAN_HILOGI("ScanManagerClient ExitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScannerList()
{
    SCAN_HILOGI("ScanManagerClient GetScannerList start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScannerList();
    SCAN_HILOGI("ScanManagerClient GetScannerList end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpenScanner(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient OpenScanner start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->OpenScanner(scannerId);
    SCAN_HILOGI("ScanManagerClient OpenScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CloseScanner(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient CloseScanner start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->CloseScanner(scannerId);
    SCAN_HILOGI("ScanManagerClient CloseScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    SCAN_HILOGI("ScanManagerClient GetScanOptionDesc start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScanOptionDesc(scannerId, optionIndex, desc);
    SCAN_HILOGD("ScanManagerClient GetScanOptionDesc end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value)
{
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->OpScanOptionValue(scannerId, optionIndex, op, value);
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    SCAN_HILOGD("ScanManagerClient GetScanParameters start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScanParameters(scannerId, para);
    SCAN_HILOGD("ScanManagerClient GetScanParameters end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::StartScan(const std::string scannerId, const bool &batchMode)
{
    SCAN_HILOGI("ScanManagerClient StartScan start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->StartScan(scannerId, batchMode);
    SCAN_HILOGI("ScanManagerClient StartScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CancelScan(const std::string scannerId)
{
    SCAN_HILOGI("ScanManagerClient CancelScan start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->CancelScan(scannerId);
    SCAN_HILOGI("ScanManagerClient CancelScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::On(const std::string &taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    SCAN_HILOGI("ScanManagerClient On start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->On(taskId, type, listener);
    SCAN_HILOGI("ScanManagerClient On out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::Off(const std::string &taskId, const std::string &type)
{
    SCAN_HILOGD("ScanManagerClient Off start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->Off(taskId, type);
    SCAN_HILOGD("ScanManagerClient Off out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    SCAN_HILOGI("ScanManagerClient GetScanProgress start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScanProgress(scannerId, prog);
    SCAN_HILOGI("ScanManagerClient GetScanProgress end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGI("ScanManagerClient AddScanner start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->AddScanner(serialNumber, discoverMode);
    SCAN_HILOGI("ScanManagerClient AddScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGI("ScanManagerClient DeleteScanner start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->DeleteScanner(serialNumber, discoverMode);
    SCAN_HILOGI("ScanManagerClient DeleteScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    SCAN_HILOGD("ScanManagerClient GetAddedScanner start.");
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    std::shared_lock<std::shared_mutex> lock(proxyLock_);
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetAddedScanner(allAddedScanner);
    SCAN_HILOGD("ScanManagerClient GetAddedScanner end ret = [%{public}d].", ret);
    return ret;
}

}  // namespace OHOS::Scan
