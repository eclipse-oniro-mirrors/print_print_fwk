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

#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::Scan {
std::mutex ScanManagerClient::instanceLock_;
sptr<ScanManagerClient> ScanManagerClient::instance_ = nullptr;

ScanManagerClient::ScanManagerClient() : scanServiceProxy_(nullptr), deathRecipient_(nullptr)
{}

ScanManagerClient::~ScanManagerClient()
{}

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
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        SCAN_HILOGE("Getting SystemAbilityManager failed.");
        return nullptr;
    }
    if (scanServiceProxy_ != nullptr) {
        SCAN_HILOGD("scanServiceProxy_ already get");
        return scanServiceProxy_;
    }
    auto systemAbility = systemAbilityManager->GetSystemAbility(SCAN_SERVICE_ID, "");
    if (systemAbility == nullptr) {
        SCAN_HILOGE("Get SystemAbility failed.");
        return nullptr;
    }
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new ScanSaDeathRecipient();
    }
    systemAbility->AddDeathRecipient(deathRecipient_);
    sptr<IScanService> serviceProxy = iface_cast<IScanService>(systemAbility);
    if (serviceProxy == nullptr) {
        SCAN_HILOGE("Get ScanManagerClientProxy from SA failed.");
        return nullptr;
    }
    SCAN_HILOGD("Getting ScanManagerClientProxy succeeded.");
    return serviceProxy;
}

void ScanManagerClient::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    scanServiceProxy_ = nullptr;
    ready_ = false;
}

bool ScanManagerClient::LoadServer()
{
    if (ready_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (ready_) {
        return true;
    }

    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        SCAN_HILOGE("GetSystemAbilityManager return null");
        return false;
    }

    sptr<ScanSyncLoadCallback> loadCallback_ = new (std::nothrow) ScanSyncLoadCallback();
    if (loadCallback_ == nullptr) {
        SCAN_HILOGE("new ScanSyncLoadCallback fail");
        return false;
    }

    int32_t result = sm->LoadSystemAbility(SCAN_SERVICE_ID, loadCallback_);
    if (result != ERR_OK) {
        SCAN_HILOGE("LoadSystemAbility %{public}d failed, result: %{public}d", SCAN_SERVICE_ID, result);
        return false;
    }

    {
        std::unique_lock<std::mutex> conditionLock(conditionMutex_);
        auto waitStatus = syncCon_.wait_for(
            conditionLock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS), [this]() { return ready_; });
        if (!waitStatus) {
            SCAN_HILOGE("scan server load sa timeout");
            return false;
        }
    }
    return true;
}

void ScanManagerClient::LoadServerSuccess()
{
    std::unique_lock<std::mutex> lock(conditionMutex_);
    ready_ = true;
    syncCon_.notify_one();
    SCAN_HILOGD("load scan server success");
}

void ScanManagerClient::LoadServerFail()
{
    ready_ = false;
    SCAN_HILOGE("load scan server fail");
}

int32_t ScanManagerClient::InitScan(int32_t &scanVersion)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient InitScan start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->InitScan(scanVersion);
    SCAN_HILOGD("ScanManagerClient InitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::ExitScan()
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient ExitScan start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->ExitScan();
    SCAN_HILOGD("ScanManagerClient ExitScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScannerList()
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetScannerList start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScannerList();
    SCAN_HILOGD("ScanManagerClient GetScannerList end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::StopDiscover()
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient StopDiscover start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->StopDiscover();
    SCAN_HILOGD("ScanManagerClient StopDiscover end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpenScanner(const std::string scannerId)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient OpenScanner start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->OpenScanner(scannerId);
    SCAN_HILOGD("ScanManagerClient OpenScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CloseScanner(const std::string scannerId)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient CloseScanner start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->CloseScanner(scannerId);
    SCAN_HILOGD("ScanManagerClient CloseScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetScanOptionDesc start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScanOptionDesc(scannerId, optionIndex, desc);
    SCAN_HILOGD("ScanManagerClient GetScanOptionDesc end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value, int32_t &info)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->OpScanOptionValue(scannerId, optionIndex, op, value, info);
    SCAN_HILOGD("ScanManagerClient OpScanOptionValue end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetScanParameters start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
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
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient StartScan start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->StartScan(scannerId, batchMode);
    SCAN_HILOGD("ScanManagerClient StartScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetSingleFrameFD start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetSingleFrameFD(scannerId, size, fd);
    SCAN_HILOGD("ScanManagerClient GetSingleFrameFD end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::CancelScan(const std::string scannerId)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient CancelScan start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->CancelScan(scannerId);
    SCAN_HILOGD("ScanManagerClient CancelScan end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::SetScanIOMode(const std::string scannerId, const bool isNonBlocking)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient SetScanIOMode start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->SetScanIOMode(scannerId, isNonBlocking);
    SCAN_HILOGD("ScanManagerClient SetScanIOMode end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanSelectFd(const std::string scannerId, int32_t &fd)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetScanSelectFd start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScanSelectFd(scannerId, fd);
    SCAN_HILOGD("ScanManagerClient GetScanSelectFd end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::On(const std::string &taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient On start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->On(taskId, type, listener);
    SCAN_HILOGD("ScanManagerClient On out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::Off(const std::string &taskId, const std::string &type)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient Off start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("Off quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->Off(taskId, type);
    SCAN_HILOGD("ScanManagerClient Off out ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScannerState(int32_t &scannerState)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetScannerState start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetScannerState(scannerState);
    SCAN_HILOGD("ScanManagerClient GetScannerState end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGI("ScanManagerClient GetScanProgress start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
        if (scanServiceProxy_ == nullptr) {
            SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
            return E_SCAN_RPC_FAILURE;
        }
    }
    int32_t ret = scanServiceProxy_->GetScanProgress(scannerId, prog);
    SCAN_HILOGI("ScanManagerClient GetScanProgress end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient AddScanner start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->AddScanner(serialNumber, discoverMode);
    SCAN_HILOGD("ScanManagerClient AddScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient DeleteScanner start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->DeleteScanner(serialNumber, discoverMode);
    SCAN_HILOGD("ScanManagerClient DeleteScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient GetAddedScanner start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->GetAddedScanner(allAddedScanner);
    SCAN_HILOGD("ScanManagerClient GetAddedScanner end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::UpdateScannerName(const std::string& serialNumber,
    const std::string& discoverMode, const std::string& deviceName)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient UpdateScannerName start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->UpdateScannerName(serialNumber, discoverMode, deviceName);
    SCAN_HILOGD("ScanManagerClient UpdateScannerName end ret = [%{public}d].", ret);
    return ret;
}

int32_t ScanManagerClient::AddPrinter(const std::string& serialNumber, const std::string& discoverMode)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    SCAN_HILOGD("ScanManagerClient AddPrinter start.");
    if (!LoadServer()) {
        SCAN_HILOGE("load scan server fail");
        return E_SCAN_RPC_FAILURE;
    }

    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGW("Redo GetScanServiceProxy");
        scanServiceProxy_ = GetScanServiceProxy();
    }
    if (scanServiceProxy_ == nullptr) {
        SCAN_HILOGE("On quit because redoing GetScanServiceProxy failed.");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = scanServiceProxy_->AddPrinter(serialNumber, discoverMode);
    SCAN_HILOGD("ScanManagerClient AddPrinter end ret = [%{public}d].", ret);
    return ret;
}
}  // namespace OHOS::Scan
