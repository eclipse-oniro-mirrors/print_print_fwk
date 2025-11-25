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

#include <thread>
#include <queue>
#include "scan_mdns_service.h"
#include "scan_system_data.h"
#include "securec.h"
#include "escl_driver_manager.h"
#include "mdns_common.h"

namespace OHOS::Scan {
using namespace OHOS::NetManagerStandard;
const char* MDNS_TYPE_SCANNER_TCP = "_scanner._tcp";
const char* MDNS_TYPE_USCAN_TCP = "_uscan._tcp";
constexpr int32_t MDNS_PORT = 5353;

ScanMdnsService& ScanMdnsService::GetInstance()
{
    static ScanMdnsService instance;
    return instance;
}

void ScanMdnsService::SetScannerInfoMap(const std::string& ip, const ScanDeviceInfoTCP& info)
{
    std::lock_guard<std::mutex> autoLock(ipToScannerInfoMapLock_);
    std::string key = ip + "-" + info.deviceType;
    netScannerInfoMap_[key] = info;
}

void ScanMdnsService::SaveMdnsCallbackStubPtr(const std::string& type, sptr<ScanMDnsDiscoveryObserver> callbackPtr)
{
    std::lock_guard<std::mutex> autoLock(discoveryCallBackPtrsLock_);
    discoveryCallBackPtrs_[type] = callbackPtr;
}

void ScanMdnsService::PushScanInfoToQueue(const ScanDeviceInfoSync& info)
{
    std::unique_lock<std::mutex> lock(infoQueueLock_);
    infoQueue_.push(info);
    cv_.notify_one();
}

std::string ScanMDnsResolveObserver::GetMdnsInfoAttribute(MDnsServiceInfo &info, const std::string& key)
{
    TxtRecord attrMap = info.GetAttrMap();
    auto attrArrSize = attrMap.size();
    if (attrArrSize < 1) {
        SCAN_HILOGE("can not get attr");
        return "";
    }
    auto it = attrMap.find(key);
    if (it == attrMap.end() || it->second.empty()) {
        SCAN_HILOGE("can not find key, key = [%{public}s]", key.c_str());
        return "";
    }
    return std::string(it->second.begin(), it->second.end());
}

bool ScanMdnsService::OnStartDiscoverService()
{
    const std::vector<std::string> scannerServiceTypes = { MDNS_TYPE_USCAN_TCP, MDNS_TYPE_SCANNER_TCP};
    for (const auto& type : scannerServiceTypes) {
        MDnsServiceInfo mdnsInfo;
        mdnsInfo.type = type;
        mdnsInfo.port = MDNS_PORT;
        sptr<ScanMDnsDiscoveryObserver> callbackPtr = new (std::nothrow) ScanMDnsDiscoveryObserver(mdnsInfo);
        if (callbackPtr == nullptr) {
            SCAN_HILOGE("scanMDnsDiscoveryCallBack_ is a nullptr.");
            OnStopDiscoverService();
            return false;
        }
        int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->StartDiscoverService(
            mdnsInfo.type, callbackPtr);
        if (ret != NETMANAGER_EXT_SUCCESS) {
            SCAN_HILOGE("mdns service [%{public}s] startDiscover failed, ret = [%{public}d].",
                mdnsInfo.type.c_str(), ret);
            OnStopDiscoverService();
            return false;
        }
        SaveMdnsCallbackStubPtr(type, callbackPtr);
        constexpr int32_t WAIT_TIME = 1;
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    if (!isListening_.load()) {
        std::thread updateScannerId(&ScanMdnsService::UpdateScannerIdThread, this);
        updateScannerId.detach();
        isListening_.store(true);
    }
    return true;
}

void ScanMdnsService::UpdateScannerIdThread()
{
    auto saPtr = ScanServiceAbility::GetInstance();
    if (saPtr == nullptr) {
        SCAN_HILOGE("saPtr is a nullptr");
        return;
    }
    while (isListening_.load()) {
        std::unique_lock<std::mutex> lock(infoQueueLock_);
        cv_.wait(lock, [this]() {
            return !infoQueue_.empty();
        });
        auto& syncInfo = infoQueue_.front();
        if (syncInfo.syncMode == ScannerSyncMode::UPDATE_MODE) {
            saPtr->UpdateScannerId(syncInfo);
        } else if (syncInfo.syncMode == ScannerSyncMode::DELETE_MODE) {
            saPtr->NetScannerLossNotify(syncInfo);
        } else {
            SCAN_HILOGW("syncMode is error : [%{private}s]", syncInfo.syncMode.c_str());
        }
        infoQueue_.pop();
    }
}

bool ScanMdnsService::OnStopDiscoverService()
{
    std::lock_guard<std::mutex> autoLock(discoveryCallBackPtrsLock_);
    for (auto& [serviceName, discoveryCallBackPtr] : discoveryCallBackPtrs_) {
        if (discoveryCallBackPtr == nullptr) {
            continue;
        }
        int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->StopDiscoverService(discoveryCallBackPtr);
        if (ret != NETMANAGER_EXT_SUCCESS) {
            SCAN_HILOGE("mdns service [%{public}s] startDiscover failed, ret = [%{public}d].",
                serviceName.c_str(), ret);
            return false;
        }
        discoveryCallBackPtr = nullptr;
    }
    discoveryCallBackPtrs_.clear();
    ScannerDiscoverData::GetInstance().ClearEsclDevices();
    isListening_.store(false);
    cv_.notify_all();
    return true;
}

bool ScanMdnsService::FindNetScannerInfoByIp(const std::string& ip, ScanDeviceInfoTCP& netScannerInfo)
{
    std::lock_guard<std::mutex> autoLock(ipToScannerInfoMapLock_);
    std::string keyScanner = ip + "-" + MDNS_TYPE_SCANNER_TCP;
    auto it = netScannerInfoMap_.find(keyScanner);
    if (it != netScannerInfoMap_.end() && it->second.uuid != "") {
        netScannerInfo = it->second;
        return true;
    }
    std::string keyUscan = ip + "-" + MDNS_TYPE_USCAN_TCP;
    it = netScannerInfoMap_.find(keyUscan);
    if (it != netScannerInfoMap_.end() && it->second.uuid != "") {
        netScannerInfo = it->second;
        return true;
    }
    return false;
}

int32_t ScanMDnsDiscoveryObserver::HandleServiceFound(const MDnsServiceInfo &info, int32_t retCode)
{
    SCAN_HILOGD("Found mdns service info, name = [%{private}s]", info.name.c_str());
    sptr<ScanMDnsResolveObserver> scanMDnsResolveCallBack_ = new (std::nothrow) ScanMDnsResolveObserver(info);
    if (scanMDnsResolveCallBack_ == nullptr) {
        SCAN_HILOGE("scanMDnsResolveCallBack_ is a nullptr.");
        return NETMANAGER_EXT_ERR_INTERNAL;
    }
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->ResolveService(info, scanMDnsResolveCallBack_);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        SCAN_HILOGE("mdns ResolveService failed, ret = [%{public}d].", ret);
        return NETMANAGER_EXT_ERR_INTERNAL;
    }
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsResolveObserver::HandleResolveResult(const MDnsServiceInfo &info, int32_t retCode)
{
    SCAN_HILOGD("MDnsInfo name = [%{private}s], type = [%{private}s]", info.name.c_str(), info.type.c_str());
    ScanDeviceInfoTCP tcpInfo;
    tcpInfo.addr = info.addr;
    tcpInfo.deviceName = info.name;
    tcpInfo.port = std::to_string(info.port);
    const std::string uuidKey = "UUID";
    MDnsServiceInfo infoTmp = info;
    std::string uuidValue = GetMdnsInfoAttribute(infoTmp, uuidKey);
    tcpInfo.uuid = uuidValue;
    ScanDeviceInfo scanInfo;
    if (info.type == MDNS_TYPE_USCAN_TCP && EsclDriverManager::GenerateEsclScannerInfo(tcpInfo, scanInfo)) {
        scanInfo.deviceType = MDNS_TYPE_USCAN_TCP;
        ScannerDiscoverData::GetInstance().SetEsclDevice(scanInfo.uniqueId, scanInfo);
        if (auto scanService = ScanServiceAbility::GetInstance()) {
            scanService->NotifyEsclScannerFound(scanInfo);
        }
    } else {
        tcpInfo.deviceType = MDNS_TYPE_SCANNER_TCP;
    }
    ScanMdnsService::GetInstance().SetScannerInfoMap(tcpInfo.addr, tcpInfo);
    SyncSysDataAndNotifyScanService(tcpInfo);
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsResolveObserver::SyncSysDataAndNotifyScanService(ScanDeviceInfoTCP& scannerInfo)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    auto updateResult = scanData.UpdateNetScannerByUuid(scannerInfo.uuid, scannerInfo.addr);
    if (!updateResult.has_value()) {
        SCAN_HILOGW("UpdateNetScannerByUuid fail.");
        return NETMANAGER_EXT_ERR_INTERNAL;
    }
    if (!scanData.SaveScannerMap()) {
        SCAN_HILOGW("SaveScannerMap fail");
    }
    auto& [oldDeviceId, newDeviceId] = updateResult.value();
    ScanDeviceInfoSync syncInfo;
    syncInfo.deviceId = newDeviceId;
    syncInfo.oldDeviceId = oldDeviceId;
    syncInfo.discoverMode = ScannerDiscoveryMode::TCP_MODE;
    syncInfo.uniqueId = scannerInfo.addr;
    syncInfo.syncMode = ScannerSyncMode::UPDATE_MODE;
    ScanMdnsService::GetInstance().PushScanInfoToQueue(syncInfo);
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsDiscoveryObserver::HandleServiceLost(const MDnsServiceInfo &info, int32_t retCode)
{
    SCAN_HILOGD("Loss mdns service info, name = [%{private}s]", info.name.c_str());
    sptr<ScanMDnsLossResolveObserver> callBack = new (std::nothrow) ScanMDnsLossResolveObserver(info);
    if (callBack == nullptr) {
        SCAN_HILOGE("callBack is a nullptr");
        return NETMANAGER_EXT_ERR_INTERNAL;
    }
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->ResolveService(info, callBack);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        SCAN_HILOGE("mdns ResolveService failed, ret = %{public}d", ret);
    }
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsLossResolveObserver::HandleResolveResult(const MDnsServiceInfo &info, int32_t retCode)
{
    SCAN_HILOGD("mdnsloss name = [%{private}s], type = [%{private}s]", info.name.c_str(), info.type.c_str());
    auto& discoverData = ScannerDiscoverData::GetInstance();
    if (!discoverData.HasTcpDevice(info.addr) && !discoverData.HasEsclDevice(info.addr)) {
        SCAN_HILOGW("not found scanner in discover data");
        return NETMANAGER_EXT_SUCCESS;
    }
    ScanDeviceInfo discoveredInfo;
    if (discoverData.HasTcpDevice(info.addr)) {
        discoverData.GetTcpDevice(info.addr, discoveredInfo);
    } else if (discoverData.HasEsclDevice(info.addr)) {
        discoverData.GetEsclDevice(info.addr, discoveredInfo);
    }
    discoverData.RemoveTcpDevice(info.addr);
    discoverData.RemoveEsclDevice(info.addr);
    ScanDeviceInfoSync syncInfo;
    syncInfo.deviceId = discoveredInfo.deviceId;
    syncInfo.discoverMode = ScannerDiscoveryMode::TCP_MODE;
    syncInfo.uniqueId = info.addr;
    syncInfo.syncMode = ScannerSyncMode::DELETE_MODE;
    ScanMdnsService::GetInstance().PushScanInfoToQueue(syncInfo);
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsDiscoveryObserver::HandleStopDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode)
{
    SCAN_HILOGD("Stop mdns service info, name = [%{private}s]", serviceInfo.name.c_str());
    return NETMANAGER_EXT_SUCCESS;
}

}  // namespace OHOS::Scan
