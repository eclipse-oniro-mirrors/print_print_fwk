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
#include "mdns_common.h"

#define TXT_MAX 256

namespace OHOS::Scan {
using namespace OHOS::NetManagerStandard;
namespace {
std::map<std::string, ScanDeviceInfoTCP> g_ipToScannerInfo;
std::mutex g_ipToScannerInfoLock;
std::queue<ScanDeviceInfoSync> g_infoQueue;
std::mutex g_infoQueueLock;
static std::string GetServiceAttribute(MDnsServiceInfo &info, const std::string& key)
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
}
std::map<std::string, sptr<ScanMDnsDiscoveryObserver>> ScanMdnsService::discoveryCallBackPtrs_;
bool ScanMdnsService::isListening_ = false;
std::mutex ScanMdnsService::discoveryCallBackPtrsLock_;

void ScanMdnsService::InsertIpToScannerInfo(const std::string& ip, ScanDeviceInfoTCP& scanDeviceInfoTCP)
{
    std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
    g_ipToScannerInfo.insert(std::make_pair(ip, scanDeviceInfoTCP));
}

bool ScanMdnsService::OnStartDiscoverService()
{
    if (isListening_) {
        SCAN_HILOGD("scanner's mdns discovery is already started.");
        return true;
    }
    const std::vector<std::string> scannerServiceTypes = { "_scanner._tcp" };
    constexpr int32_t MDNS_PORT = 5353;
    {
        std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
        g_ipToScannerInfo.clear();
    }
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
        {
            std::lock_guard<std::mutex> autoLock(discoveryCallBackPtrsLock_);
            auto it = discoveryCallBackPtrs_.find(type);
            if (it == discoveryCallBackPtrs_.end()) {
                discoveryCallBackPtrs_.insert(std::make_pair(type, callbackPtr));
            } else {
                it->second = callbackPtr;
            }
            isListening_ = true;
            std::thread updateScannerId(UpdateScannerIdThread);
            updateScannerId.detach();
        }
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
    while (isListening_) {
        {
            std::lock_guard<std::mutex> autoLock(g_infoQueueLock);
            while (!g_infoQueue.empty()) {
                saPtr->UpdateScannerId(g_infoQueue.front());
                g_infoQueue.pop();
            }
        }
        constexpr int32_t sleepTime = 100000; // 100ms
        usleep(sleepTime);
    }
}

bool ScanMdnsService::OnStopDiscoverService()
{
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
    {
        std::lock_guard<std::mutex> autoLock(discoveryCallBackPtrsLock_);
        discoveryCallBackPtrs_.clear();
        isListening_ = false;
    }
    return true;
}

bool ScanMdnsService::FindNetScannerInfoByIp(const std::string& ip, ScanDeviceInfoTCP& netScannerInfo)
{
    std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
    auto it = g_ipToScannerInfo.find(ip);
    if (it == g_ipToScannerInfo.end()) {
        SCAN_HILOGW("cannot find scanner info in map.");
        return false;
    }
    netScannerInfo = it->second;
    return true;
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
    }
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsResolveObserver::HandleResolveResult(const MDnsServiceInfo &info, int32_t retCode)
{
    MDnsServiceInfo tempInfo = info;
    SCAN_HILOGD("MDnsInfo name = [%{private}s], type = [%{private}s]", info.name.c_str(), info.type.c_str());
    std::unique_ptr<ScanDeviceInfoTCP> scannerInfo = std::make_unique<ScanDeviceInfoTCP>();
    scannerInfo->addr = tempInfo.addr;
    scannerInfo->deviceName = tempInfo.name;
    scannerInfo->port = std::to_string(tempInfo.port);
    const std::string uuidKey = "UUID";
    std::string uuidValue = GetServiceAttribute(tempInfo, uuidKey);
    scannerInfo->uuid = uuidValue;
    {
        std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
        auto it = g_ipToScannerInfo.find(scannerInfo->addr);
        if (it == g_ipToScannerInfo.end()) {
            g_ipToScannerInfo.insert(std::make_pair(scannerInfo->addr, *scannerInfo));
        } else {
            it->second = *scannerInfo;
        }
    }
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    auto updateResult = scanData.UpdateNetScannerByUuid(uuidValue, scannerInfo->addr);
    if (!updateResult.has_value()) {
        SCAN_HILOGE("UpdateNetScannerByUuid fail.");
        return NETMANAGER_EXT_ERR_INTERNAL;
    }
    if (!scanData.SaveScannerMap()) {
        SCAN_HILOGW("SaveScannerMap fail");
    }
    auto& [oldDeviceId, newDeviceId] = updateResult.value();
    ScanDeviceInfoSync syncInfo;
    syncInfo.deviceId = newDeviceId;
    syncInfo.oldDeviceId = oldDeviceId;
    syncInfo.discoverMode = "TCP";
    syncInfo.uniqueId = scannerInfo->addr;
    syncInfo.syncMode = "update";
    {
        std::lock_guard<std::mutex> autoLock(g_infoQueueLock);
        g_infoQueue.push(syncInfo);
    }
    {
        std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
        auto it = g_ipToScannerInfo.find(scannerInfo->addr);
        if (it == g_ipToScannerInfo.end()) {
            g_ipToScannerInfo.insert(std::make_pair(scannerInfo->addr, *scannerInfo));
        } else {
            it->second = *scannerInfo;
        }
    }
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
    MDnsServiceInfo tempInfo = info;
    SCAN_HILOGD("mdnsloss name = [%{private}s], type = [%{private}s]", info.name.c_str(), info.type.c_str());
    {
        std::lock_guard<std::mutex> autoLock(g_ipToScannerInfoLock);
        std::string ip = info.addr;
        auto it = g_ipToScannerInfo.find(ip);
        if (it != g_ipToScannerInfo.end()) {
            g_ipToScannerInfo.erase(it);
        }
    }
    return NETMANAGER_EXT_SUCCESS;
}

int32_t ScanMDnsDiscoveryObserver::HandleStopDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode)
{
    SCAN_HILOGD("Stop mdns service info, name = [%{private}s]", serviceInfo.name.c_str());
    return NETMANAGER_EXT_SUCCESS;
}

}  // namespace OHOS::Scan
