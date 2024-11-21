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

#include "scan_mdns_service.h"
#include "mdns_common.h"

namespace OHOS::Scan {
using namespace OHOS::NetManagerStandard;
namespace {
std::map<std::string, ScanDeviceInfoTCP> g_ipTpScannerInfo;
std::mutex g_lock;
static std::string GetServiceAttribute(MDnsServiceInfo &info, const std::string& key)
{
    TxtRecord attrMap = info.GetAttrMap();
    auto attrArrSize = attrMap.size();
    if (attrArrSize < 1) {
        SCAN_HILOGE("can not get attr");
        return "";
    }
    if (attrMap.find(key) == attrMap.end()) {
        SCAN_HILOGE("can not find key, key = [%{public}s]", key.c_str());
        return "";
    }
    std::string value = "";
    if (!attrMap[key].empty()) {
        value += std::accumulate(attrMap[key].begin(), attrMap[key].end(), "");
    }
    return value;
}
}
std::map<std::string, sptr<ScanMDnsDiscoveryObserver>> ScanMdnsService::discoveryCallBackPtrs_;

bool ScanMdnsService::OnStartDiscoverService()
{
    const std::vector<std::string> scannerServiceTypes = { "_scanner._tcp" };
    constexpr int32_t MDNS_PORT = 5353;
    {
        std::lock_guard<std::mutex> autoLock(g_lock);
        g_ipTpScannerInfo.clear();
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
        discoveryCallBackPtrs_[type] = callbackPtr;
    }
    return true;
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
    discoveryCallBackPtrs_.clear();
    return true;
}

bool ScanMdnsService::FindDeviceNameByIp(const std::string& ip, std::string& deviceName)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (g_ipTpScannerInfo.find(ip) == g_ipTpScannerInfo.end()) {
        SCAN_HILOGW("cannot find scanner info in map.");
        return false;
    }
    deviceName = g_ipTpScannerInfo[ip].deviceName;
    return true;
}

void ScanMDnsDiscoveryObserver::HandleServiceFound(const MDnsServiceInfo &info, int32_t retCode)
{
    SCAN_HILOGD("Found mdns service info, name = [%{public}s]", info.name.c_str());
    sptr<ScanMDnsResolveObserver> scanMDnsResolveCallBack_ = new (std::nothrow) ScanMDnsResolveObserver(info);
    if (scanMDnsResolveCallBack_ == nullptr) {
        SCAN_HILOGE("scanMDnsResolveCallBack_ is a nullptr.");
        return;
    }
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->ResolveService(info, scanMDnsResolveCallBack_);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        SCAN_HILOGE("mdns ResolveService failed, ret = [%{public}d].", ret);
    }
}

void ScanMDnsResolveObserver::HandleResolveResult(const MDnsServiceInfo &info, int32_t retCode)
{
    MDnsServiceInfo tempInfo = info;
    SCAN_HILOGD("MDnsInfo name = [%{public}s], type = [%{public}s]", info.name.c_str(), info.type.c_str());
    std::unique_ptr<ScanDeviceInfoTCP> scannerInfo = std::make_unique<ScanDeviceInfoTCP>();
    scannerInfo->addr = tempInfo.addr;
    scannerInfo->deviceName = tempInfo.name;
    scannerInfo->port = std::to_string(tempInfo.port);
    std::vector<std::string> keys = {"UUID", "adminur", "button", "feeder", "mdl", "mfg", "mote", "txtvers", "ty"};
    for (auto key : keys) {
        std::string value = GetServiceAttribute(tempInfo, key);
        if (value.empty()) {
            SCAN_HILOGW("GetScannerList key [%{public}s] is empty", key.c_str());
            continue;
        }
        SCAN_HILOGD("MdnsInfo key:[%{public}s] value:[%{public}s]", key.c_str(), value.c_str());
        if (key == "UUID") {
            scannerInfo->uuid = value;
        } else if (key == "mdl") {
            scannerInfo->model = value;
        } else if (key == "mfg") {
            scannerInfo->manufacturer = value;
        } else if (key == "ty") {
            scannerInfo->deviceType = value;
        } else if (key == "port") {
            scannerInfo->port = value;
        } else if (key == "button") {
            scannerInfo->button = value;
        } else if (key == "feeder") {
            scannerInfo->feeder = value;
        }
    }
    SCAN_HILOGI("mdns scanner's deviceName:[%{public}s]", scannerInfo->deviceName.c_str());
    {
        std::lock_guard<std::mutex> autoLock(g_lock);
        g_ipTpScannerInfo[scannerInfo->addr] = *scannerInfo;
    }
}

void ScanMDnsDiscoveryObserver::HandleStopDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode)
{
    SCAN_HILOGD("Stop mdns service info, name = [%{public}s]", serviceInfo.name.c_str());
}

}  // namespace OHOS::Scan
