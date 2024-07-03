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

#define SCAN_MDNS_PORT 5353

namespace OHOS::Scan {
using namespace OHOS::NetManagerStandard;

void ScanMdnsService::SetServiceType(std::string stype)
{
    _serviceInfo.type = stype;
    _serviceInfo.port = SCAN_MDNS_PORT;
    _scanMDnsDiscoveryCallBack = new (std::nothrow) ScanMDnsDiscoveryObserver(_serviceInfo);
    _scanMDnsResolveCallBack = new (std::nothrow) ScanMDnsResolveObserver(_serviceInfo);
}

MDnsServiceInfo &ScanMdnsService::GetServiceInfo()
{
    return _serviceInfo;
}

void ScanMdnsService::SetServiceInfo(const MDnsServiceInfo &info)
{
    _serviceInfo = info;
}

sptr<ScanMDnsDiscoveryObserver> ScanMdnsService::GetMDnsDiscoveryCallBack()
{
    return _scanMDnsDiscoveryCallBack;
}

void ScanMdnsService::SetMDnsDiscoveryCallBack(sptr<ScanMDnsDiscoveryObserver> &cb)
{
    _scanMDnsDiscoveryCallBack = cb;
}

sptr<ScanMDnsResolveObserver> ScanMdnsService::GetMDnsResolveCallBack()
{
    return _scanMDnsResolveCallBack;
}

void ScanMdnsService::SetMDnsResolveCallBack(sptr<ScanMDnsResolveObserver> &cb)
{
    _scanMDnsResolveCallBack = cb;
}

bool ScanMdnsService::onStartDiscoverService()
{
    if (_scanMDnsDiscoveryCallBack == nullptr) {
        SCAN_HILOGE("GetScannerList onStartDiscoverService1 nullptr");
        return false;
    }
    SCAN_HILOGI("GetScannerList onStartDiscoverService begin");
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->StartDiscoverService(
        _serviceInfo.type, _scanMDnsDiscoveryCallBack);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        return false;
    }
    SCAN_HILOGI("GetScannerList onStartDiscoverService end");
    return true;
}

bool ScanMdnsService::onResolveService(MDnsServiceInfo &serviceInfo)
{
    SCAN_HILOGI("GetScannerList onResolveService");
    if (_scanMDnsResolveCallBack == nullptr) {
        SCAN_HILOGE("GetScannerList _scanMDnsResolveCallBack null fail");
        return false;
    }
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->ResolveService(serviceInfo, _scanMDnsResolveCallBack);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        SCAN_HILOGE("GetScannerList onResolveService false");
        return false;
    }
    SCAN_HILOGI("GetScannerList onResolveService1 success");
    return true;
}

bool ScanMdnsService::onStopDiscoverService()
{
    SCAN_HILOGI("GetScannerList onStopDiscoverService");
    if (_scanMDnsDiscoveryCallBack == nullptr) {
        SCAN_HILOGE("GetScannerList _scanMDnsDiscoveryCallBack null fail");
        return false;
    }
    int32_t ret = DelayedSingleton<MDnsClient>::GetInstance()->StopDiscoverService(_scanMDnsDiscoveryCallBack);
    if (ret != NETMANAGER_EXT_SUCCESS) {
        SCAN_HILOGE("GetScannerList onStopDiscoverService false");
        return false;
    }
    SCAN_HILOGI("GetScannerList onStopDiscoverService success");
    return true;
}

void ScanMDnsDiscoveryObserver::HandleServiceFound(const MDnsServiceInfo &info, int32_t retCode)
{
    MDnsServiceInfo tempInfo = info;
    SCAN_HILOGD("GetScannerList HandleServiceFound [%{public}s][%{public}s][%{public}d][%{public}s]",
        info.name.c_str(),
        info.type.c_str(),
        info.port,
        info.addr.c_str());
    ScanMdnsService::GetInstance().onResolveService(tempInfo);
}

void ScanMDnsResolveObserver::HandleResolveResult(const MDnsServiceInfo &info, int32_t retCode)
{
    _serviceInfo = info;
    SCAN_HILOGD("GetScannerList HandleResolveResult [%{public}s][%{public}s][%{public}d][%{public}s]",
        info.name.c_str(),
        info.type.c_str(),
        info.port,
        info.addr.c_str());
    MDnsServiceInfo tempInfo = info;
    auto texRecord = tempInfo.GetAttrMap();
    auto textIt = texRecord.begin();
    for (; textIt != texRecord.end(); textIt++) {
        SCAN_HILOGD("GetScannerList startHandleServiceResolve keys [%{public}s]", textIt->first.c_str());
    }

    ScanMdnsService::GetInstance().ToMDnsScaner(tempInfo);
}

void ScanMDnsDiscoveryObserver::HandleStopDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode)
{
    MDnsServiceInfo info = serviceInfo;
    SCAN_HILOGD("GetScannerList HandleStopDiscover [%{public}s][%{public}s][%{public}d][%{public}s]",
        info.name.c_str(),
        info.type.c_str(),
        info.port,
        info.addr.c_str());
}

void ScanMdnsService::ToMDnsScaner(MDnsServiceInfo &serviceInfo)
{
    std::unique_ptr<ScanDeviceInfoTCP> scannerInfo = std::make_unique<ScanDeviceInfoTCP>();
    scannerInfo->addr = serviceInfo.addr;
    scannerInfo->deviceName = serviceInfo.name;
    scannerInfo->port = std::to_string(serviceInfo.port);
    std::vector<std::string> keys = {"UUID", "adminur", "button", "feeder", "mdl", "mfg", "mote", "txtvers", "ty"};
    for (auto key : keys) {
        std::string value = ScanMdnsService::GetServiceAttribute(serviceInfo, key);
        if (value.empty()) {
            SCAN_HILOGW("GetScannerList key [%{public}s] is empty", key.c_str());
            continue;
        }
        SCAN_HILOGD("GetScannerList key:[%{public}s] value:[%{public}s]", key.c_str(), value.c_str());
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
    SCAN_HILOGD("mdns scanner's addr:[%{public}s]", scannerInfo->addr.c_str());
    SCAN_HILOGD("mdns scanner's port:[%{public}s]", scannerInfo->port.c_str());
    ScanServiceAbility::scanDeviceInfoTCPMap_[scannerInfo->addr] = *scannerInfo;
}

std::string ScanMdnsService::GetServiceAttribute(MDnsServiceInfo &serviceInfo, std::string keyStr)
{
    SCAN_HILOGD("GetScannerList GetServiceAttribute keyStr [%{public}s]", keyStr.c_str());
    TxtRecord attrMap = serviceInfo.GetAttrMap();
    auto attrArrSize = attrMap.size();
    if (attrArrSize < 1) {
        SCAN_HILOGE("can not get attr");
        return "";
    }
    auto attrIt = attrMap.find(keyStr);
    if (attrIt == attrMap.end()) {
        SCAN_HILOGE("can not find key");
        return "";
    }
    std::string value = "";
    if (!attrMap[keyStr].empty()) {
        value += std::accumulate(attrMap[keyStr].begin(), attrMap[keyStr].end(), "");
    }

    return value;
}


}  // namespace OHOS::Scan
