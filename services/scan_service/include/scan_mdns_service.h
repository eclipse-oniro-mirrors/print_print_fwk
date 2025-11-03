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

#ifndef SCAN_MDNS_SERVICE_H
#define SCAN_MDNS_SERVICE_H

#include <unordered_set>
#include <condition_variable>
#include <variant>
#include "discovery_callback_stub.h"
#include "resolve_callback_stub.h"
#include "mdns_client.h"
#include "mdns_common.h"
#include "scanner_info.h"
#include "scan_log.h"
#include "scan_service_ability.h"

namespace OHOS::Scan {
using namespace OHOS::NetManagerStandard;

class ScanMDnsDiscoveryObserver : public DiscoveryCallbackStub {
public:
    explicit ScanMDnsDiscoveryObserver(const MDnsServiceInfo &info) : expected_(info) {}
    virtual ~ScanMDnsDiscoveryObserver() = default;
    int32_t HandleStartDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode) override
    {
        return NETMANAGER_EXT_SUCCESS;
    }
    int32_t HandleStopDiscover(const MDnsServiceInfo &serviceInfo, int32_t retCode) override;
    int32_t HandleServiceLost(const MDnsServiceInfo &serviceInfo, int32_t retCode) override;
    int32_t HandleServiceFound(const MDnsServiceInfo &info, int32_t retCode) override;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        SCAN_HILOGD("GetScannerList HandleSerieFound OnRemoteRequest");
        return DiscoveryCallbackStub::OnRemoteRequest(code, data, reply, option);
    }
public:
    MDnsServiceInfo expected_;
};

class ScanMDnsResolveObserver : public ResolveCallbackStub {
public:
    explicit ScanMDnsResolveObserver(const MDnsServiceInfo &info):_serviceInfo(info) {}
    virtual ~ScanMDnsResolveObserver() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption& option) override
    {
        SCAN_HILOGD("GetScannerList ScanMDnsResolveObserver OnRemoteRequest");
        return ResolveCallbackStub::OnRemoteRequest(code, data, reply, option);
    }
    int32_t HandleResolveResult(const MDnsServiceInfo& info, int32_t retCode) override;
public:
    MDnsServiceInfo _serviceInfo;

private:
    int32_t SyncSysDataAndNotifyScanService(ScanDeviceInfoTCP& scannerInfo);
    std::string GetMdnsInfoAttribute(MDnsServiceInfo &info, const std::string& key);
};

class ScanMDnsLossResolveObserver : public ResolveCallbackStub {
public:
    explicit ScanMDnsLossResolveObserver(const MDnsServiceInfo &info):_serviceInfo(info) {}
    virtual ~ScanMDnsLossResolveObserver() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption& option) override
    {
        SCAN_HILOGD("GetScannerList ScanMDnsLossResolveObserver OnRemoteRequest");
        return ResolveCallbackStub::OnRemoteRequest(code, data, reply, option);
    }
    int32_t HandleResolveResult(const MDnsServiceInfo& info, int32_t retCode) override;
public:
    MDnsServiceInfo _serviceInfo;
};

class ScanMdnsService {
public:
    static ScanMdnsService& GetInstance();
    void PushScanInfoToQueue(const ScanDeviceInfoSync& info);
    void SetScannerInfoMap(const std::string& ip, const ScanDeviceInfoTCP& info);
    bool OnStartDiscoverService();
    bool OnStopDiscoverService();
    bool FindNetScannerInfoByIp(const std::string& ip, ScanDeviceInfoTCP& netScannerInfo);
private:
    void UpdateScannerIdThread();
    void SaveMdnsCallbackStubPtr(const std::string& type, sptr<ScanMDnsDiscoveryObserver> callbackPtr);
    std::queue<ScanDeviceInfoSync> infoQueue_;
    std::map<std::string, ScanDeviceInfoTCP> netScannerInfoMap_;
    std::map<std::string, sptr<ScanMDnsDiscoveryObserver>> discoveryCallBackPtrs_;
    std::mutex discoveryCallBackPtrsLock_;
    std::mutex infoQueueLock_;
    std::mutex ipToScannerInfoMapLock_;
    std::atomic<bool> isListening_{false};
    std::condition_variable cv_;
};
}
#endif // !SCAN_MDNS_SERVICE_H
