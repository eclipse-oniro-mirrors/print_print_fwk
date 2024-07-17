/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "fuzzer/FuzzedDataProvider.h"
#include "scanmdnsservice_fuzzer.h"
#include "scan_mdns_service.h"

namespace OHOS {
namespace Scan {
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr int MAX_SET_NUMBER = 100;
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;

    void TestOnStartDiscoverService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanMdnsService::GetInstance().SetServiceType("_scanner._tcp");
        ScanMdnsService::GetInstance().onStartDiscoverService();
    }

    void TestSetServiceInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo info;
        ScanMdnsService::GetInstance().SetServiceInfo(info);
    }

    void TestSetMDnsResolveCallBack(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        sptr<ScanMDnsResolveObserver> cb;
        ScanMdnsService::GetInstance().SetMDnsResolveCallBack(cb);
    }

    void TestSetMDnsDiscoveryCallBack(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        sptr<ScanMDnsDiscoveryObserver> cb;
        ScanMdnsService::GetInstance().SetMDnsDiscoveryCallBack(cb);
        ScanMdnsService::GetInstance().onStartDiscoverService();
    }

    void TestSetServiceType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string stype = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().SetServiceType(stype);
    }

    void TestGetMDnsResolveCallBack(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanMdnsService::GetInstance().GetMDnsResolveCallBack();
    }

    void TestGetMDnsDiscoveryCallBack(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanMdnsService::GetInstance().GetMDnsDiscoveryCallBack();
    }

    void TestGetServiceInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanMdnsService::GetInstance().GetServiceInfo();
    }

    void TestGetServiceAttribute(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        std::string keyStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().GetServiceAttribute(serviceInfo, keyStr);
    }

    void TestonStopDiscoverService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanMdnsService::GetInstance().onStopDiscoverService();
    }

    void TestonResolveService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        ScanMdnsService::GetInstance().onResolveService(serviceInfo);
    }

    void TestToMDnsScaner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        ScanMdnsService::GetInstance().ToMDnsScaner(serviceInfo);
    }

    void TestHandleServiceFound(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        ScanMDnsDiscoveryObserver scanMDnsDiscoveryObserver = ScanMDnsDiscoveryObserver(serviceInfo);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanMDnsDiscoveryObserver.HandleServiceFound(serviceInfo, retCode);
    }

    void TestHandleResolveResult(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        ScanMDnsResolveObserver scanMDnsResolveObserver = ScanMDnsResolveObserver(serviceInfo);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanMDnsResolveObserver.HandleResolveResult(serviceInfo, retCode);
    }

    void TestHandleStopDiscover(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        ScanMDnsDiscoveryObserver scanMDnsDiscoveryObserver = ScanMDnsDiscoveryObserver(serviceInfo);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanMDnsDiscoveryObserver.HandleStopDiscover(serviceInfo, retCode);
    }

}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Scan::TestOnStartDiscoverService(data, size, &dataProvider);
    OHOS::Scan::TestSetServiceInfo(data, size, &dataProvider);
    OHOS::Scan::TestSetMDnsResolveCallBack(data, size, &dataProvider);
    OHOS::Scan::TestSetMDnsDiscoveryCallBack(data, size, &dataProvider);
    OHOS::Scan::TestSetServiceType(data, size, &dataProvider);
    OHOS::Scan::TestGetMDnsResolveCallBack(data, size, &dataProvider);
    OHOS::Scan::TestGetMDnsDiscoveryCallBack(data, size, &dataProvider);
    OHOS::Scan::TestGetServiceInfo(data, size, &dataProvider);
    OHOS::Scan::TestGetServiceAttribute(data, size, &dataProvider);
    OHOS::Scan::TestonStopDiscoverService(data, size, &dataProvider);
    OHOS::Scan::TestonResolveService(data, size, &dataProvider);
    OHOS::Scan::TestToMDnsScaner(data, size, &dataProvider);
    OHOS::Scan::TestHandleServiceFound(data, size, &dataProvider);
    OHOS::Scan::TestHandleResolveResult(data, size, &dataProvider);
    OHOS::Scan::TestHandleStopDiscover(data, size, &dataProvider);
    return 0;
}

