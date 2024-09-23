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
        std::string serviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().SetServiceType(serviceName.c_str());
        ScanMdnsService::GetInstance().onStartDiscoverService();
        ScanMdnsService::GetInstance().onStopDiscoverService();
    }

    void TestSetService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo info;
        ScanMdnsService::GetInstance().SetServiceInfo(info);
        sptr<ScanMDnsResolveObserver> resolveObserve;
        ScanMdnsService::GetInstance().SetMDnsResolveCallBack(resolveObserve);
        sptr<ScanMDnsDiscoveryObserver> discoveryObserve;
        ScanMdnsService::GetInstance().SetMDnsDiscoveryCallBack(discoveryObserve);
        ScanMdnsService::GetInstance().onStartDiscoverService();
        std::string stype = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().SetServiceType(stype);
        ScanMdnsService::GetInstance().GetMDnsResolveCallBack();
        ScanMdnsService::GetInstance().GetMDnsDiscoveryCallBack();
        ScanMdnsService::GetInstance().GetServiceInfo();
    }

    void TestGetServiceAttribute(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        serviceInfo.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string keyStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().GetServiceAttribute(serviceInfo, keyStr);
    }

    void TestonResolveService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        serviceInfo.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanMdnsService::GetInstance().onResolveService(serviceInfo);
    }

    void TestToMDnsScaner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MDnsServiceInfo serviceInfo;
        serviceInfo.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
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
    OHOS::Scan::TestGetServiceAttribute(data, size, &dataProvider);
    OHOS::Scan::TestonResolveService(data, size, &dataProvider);
    OHOS::Scan::TestToMDnsScaner(data, size, &dataProvider);
    OHOS::Scan::TestHandleServiceFound(data, size, &dataProvider);
    OHOS::Scan::TestHandleResolveResult(data, size, &dataProvider);
    OHOS::Scan::TestHandleStopDiscover(data, size, &dataProvider);
    return 0;
}

