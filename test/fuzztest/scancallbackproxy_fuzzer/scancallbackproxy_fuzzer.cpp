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
#include "scancallbackproxy_fuzzer.h"
#include "scan_callback_proxy.h"

namespace OHOS {
namespace Scan {
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr int MAX_SET_NUMBER = 100;
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;

    void TestTcpOnCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        ScanDeviceInfoTCP info;
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnCallback(state, info);
    }

    void TestUsbOnCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        ScanDeviceInfo info;
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnCallback(state, info);
    }

    void TestOnCallbackSync(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        ScanDeviceInfoSync info;
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnCallbackSync(state, info);
    }

    void TestOnGetFrameResCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        bool isGetSucc = dataProvider->ConsumeBool();
        int32_t sizeRead = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnGetFrameResCallback(isGetSucc, sizeRead);
    }

    void TestOnScanInitCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnScanInitCallback(scanVersion);
    }

    void TestOnSendSearchMessage(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string message = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        scanCallbackProxy.OnSendSearchMessage(message);
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
    OHOS::Scan::TestTcpOnCallback(data, size, &dataProvider);
    OHOS::Scan::TestUsbOnCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnCallbackSync(data, size, &dataProvider);
    OHOS::Scan::TestOnGetFrameResCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnScanInitCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnSendSearchMessage(data, size, &dataProvider);
    return 0;
}

