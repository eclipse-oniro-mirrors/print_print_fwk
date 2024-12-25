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
#include "scan_manager_client.h"
#include "scan_callback.h"
#include "scanner_info.h"
#include "scancallback_fuzzer.h"

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestSetCallbackParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    CallbackParam param;
    std::mutex mutex;
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    param.InitialCallbackParam(env, ref, mutex);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    ScanDeviceInfoTCP tcpInfo;
    param.SetCallbackParam(state, tcpInfo);
}

void TestSetCallbackSyncParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    CallbackParam param;
    std::mutex mutex;
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    param.InitialCallbackParam(env, ref, mutex);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    ScanDeviceInfoSync syncInfo;
    param.SetCallbackSyncParam(state, syncInfo);
}

void TestOnCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    ScanDeviceInfoTCP tcpInfo;
    callBack.OnCallback(state, tcpInfo);
    ScanDeviceInfo deviceInfo;
    callBack.OnCallback(state, deviceInfo);
}

void TestOnCallbackSync(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    std::mutex mutex;
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    ScanDeviceInfoSync syncInfo;
    callBack.OnCallbackSync(state, syncInfo);
}

void TestOnGetFrameResCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    bool isGetSucc = dataProvider->ConsumeBool();
    int32_t sizeRead = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    callBack.OnGetFrameResCallback(isGetSucc, sizeRead);
}

void TestOnScanInitCallback(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    callBack.OnScanInitCallback(scanVersion);
}

void TestOnSendSearchMessage(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    std::string message = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callBack.OnSendSearchMessage(message);
}

void TestOnGetDevicesList(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    int32_t infoSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::vector<ScanDeviceInfo> infos(infoSize);
    callBack.OnGetDevicesList(infos);
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
    OHOS::Scan::TestSetCallbackParam(data, size, &dataProvider);
    OHOS::Scan::TestSetCallbackSyncParam(data, size, &dataProvider);
    OHOS::Scan::TestOnCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnCallbackSync(data, size, &dataProvider);
    OHOS::Scan::TestOnGetFrameResCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnScanInitCallback(data, size, &dataProvider);
    OHOS::Scan::TestOnSendSearchMessage(data, size, &dataProvider);
    OHOS::Scan::TestOnGetDevicesList(data, size, &dataProvider);

    return 0;
}

