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
#include "print_log.h"
#include <functional>

namespace OHOS::Scan {
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t FUZZ_NAPI_CALLBACK_ARG_COUNT = 1;

void TestSetCallbackParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    CallbackParam param;
    std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    param.InitialCallbackParam(env, ref, mutex);
}

void TestSetCallbackSyncParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    CallbackParam param;
    std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
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

void TestOnGetDevicesList(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    int32_t infoSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::vector<ScanDeviceInfo> infos(infoSize);
    callBack.OnGetDevicesList(infos);
}

void TestNapiCallFunctionNullParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    callBack.NapiCallFunction(nullptr, 0, nullptr);
}

void TestNapiCallFunctionWithParam(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ScanCallback callBack(env, ref);
    CallbackParam cbParam;
    std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
    cbParam.InitialCallbackParam(env, ref, mutex);
    napi_value callbackValues[FUZZ_NAPI_CALLBACK_ARG_COUNT] = { nullptr };
    callBack.NapiCallFunction(&cbParam, FUZZ_NAPI_CALLBACK_ARG_COUNT, callbackValues);
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
    }
    FuzzedDataProvider dataProvider(data, size);

    PRINT_HILOGI("Multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestSetCallbackParam,
        &OHOS::Scan::TestSetCallbackSyncParam,
        &OHOS::Scan::TestOnCallback,
        &OHOS::Scan::TestOnCallbackSync,
        &OHOS::Scan::TestOnGetDevicesList,
        &OHOS::Scan::TestNapiCallFunctionNullParam,
        &OHOS::Scan::TestNapiCallFunctionWithParam
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);

    return 0;
}

