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

#define TDD_ENABLE 1

#include "fuzzer/FuzzedDataProvider.h"
#include "napi/native_api.h"
#include "scan_callback.h"
#include "scancallbackstub_fuzzer.h"
#include "print_log.h"
#include <functional>

namespace OHOS::Scan {
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    uint32_t code = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    MessageParcel parcelData;
    parcelData.WriteInterfaceToken(u"OHOS.Scan.IScanCallback");
    MessageParcel reply;
    ScanCallback callBack(nullptr, nullptr);
    MessageOption option;
    callBack.OnRemoteRequest(code, parcelData, reply, option);
}

void HandleDeviceInfoEventFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    MessageParcel parcelData;
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    parcelData.WriteUint32(state);
    ScanCallback callBack(nullptr, nullptr);
    MessageParcel reply;
    callBack.HandleDeviceInfoEvent(parcelData, reply);
}

void HandleDeviceInfoSyncEventFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    MessageParcel parcelData;
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    parcelData.WriteUint32(state);
    ScanCallback callBack(nullptr, nullptr);
    MessageParcel reply;
    callBack.HandleDeviceInfoSyncEvent(parcelData, reply);
}

void HandleSendDeviceListFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    MessageParcel parcelData;
    int32_t infosSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    parcelData.WriteInt32(infosSize);
    std::vector<ScanDeviceInfo> infos(infosSize);
    for (size_t i = 0; i < infos.size(); i++) {
        infos[i].Marshalling(parcelData);
    }
    ScanCallback callBack(nullptr, nullptr);
    MessageParcel reply;
    callBack.HandleSendDeviceList(parcelData, reply);
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

    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::OnRemoteRequestFuzzTest,
        &OHOS::Scan::HandleDeviceInfoEventFuzzTest,
        &OHOS::Scan::HandleDeviceInfoSyncEventFuzzTest,
        &OHOS::Scan::HandleSendDeviceListFuzzTest
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}

