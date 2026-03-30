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
#include "eventlistenermgr_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "event_listener_mgr.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_USERID_NUMBER = 1000;
constexpr int MAX_SET_NUMBER = 100;
constexpr int POLICY_ENUM_MAX = 3;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestFindCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(100, MAX_SET_USERID_NUMBER);
    uint32_t pid = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t eventType = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    DelayedSingleton<EventListenerMgr>::GetInstance()->FindCallback(userId, pid, eventType);
}

void TestRegisterPrinterListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t eventType = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    sptr<IPrintCallback> listener = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(eventType, listener);
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr<IPrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(eventType, callback);
}

}  // namespace Print
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Print::U32_AT_SIZE || size > OHOS::Print::FOO_MAX_LEN) {
    }

    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Print::TestFindCallback,
        &OHOS::Print::TestRegisterPrinterListener
    };
    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
