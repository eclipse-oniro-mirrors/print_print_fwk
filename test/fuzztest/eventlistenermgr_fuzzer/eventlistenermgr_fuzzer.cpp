/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "print_callback.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr int POLICY_ENUM_MAX = 3;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestRegisterPrinterListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINTER_STATE_CHANGE, CallbackEventType::PRINTER_EXT_INFO_CHANGE));
    sptr<IPrintCallback> listener = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(eventType, listener);
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr<IPrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    if (callback != nullptr) {
        DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(eventType, callback);
    } else {
        delete printerAdapterPtr;
        printerAdapterPtr = nullptr;
    }
}

void TestRegisterExtensionListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::EXTCB_START_DISCOVERY, CallbackEventType::EXTCB_DESTROY_EXTENSION));
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sptr<IPrintExtensionCallback> listener = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterExtensionListener(eventType, extensionId, listener);
}

void TestRegisterPrintJobListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINT_JOB_BLOCK, CallbackEventType::PRINT_JOB_FILE_GET_ADAPTER));
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sptr<IPrintCallback> listener = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrintJobListener(eventType, jobId, listener);
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr<IPrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    if (callback != nullptr) {
        DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrintJobListener(eventType, jobId, callback);
    } else {
        delete printerAdapterPtr;
        printerAdapterPtr = nullptr;
    }
}

void TestUnRegisterPrinterListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINTER_STATE_CHANGE, CallbackEventType::PRINTER_EXT_INFO_CHANGE));
    DelayedSingleton<EventListenerMgr>::GetInstance()->UnRegisterPrinterListener(eventType);
}

void TestUnRegisterPrintJobListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINT_JOB_BLOCK, CallbackEventType::PRINT_JOB_FILE_GET_ADAPTER));
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DelayedSingleton<EventListenerMgr>::GetInstance()->UnRegisterPrintJobListener(eventType, jobId);
}

void TestExecute(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackInfo callbackInfo;
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINTER_STATE_CHANGE, CallbackEventType::PRINT_JOB_FILE_GET_ADAPTER));
    int32_t userId = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    callbackInfo.cbEventType = eventType;
    callbackInfo.userId = userId;
    DelayedSingleton<EventListenerMgr>::GetInstance()->Execute(callbackInfo);
}

void TestIsPrinterListenerEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINTER_STATE_CHANGE, CallbackEventType::PRINTER_EXT_INFO_CHANGE));
    DelayedSingleton<EventListenerMgr>::GetInstance()->IsPrinterListenerEmpty(eventType);
}

void TestIsExtensionListenerEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::EXTCB_START_DISCOVERY, CallbackEventType::EXTCB_DESTROY_EXTENSION));
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    DelayedSingleton<EventListenerMgr>::GetInstance()->IsExtensionListenerEmpty(eventType, extensionId, userId);
}

void TestIsPrintJobListenerEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    CallbackEventType eventType = static_cast<CallbackEventType>(dataProvider->ConsumeIntegralInRange<uint32_t>(
        CallbackEventType::PRINT_JOB_BLOCK, CallbackEventType::PRINT_JOB_FILE_GET_ADAPTER));
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DelayedSingleton<EventListenerMgr>::GetInstance()->IsPrintJobListenerEmpty(eventType, jobId);
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
        &OHOS::Print::TestRegisterPrinterListener,
        &OHOS::Print::TestRegisterExtensionListener,
        &OHOS::Print::TestRegisterPrintJobListener,
        &OHOS::Print::TestUnRegisterPrinterListener,
        &OHOS::Print::TestUnRegisterPrintJobListener,
        &OHOS::Print::TestExecute,
        &OHOS::Print::TestIsPrinterListenerEmpty,
        &OHOS::Print::TestIsExtensionListenerEmpty,
        &OHOS::Print::TestIsPrintJobListenerEmpty,
    };
    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
