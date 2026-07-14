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
#define private public
#include "printereventcallback_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "printer_event_callback.h"
#include "print_callback_stub.h"
#include "print_common_death_recipient.h"
#include "print_log.h"
#include "print_constant.h"
#include "printer_info.h"
#include "print_job.h"
#include "ppd_info.h"
#include "print_shared_host.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 50;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t FUZZ_MAX_PRINTER_EVENT_TYPE = 5;
constexpr int FUZZ_MAX_PPD_QUERY_COUNT = 5;
constexpr int FUZZ_MAX_SHARED_HOST_COUNT = 5;
constexpr uint32_t FUZZ_UNKNOWN_CALLBACK_TYPE_MIN = 20;

class MockPrintCallbackStub : public PrintCallbackStub {
public:
    MockPrintCallbackStub() : PrintCallbackStub() {}
    bool OnCallback() override { return true; }
    bool OnCallback(uint32_t state, const PrinterInfo &info) override { return true; }
    bool OnCallback(uint32_t state, const PrintJob &info) override { return true; }
    bool OnCallback(const std::string &extensionId, const std::string &info) override { return true; }
    bool OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds) override { return true; }
    bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) override { return true; }
    bool OnCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) override { return true; }
    bool OnCallbackAdapterGetFile(uint32_t state) override { return true; }
    bool OnCallback(const std::vector<PrintSharedHost> &sharedHosts) override { return true; }
};

sptr<IPrintCallback> CreateMockListener(FuzzedDataProvider *dataProvider)
{
    bool createNull = dataProvider->ConsumeBool();
    if (createNull) {
        return nullptr;
    }
    sptr<IPrintCallback> listener = new(std::nothrow) MockPrintCallbackStub();
    return listener;
}

std::shared_ptr<PrinterInfo> CreateFuzzPrinterInfo(FuzzedDataProvider *dataProvider)
{
    bool createNull = dataProvider->ConsumeBool();
    if (createNull) {
        return nullptr;
    }
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    info->SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    info->SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    return info;
}

std::shared_ptr<PrintJob> CreateFuzzPrintJob(FuzzedDataProvider *dataProvider)
{
    bool createNull = dataProvider->ConsumeBool();
    if (createNull) {
        return nullptr;
    }
    auto job = std::make_shared<PrintJob>();
    job->SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    job->SetJobState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    return job;
}

void TestExecutePrinterJobStateChange(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_JOB_STATE_CHANGE,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_JOB_STATE_CHANGE;
    info.printJobInfo = CreateFuzzPrintJob(dataProvider);
    callback->Execute(info);
}

void TestExecutePrinterChange(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_CHANGE,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_CHANGE;
    info.printerEvent = static_cast<PrinterEvent>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_PRINTER_EVENT_TYPE));
    info.printerInfo = CreateFuzzPrinterInfo(dataProvider);
    callback->Execute(info);
}

void TestExecutePrinterDiscover(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_DISCOVER,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_DISCOVER;
    info.printerEvent = static_cast<PrinterEvent>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_PRINTER_EVENT_TYPE));
    info.printerInfo = CreateFuzzPrinterInfo(dataProvider);
    callback->Execute(info);
}

void TestExecutePrinterStateChange(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_STATE_CHANGE,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_STATE_CHANGE;
    info.printerInfo = CreateFuzzPrinterInfo(dataProvider);
    callback->Execute(info);
}

void TestExecutePrinterInfoQuery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_INFO_QUERY,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_INFO_QUERY;
    info.printerInfo = CreateFuzzPrinterInfo(dataProvider);
    int ppdCount = dataProvider->ConsumeIntegralInRange<int>(0, FUZZ_MAX_PPD_QUERY_COUNT);
    for (int i = 0; i < ppdCount; ++i) {
        PpdInfo ppdInfo;
        ppdInfo.SetPpdName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
        info.ppdInfos.push_back(ppdInfo);
    }
    callback->Execute(info);
}

void TestExecuteExtInfoChange(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_EXT_INFO_CHANGE,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_EXT_INFO_CHANGE;
    info.extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    info.extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->Execute(info);
}

void TestExecuteSharedHostDiscover(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_SHARED_HOST_DISCOVER,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINTER_SHARED_HOST_DISCOVER;
    int hostCount = dataProvider->ConsumeIntegralInRange<int>(0, FUZZ_MAX_SHARED_HOST_COUNT);
    for (int i = 0; i < hostCount; ++i) {
        PrintSharedHost host;
        host.SetIp(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
        host.SetShareName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
        host.SetWorkgroupName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
        info.sharedHosts.push_back(host);
    }
    callback->Execute(info);
}

void TestExecuteUnknownType(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        UNKNOWN_TYPE,
        CreateMockListener(dataProvider),
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = static_cast<CallbackEventType>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(FUZZ_UNKNOWN_CALLBACK_TYPE_MIN, MAX_SET_NUMBER));
    callback->Execute(info);
}

void TestIsRemoteDied(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_STATE_CHANGE,
        nullptr,
        deathRecipient);

    bool setListener = dataProvider->ConsumeBool();
    if (setListener) {
        sptr<IPrintCallback> listener = new(std::nothrow) MockPrintCallbackStub();
        callback->SetListener(listener);
    }

    sptr<IRemoteObject> remoteObj = nullptr;
    if (dataProvider->ConsumeBool() && callback->listener_ != nullptr) {
        remoteObj = callback->listener_->AsObject();
    }
    callback->IsRemoteDied(remoteObj);
}

void TestClear(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_STATE_CHANGE,
        nullptr,
        deathRecipient);

    bool setListener = dataProvider->ConsumeBool();
    if (setListener) {
        sptr<IPrintCallback> listener = new(std::nothrow) MockPrintCallbackStub();
        callback->SetListener(listener);
    }
    callback->Clear();
}

void TestSetListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrinterEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINTER_STATE_CHANGE,
        nullptr,
        deathRecipient);

    sptr<IPrintCallback> firstListener = CreateMockListener(dataProvider);
    callback->SetListener(firstListener);
    sptr<IPrintCallback> secondListener = CreateMockListener(dataProvider);
    callback->SetListener(secondListener);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestExecutePrinterJobStateChange,
        &TestExecutePrinterChange,
        &TestExecutePrinterDiscover,
        &TestExecutePrinterStateChange,
        &TestExecutePrinterInfoQuery,
        &TestExecuteExtInfoChange,
        &TestExecuteSharedHostDiscover,
        &TestExecuteUnknownType,
        &TestIsRemoteDied,
        &TestClear,
        &TestSetListener,
    };
    TestHandler handler = dataProvider->PickValueInArray(tasks);
    handler(data, size, dataProvider);
}

}  // namespace Print
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < OHOS::Print::U32_AT_SIZE) {
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
