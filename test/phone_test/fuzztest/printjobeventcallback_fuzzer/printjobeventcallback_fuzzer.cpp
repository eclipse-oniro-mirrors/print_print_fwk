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
#include "printjobeventcallback_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_job_event_callback.h"
#include "print_callback_stub.h"
#include "print_common_death_recipient.h"
#include "print_log.h"
#include "print_constant.h"
#include "printer_info.h"
#include "print_job.h"
#include "ppd_info.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 50;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t U32_AT_SIZE = 4;
constexpr int FUZZ_MAX_JOB_LISTENER_COUNT = 5;
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

std::shared_ptr<PrintAttributes> CreateFuzzPrintAttributes(FuzzedDataProvider *dataProvider)
{
    bool createNull = dataProvider->ConsumeBool();
    if (createNull) {
        return nullptr;
    }
    auto attrs = std::make_shared<PrintAttributes>();
    attrs->SetCopyNumber(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    return attrs;
}

void TestExecuteJobBlock(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_BLOCK;
    info.jobId = jobId;
    callback->Execute(info);
}

void TestExecuteJobSuccess(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_SUCCESS,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_SUCCESS;
    info.jobId = jobId;
    callback->Execute(info);
}

void TestExecuteJobFail(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_FAIL,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_FAIL;
    info.jobId = jobId;
    callback->Execute(info);
}

void TestExecuteJobCancel(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_CANCEL,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_CANCEL;
    info.jobId = jobId;
    callback->Execute(info);
}

void TestExecuteJobStateCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_STATE_CALLBACK,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_STATE_CALLBACK;
    info.jobId = jobId;
    info.printJobInfo = CreateFuzzPrintJob(dataProvider);
    callback->Execute(info);
}

void TestExecuteJobCallbackAdapterWithFd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_CALLBACK_ADAPTER,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_CALLBACK_ADAPTER;
    info.jobId = jobId;
    info.fd = dataProvider->ConsumeIntegralInRange<uint32_t>(1, MAX_SET_NUMBER);
    info.jobState = static_cast<PrintJobState>(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    info.adapterState = static_cast<PrintDocumentAdapterState>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    callback->Execute(info);
}

void TestExecuteJobCallbackAdapterWithAttrs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_CALLBACK_ADAPTER,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_CALLBACK_ADAPTER;
    info.jobId = jobId;
    info.fd = 0;
    info.oldAttrs = CreateFuzzPrintAttributes(dataProvider);
    info.newAttrs = CreateFuzzPrintAttributes(dataProvider);
    callback->Execute(info);
}

void TestExecuteJobCallbackAdapterFail(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_CALLBACK_ADAPTER,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_CALLBACK_ADAPTER;
    info.jobId = jobId;
    info.fd = 0;
    info.oldAttrs = nullptr;
    info.newAttrs = nullptr;
    callback->Execute(info);
}

void TestExecuteJobFileGetAdapter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_FILE_GET_ADAPTER,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_FILE_GET_ADAPTER;
    info.jobId = jobId;
    info.fileCompletedState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    callback->Execute(info);
}

void TestExecuteUnknownType(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        UNKNOWN_TYPE,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);

    CallbackInfo info;
    info.cbEventType = static_cast<CallbackEventType>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(FUZZ_UNKNOWN_CALLBACK_TYPE_MIN, MAX_SET_NUMBER));
    info.jobId = jobId;
    callback->Execute(info);
}

void TestExecuteNoListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    CallbackInfo info;
    info.cbEventType = PRINT_JOB_BLOCK;
    info.jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->Execute(info);
}

void TestIsRemoteDied(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    int jobCount = dataProvider->ConsumeIntegralInRange<int>(1, FUZZ_MAX_JOB_LISTENER_COUNT);
    for (int i = 0; i < jobCount; ++i) {
        std::string jobId = "job-" + std::to_string(i);
        callback->SetListener(CreateMockListener(dataProvider), jobId);
    }

    sptr<IRemoteObject> remoteObj = nullptr;
    if (dataProvider->ConsumeBool() && !callback->listeners_.empty()) {
        auto it = callback->listeners_.begin();
        if (it->second != nullptr) {
            remoteObj = it->second->AsObject();
        }
    }
    callback->IsRemoteDied(remoteObj);
}

void TestClear(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    int jobCount = dataProvider->ConsumeIntegralInRange<int>(0, FUZZ_MAX_JOB_LISTENER_COUNT);
    for (int i = 0; i < jobCount; ++i) {
        std::string jobId = "job-" + std::to_string(i);
        callback->SetListener(CreateMockListener(dataProvider), jobId);
    }
    callback->Clear();
}

void TestSetListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sptr<IPrintCallback> firstListener = CreateMockListener(dataProvider);
    callback->SetListener(firstListener, jobId);
    sptr<IPrintCallback> secondListener = CreateMockListener(dataProvider);
    callback->SetListener(secondListener, jobId);
}

void TestDeleteListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);
    callback->DeleteListener(jobId);

    callback->DeleteListener(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
}

void TestHasJobId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new(std::nothrow) PrintCommonDeathRecipient([](const sptr<IRemoteObject> &) {});
    auto callback = std::make_shared<PrintJobEventCallback>(
        dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER),
        dataProvider->ConsumeIntegralInRange<pid_t>(0, MAX_SET_NUMBER),
        PRINT_JOB_BLOCK,
        deathRecipient);

    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    callback->SetListener(CreateMockListener(dataProvider), jobId);
    callback->HasJobId(jobId);

    callback->HasJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestExecuteJobBlock,
        &TestExecuteJobSuccess,
        &TestExecuteJobFail,
        &TestExecuteJobCancel,
        &TestExecuteJobStateCallback,
        &TestExecuteJobCallbackAdapterWithFd,
        &TestExecuteJobCallbackAdapterWithAttrs,
        &TestExecuteJobCallbackAdapterFail,
        &TestExecuteJobFileGetAdapter,
        &TestExecuteUnknownType,
        &TestExecuteNoListener,
        &TestIsRemoteDied,
        &TestClear,
        &TestSetListener,
        &TestDeleteListener,
        &TestHasJobId,
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
