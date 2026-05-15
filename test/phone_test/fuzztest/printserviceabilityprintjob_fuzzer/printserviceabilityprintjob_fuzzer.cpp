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
#define private public
#define protected public
#include "printserviceabilityprintjob_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr int MAX_SET_NUMBER = 128;
constexpr size_t U32_AT_SIZE = 4;

void TestQueryAllActivePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files;
    for (size_t i = 0; i < dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER); ++i) {
        files.push_back(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    }
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintJob> printJobs;
    printJobs.push_back(printJob);
    PrintServiceAbility::GetInstance()->QueryAllActivePrintJob(printJobs);
}

void TestQueryAllPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files;
    for (size_t i = 0; i < dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER); ++i) {
        files.push_back(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    }
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintJob> printJobs;
    printJobs.push_back(printJob);
    PrintServiceAbility::GetInstance()->QueryAllPrintJob(printJobs);
}

void TestQueryPrintJobById(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files;
    for (size_t i = 0; i < dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER); ++i) {
        files.push_back(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    }
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryPrintJobById(printJobId, printJob);
}

void TestQueryQueuedPrintJobById(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files;
    for (size_t i = 0; i < dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER); ++i) {
        files.push_back(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    }
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryQueuedPrintJobById(printJobId, printJob);
}

void TestOnQueryCallBackEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string make = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo info;
    info.SetPrinterMake(make);
    info.SetOption(option);
    PrintServiceAbility::GetInstance()->OnQueryCallBackEvent(info);
}

void TestGetPrinterDefaultPreferences(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterPreferences defaultPreferences;
    PrintServiceAbility::GetInstance()->GetPrinterDefaultPreferences(printerId, defaultPreferences);
}

void TestCheckPreferencesConflicts(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string changedType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterPreferences printerPreference;
    printerPreference.SetDefaultDuplexMode(dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    printerPreference.SetDefaultPrintQuality(dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    printerPreference.SetDefaultOrientation(dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    printerPreference.SetDefaultColorMode(dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    printerPreference.SetDefaultMediaType(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerPreference.SetDefaultPageSizeId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerPreference.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerPreference.SetBorderless(dataProvider->ConsumeBool());
    printerPreference.SetDefaultCollate(dataProvider->ConsumeBool());
    printerPreference.SetDefaultReverse(dataProvider->ConsumeBool());
    std::vector<std::string> conflictingOptions;
    PrintServiceAbility::GetInstance()->CheckPreferencesConflicts(
        printerId, changedType, printerPreference, conflictingOptions);
}

void TestCheckPrintJobConflicts(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string changedType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files;
    for (size_t i = 0; i < dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER); ++i) {
        files.push_back(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    }
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<std::string> conflictingOptions;
    PrintServiceAbility::GetInstance()->CheckPrintJobConflicts(changedType, printJob, conflictingOptions);
}

void TestCheckPrintConstraint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckPrintConstraint(option, jobId);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("Multithreading is running at function TestAllFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestQueryAllActivePrintJob,
        &TestQueryAllPrintJob,
        &TestQueryPrintJobById,
        &TestQueryQueuedPrintJobById,
        &TestOnQueryCallBackEvent,
        &TestGetPrinterDefaultPreferences,
        &TestCheckPreferencesConflicts,
        &TestCheckPrintJobConflicts,
        &TestCheckPrintConstraint,
    };
    TestHandler handler = dataProvider->PickValueInArray(tasks);
    handler(data, size, dataProvider);
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

    if (size < OHOS::Print::U32_AT_SIZE) {
    }

    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
