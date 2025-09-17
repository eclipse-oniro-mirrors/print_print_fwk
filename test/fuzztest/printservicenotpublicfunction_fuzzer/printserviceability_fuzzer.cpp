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
#include "printserviceability_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "printer_capability.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"
#include "print_callback.h"
#include "iprint_adapter_inner.h"

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr int MAX_SET_NUMBER = 128;
constexpr size_t U32_AT_SIZE = 4;
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"testId\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\","
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"]}";

void TestCheckIsDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsDefaultPrinter(printerId);
}

void TestCheckIsLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsLastUsedPrinter(printerName);
}

void TestSetLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetLastUsedPrinter(printerId);
}

void TestSendPrintJobEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob jobInfo;
    uint32_t jobStateArr[] = {PRINT_JOB_COMPLETED, PRINT_JOB_BLOCKED, PRINT_JOB_COMPLETED};
    for (auto jobState : jobStateArr) {
        jobInfo.SetJobState(jobState);
        PrintServiceAbility::GetInstance()->SendPrintJobEvent(jobInfo);
    }
    uint32_t jobState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    jobInfo.SetJobState(jobState);
    PrintServiceAbility::GetInstance()->SendPrintJobEvent(jobInfo);
}

void TestStartPrintJobCB(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->StartPrintJobCB(jobId, printJob);
}

void TestCheckPrinterUriDifferent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->CheckPrinterUriDifferent(printerInfo);
}

void TestUpdatePrinterCapability(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->UpdatePrinterCapability(printerId, printerInfo);
}

void TestReportCompletedPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReportCompletedPrint(printerId);
}

void TestNotifyAppJobQueueChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string applyResult = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyAppJobQueueChanged(applyResult);
}

void TestSendPrinterChangeEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int event = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->SendPrinterChangeEvent(event, printerInfo);
    PrintServiceAbility::GetInstance()->DestroyExtension();
}

void TestCheckJobQueueBlocked(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJob printJob;
    printJob.SetJobId(jobId);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->CheckJobQueueBlocked(printJob);
}

void TestGetListeningState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetListeningState(subState);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetListeningState(state, subState);
}

void TestUpdatePageSizeNameWithPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string pageSizeId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintPageSize pageSize;
    pageSize.SetId(pageSizeId);
    PrinterInfo printerInfo;
    PrintServiceAbility::GetInstance()->UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
}

void TestUpdatePrintJobOptionWithPrinterPreferences(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    Json::Value jobOptions;
    jobOptions[key] = value;
    PrinterInfo printerInfo;
    PrintServiceAbility::GetInstance()->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, printerInfo);
}

void TestConnectUsbPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ConnectUsbPrinter(printerId);
}

void TestClosePrintJobFd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->ClosePrintJobFd(printJob);
}


void TestNoParmFuncs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->DelayEnterLowPowerMode();
    PrintServiceAbility::GetInstance()->ExitLowPowerMode();
    PrintServiceAbility::GetInstance()->UnloadSystemAbility();
}

void TestNotPublicFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestCheckIsDefaultPrinter(data, size, dataProvider);
    TestCheckIsLastUsedPrinter(data, size, dataProvider);
    TestSetLastUsedPrinter(data, size, dataProvider);
    TestSendPrintJobEvent(data, size, dataProvider);
    TestStartPrintJobCB(data, size, dataProvider);
    TestCheckPrinterUriDifferent(data, size, dataProvider);
    TestUpdatePrinterCapability(data, size, dataProvider);
    TestReportCompletedPrint(data, size, dataProvider);
    TestNotifyAppJobQueueChanged(data, size, dataProvider);
    TestSendPrinterChangeEvent(data, size, dataProvider);
    TestCheckJobQueueBlocked(data, size, dataProvider);
    TestGetListeningState(data, size, dataProvider);
    TestUpdatePageSizeNameWithPrinterInfo(data, size, dataProvider);
    TestUpdatePrintJobOptionWithPrinterPreferences(data, size, dataProvider);
    TestConnectUsbPrinter(data, size, dataProvider);
    TestClosePrintJobFd(data, size, dataProvider);
    TestNoParmFuncs(data, size, dataProvider);
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
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    return 0;
}
