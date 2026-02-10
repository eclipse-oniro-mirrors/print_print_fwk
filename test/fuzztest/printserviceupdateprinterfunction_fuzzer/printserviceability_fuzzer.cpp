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
static const std::string DEFAULT_PRINTERID = "testId";
void TestAddPrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->AddPrinters(printerInfos);
}

void TestAddRawPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);

    PrintServiceAbility::GetInstance()->AddRawPrinter(printerInfo);
}

void TestRemovePrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerIds;
    printerIds.push_back(printerId);
    PrintServiceAbility::GetInstance()->RemovePrinters(printerIds);
}

void TestUpdatePrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->UpdatePrinters(printerInfos);
    return;
}

void TestUpdatePrinterState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrinterState(printerId, state);
}

void TestUpdatePrintJobStateOnlyForSystemApp(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
}

void TestAdapterGetFileCallBack(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->AdapterGetFileCallBack(jobId, state, subState);
}

void TestUnregisterPrintTaskCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UnregisterPrintTaskCallback(jobId, state, subState);
}

void TestUpdateExtensionInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->UpdateExtensionInfo(extInfo);
}

void TestRequestPreview(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {1};
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetOption(JOB_OPTIONS);
    std::string previewResult = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RequestPreview(printJob, previewResult);
}

void TestQueryPrinterCapability(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryPrinterCapability(printerId);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestAddPrinters(data, size, dataProvider);
    TestRemovePrinters(data, size, dataProvider);
    TestUpdatePrinters(data, size, dataProvider);
    TestUpdatePrinterState(data, size, dataProvider);
    TestUpdatePrintJobStateOnlyForSystemApp(data, size, dataProvider);
    TestAdapterGetFileCallBack(data, size, dataProvider);
    TestUnregisterPrintTaskCallback(data, size, dataProvider);
    TestUpdateExtensionInfo(data, size, dataProvider);
    TestRequestPreview(data, size, dataProvider);
    TestQueryPrinterCapability(data, size, dataProvider);
    TestAddRawPrinter(data, size, dataProvider);
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
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
