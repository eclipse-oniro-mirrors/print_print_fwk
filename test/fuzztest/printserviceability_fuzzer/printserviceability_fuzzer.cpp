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
void TestOn(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr <PrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    if (callback != nullptr) {
        std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        PrintServiceAbility::GetInstance()->On(taskId, type, callback);
    } else {
        delete printerAdapterPtr;
        printerAdapterPtr = nullptr;
    }
}

void TestOff(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->Off(taskId, type);
}

void TestCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr <PrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    if (callback != nullptr) {
        std::string type = PRINTER_DISCOVER_EVENT_TYPE;
        PrintServiceAbility::GetInstance()->RegisterPrinterCallback(type, callback);
        PrintServiceAbility::GetInstance()->UnregisterPrinterCallback(type);
    } else {
        delete printerAdapterPtr;
        printerAdapterPtr = nullptr;
    }
    std::vector <PrintExtensionInfo> printExtensionInfos;
    PrintServiceAbility::GetInstance()->QueryAllExtension(printExtensionInfos);
    std::vector <std::string> extensionIds;
    for (auto &printExtensionInfo: printExtensionInfos) {
        extensionIds.push_back(printExtensionInfo.GetExtensionId());
    }
    PrintServiceAbility::GetInstance()->StartDiscoverPrinter(extensionIds);

    for (auto &printExtensionInfo: printExtensionInfos) {
        PrintServiceAbility::GetInstance()->RegisterExtCallback(printExtensionInfo.GetExtensionId(), nullptr);
    }

    std::string extensionCID = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterExtCallback(extensionCID, nullptr);
}

void TestLoadExtSuccess(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->LoadExtSuccess(extensionId);
}

void TestQueryAllActivePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {0};
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
    std::vector<uint32_t> files = {0};
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
    std::vector<uint32_t> files = {0};
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
    std::vector<uint32_t> files = {0};
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryQueuedPrintJobById(printJobId, printJob);
}

void TestAddPrinterToCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerMake = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

void TestQueryPrinterCapabilityByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintServiceAbility::GetInstance()->SetHelper(nullptr);
    PrintServiceAbility::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestOn(data, size, dataProvider);
    TestOff(data, size, dataProvider);
    TestCallback(data, size, dataProvider);
    TestLoadExtSuccess(data, size, dataProvider);
    TestQueryAllActivePrintJob(data, size, dataProvider);
    TestQueryAllPrintJob(data, size, dataProvider);
    TestQueryPrintJobById(data, size, dataProvider);
    TestQueryQueuedPrintJobById(data, size, dataProvider);
    TestAddPrinterToCups(data, size, dataProvider);
    TestQueryPrinterCapabilityByUri(data, size, dataProvider);
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
