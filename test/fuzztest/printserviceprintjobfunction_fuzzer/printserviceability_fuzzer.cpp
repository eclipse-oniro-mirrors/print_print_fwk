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

void TestStartPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->OnStart();
    PrintServiceAbility::GetInstance()->ManualStart();
    auto printer = std::make_shared<PrinterInfo>();
    PrintServiceAbility::GetInstance()->printSystemData_.addedPrinterMap_.Insert(DEFAULT_PRINTERID, printer);
    PrintServiceAbility::GetInstance()->StartService();
    std::string fileUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    fileList.push_back(fileUri);
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::vector<uint32_t> fdList;
    fdList.push_back(fd);
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId);
    PrintServiceAbility::GetInstance()->OnStop();
}

void TestStopPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->StopPrint(taskId);
}

void TestConnectPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = size ? dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH) : DEFAULT_PRINTERID;
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    std::vector <PrinterInfo> printerInfos;
    printerInfos.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->AddPrinters(printerInfos);
    PrintServiceAbility::GetInstance()->ConnectPrinter(printerId);
    PrintServiceAbility::GetInstance()->DisconnectPrinter(printerId);
}

void TestDisconnectPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DisconnectPrinter(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    // anyway add printer to discovery list.
    PrintServiceAbility::GetInstance()->
        printSystemData_.discoveredPrinterInfoList_[printerInfo->GetPrinterId()] = printerInfo;
    PrintServiceAbility::GetInstance()->DisconnectPrinter(printerId);
}

void TestStartDiscoverPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::vector <PrintExtensionInfo> printExtensionInfos;
    PrintServiceAbility::GetInstance()->QueryAllExtension(printExtensionInfos);
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector <std::string> extensionIds;
    extensionIds.push_back(extensionId);
    for (auto &printExtensionInfo: printExtensionInfos) {
        extensionIds.push_back(printExtensionInfo.GetExtensionId());
    }
    PrintServiceAbility::GetInstance()->StartDiscoverPrinter(extensionIds);
    PrintServiceAbility::GetInstance()->StopDiscoverPrinter();
}

void TestQueryAllExtension(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintExtensionInfo> printExtensionInfos;
    printExtensionInfos.push_back(printExtensionInfo);
    PrintServiceAbility::GetInstance()->QueryAllExtension(printExtensionInfos);
}

void TestStartPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(DEFAULT_PRINTERID);
    printerInfo.SetPrinterName(DEFAULT_PRINTERID);
    std::vector <PrinterInfo> printerInfos;
    PrinterCapability printerCaps;
    printerCaps.SetColorMode(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    printerInfos.push_back(printerInfo);

    PrintServiceAbility::GetInstance()->AddPrinters(printerInfos);
    PrintServiceAbility::GetInstance()->UpdatePrinters(printerInfos);

    PrintJob testJob;
    testJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector <uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetOption(JOB_OPTIONS);
    PrintServiceAbility::GetInstance()->StartPrintJob(testJob);
    PrintServiceAbility::GetInstance()->GetCallerUserName();
}

void TestCancelPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CancelPrintJob(jobId);
}

void TestRestartPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RestartPrintJob(jobId);
}

void TestFlushCacheFileToUserData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->FlushCacheFileToUserData(jobId);
    PrintServiceAbility::GetInstance()->DeleteCacheFileFromUserData(jobId);
    std::vector<uint32_t> fdList = {};
    PrintServiceAbility::GetInstance()->OpenCacheFileFd(jobId, fdList);
    for (uint32_t fd : fdList) {
        if (static_cast<int32_t>(fd) > 0) {
            close(fd);
        }
    }
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestStartPrint(data, size, dataProvider);
    TestStopPrint(data, size, dataProvider);
    TestConnectPrinter(data, size, dataProvider);
    TestDisconnectPrinter(data, size, dataProvider);
    TestStartDiscoverPrinter(data, size, dataProvider);
    TestQueryAllExtension(data, size, dataProvider);
    TestStartPrintJob(data, size, dataProvider);
    TestCancelPrintJob(data, size, dataProvider);
    TestRestartPrintJob(data, size, dataProvider);
    TestFlushCacheFileToUserData(data, size, dataProvider);
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
