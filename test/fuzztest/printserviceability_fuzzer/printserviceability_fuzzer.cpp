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

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t U32_AT_SIZE = 4;
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"printer1\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\","
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"]}";

void TestStartService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->StartService();
}

void TestStartPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string fileUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    fileList.push_back(fileUri);
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::vector<uint32_t> fdList;
    fdList.push_back(fd);
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId);
}

void TestStopPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->StopPrint(taskId);
}

void TestConnectPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ConnectPrinter(printerId);
}

void TestDisconnectPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DisconnectPrinter(printerId);
}

void TestStartDiscoverPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> extensionIds;
    extensionIds.push_back(extensionId);
    PrintServiceAbility::GetInstance()->StartDiscoverPrinter(extensionIds);
}

void TestStopDiscoverPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->StopDiscoverPrinter();
}

void TestQueryAllExtension(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintExtensionInfo> printExtensionInfos;
    printExtensionInfos.push_back(printExtensionInfo);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->QueryAllExtension(printExtensionInfos);
}

void TestStartPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintJob testJob;
    testJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetOption(JOB_OPTIONS);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->StartPrintJob(testJob);
}

void TestCancelPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CancelPrintJob(jobId);
}

void TestAddPrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->AddPrinters(printerInfos);
}

void TestRemovePrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerIds;
    printerIds.push_back(printerId);
    PrintServiceAbility::GetInstance()->RemovePrinters(printerIds);
}

void TestUpdatePrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->UpdatePrinters(printerInfos);
    return;
}

void TestUpdatePrinterState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrinterState(printerId, state);
}

void TestUpdatePrintJobStateOnlyForSystemApp(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
}

void TestUpdateExtensionInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->UpdateExtensionInfo(extInfo);
}

void TestRequestPreview(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
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
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->RequestPreview(printJob, previewResult);
    return;
}

void TestQueryPrinterCapability(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryPrinterCapability(printerId);
}

void TestOn(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->On(taskId, type, nullptr);
}

void TestOff(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->Off(taskId, type);
}

void TestRegisterPrinterCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterPrinterCallback(type, nullptr);
}

void TestUnregisterPrinterCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->UnregisterPrinterCallback(type);
}

void TestRegisterExtCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionCID = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterExtCallback(extensionCID, nullptr);
}

void TestUnregisterAllExtCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionCID = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->UnregisterAllExtCallback(extensionCID);
}

void TestLoadExtSuccess(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->LoadExtSuccess(extensionId);
}

void TestQueryAllPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
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
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->QueryAllPrintJob(printJobs);
}

void TestQueryPrintJobById(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {0};
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->QueryPrintJobById(printJobId, printJob);
}

void TestAddPrinterToCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerMake = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

void TestQueryPrinterCapabilityByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintServiceAbility::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

void TestSetHelper(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->SetHelper(nullptr);
}

void TestPrintByAdapter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    std::string jobName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintAttributes printAttributes;
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->PrintByAdapter(jobName, printAttributes, taskId);
}

void TestStartGetPrintFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintAttributes printAttributes;
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->StartGetPrintFile(jobId, printAttributes, fd);
}

void TestQueryPrinterInfoByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->QueryPrinterInfoByPrinterId(printerId, printerInfo);
}

void TestNotifyPrintService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyPrintService(jobId, type);
}

void TestQueryAddedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerNameList;
    printerNameList.push_back(printerName);
    PrintServiceAbility::GetInstance()->QueryAddedPrinter(printerNameList);
}

void TestQueryPrinterProperties(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> keyList;
    keyList.push_back(key);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> valueList;
    valueList.push_back(value);
    PrintServiceAbility::GetInstance()->QueryPrinterProperties(printerId, keyList, valueList);
}

void TestUpdatePrintJobState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrintJobState(jobId, state, subState);
}

void TestGetPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->GetPrinterPreference(printerId, printerPreference);
}

void TestSetPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetPrinterPreference(printerId, printerPreference);
}

void TestSetDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetDefaultPrinter(printerId);
}

void TestDeletePrinterFromCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerMake = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DeletePrinterFromCups(printerId, printerName, printerMake);
}

void TestDestroyExtension(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->DestroyExtension();
}

void TestStartNativePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintJob printJob;
    PrintServiceAbility::GetInstance()->StartNativePrintJob(printJob);
}

void TestNotifyPrintServiceEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t event = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->NotifyPrintServiceEvent(jobId, event);
}

void TestSomePublicFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestQueryAllPrintJob(data, size, dataProvider);
    TestQueryPrintJobById(data, size, dataProvider);
    TestAddPrinterToCups(data, size, dataProvider);
    TestQueryPrinterCapabilityByUri(data, size, dataProvider);
    TestSetHelper(data, size, dataProvider);
    TestPrintByAdapter(data, size, dataProvider);
    TestStartGetPrintFile(data, size, dataProvider);
    TestNotifyPrintService(data, size, dataProvider);
    TestQueryPrinterInfoByPrinterId(data, size, dataProvider);
    TestQueryAddedPrinter(data, size, dataProvider);
    TestQueryPrinterProperties(data, size, dataProvider);
    TestUpdatePrintJobState(data, size, dataProvider);
    TestGetPrinterPreference(data, size, dataProvider);
    TestSetPrinterPreference(data, size, dataProvider);
    TestSetDefaultPrinter(data, size, dataProvider);
    TestDeletePrinterFromCups(data, size, dataProvider);
    TestDestroyExtension(data, size, dataProvider);
    TestStartNativePrintJob(data, size, dataProvider);
    TestNotifyPrintServiceEvent(data, size, dataProvider);
}

// below are private test
void TestUpdateQueuedJobList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(printJobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->UpdateQueuedJobList(printJobId, printJob);
}

void TestUpdatePrintJobOptionByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbilityMockPermission::MockPermission();
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {0};
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->UpdatePrintJobOptionByPrinterId(printJob);
}

void TestDelayStartDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DelayStartDiscovery(extensionId);
}

void TestBuildFDParam(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::vector<uint32_t> fdList;
    fdList.push_back(fd);
    AAFwk::Want want;
    PrintServiceAbility::GetInstance()->BuildFDParam(fdList, want);
}

void TestAdapterGetFileCallBack(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->AdapterGetFileCallBack(jobId, state, subState);
}

void TestAddNativePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJob printJob;
    PrintServiceAbility::GetInstance()->AddNativePrintJob(jobId, printJob);
}

void TestIsQueuedJobListEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->IsQueuedJobListEmpty(jobId);
}

void TestSetPrintJobCanceled(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintJob printJob;
    PrintServiceAbility::GetInstance()->SetPrintJobCanceled(printJob);
}

void TestCancelUserPrintJobs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->CancelUserPrintJobs(userId);
}

void TestSendExtensionEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SendExtensionEvent(extensionId, extInfo);
}

void TestgetPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->getPrinterInfo(printerId);
}

void TestCallStatusBar(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->CallStatusBar();
}

void TestUpdatePrintUserMap(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->UpdatePrintUserMap();
}

void TestnotifyAdapterJobChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->notifyAdapterJobChanged(jobId, state, subState);
}

void TestRegisterAdapterListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterAdapterListener(jobId);
}

void TestisEprint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->isEprint(printerId);
}

void TestManualStart(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->ManualStart();
}

void TestGetPrintJobOrderId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->GetPrintJobOrderId();
}

void TestOnStop(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->OnStop();
}

void TestWritePreferenceToFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintServiceAbility::GetInstance()->WritePreferenceToFile();
}

void TestBuildPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string option = "{\
        \"cupsOptions\" : {\
            \"supportedPageSizeArray\" : \"String\",\
            \"orientation-requested-supported\" : \"String\",\
            \"print-quality-supported\" : \"String\"\
        }\
    }";
    PrinterCapability cap;
    cap.SetOption(option);
    PrinterPreference printPreference;
    PrintServiceAbility::GetInstance()->BuildPrinterPreference(cap, printPreference);
}

void TestBuildPrinterPreferenceByDefault(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string optJson = "{\
        \"defaultPageSizeId\" : \"String\",\
        \"orientation-requested-default\" : \"String\",\
        \"sides-default\" : \"String\",\
        \"print-quality-default\" : \"String\"\
    }";
    nlohmann::json capOpt = nlohmann::json::parse(optJson);
    PreferenceSetting printerDefaultAttr;
    PrintServiceAbility::GetInstance()->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
}

void TestBuildPrinterPreferenceByOption(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string supportedOpts = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string optAttr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> optAttrs;
    optAttrs.push_back(optAttr);
    PrintServiceAbility::GetInstance()->BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
}

void TestBuildPrinterAttrComponentByJson(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string arrObject = "{\
        \"cupsOptions\" : [\
            \"supportedPageSizeArray\", \
            \"orientation-requested-supported\", \
            \"print-quality-supported\"\
        ]\
    }";
    nlohmann::json jsonArrObject = nlohmann::json::parse(arrObject);
    std::string printerAttr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerAttrs;
    printerAttrs.push_back(printerAttr);
    PrintServiceAbility::GetInstance()->BuildPrinterAttrComponentByJson(key, jsonArrObject, printerAttrs);
}

void TestCheckIsDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsDefaultPrinter(printerId);
}

void TestCheckIsLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsLastUsedPrinter(printerName);
}

void TestSetLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetLastUsedPrinter(printerId);
}

void TestSendPrintJobEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    PrintJob jobInfo;
    uint32_t jobStateArr[] = {PRINT_JOB_COMPLETED, PRINT_JOB_BLOCKED, PRINT_JOB_COMPLETED};
    for (auto jobState : jobStateArr) {
        jobInfo.SetJobState(jobState);
        PrintServiceAbility::GetInstance()->SendPrintJobEvent(jobInfo);
    }
}

void TestReadPreferenceFromFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReadPreferenceFromFile(printerId, printPreference);
}

void TestReportCompletedPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReportCompletedPrint(printerId);
}

void TestNotifyAppJobQueueChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    std::string applyResult = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyAppJobQueueChanged(applyResult);
}

void TestConvertToPrintExtensionInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->Init();
    AppExecFwk::ExtensionAbilityInfo extInfo;
    PrintServiceAbility::GetInstance()->ConvertToPrintExtensionInfo(extInfo);
}

void TestNotPublicFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestUpdateQueuedJobList(data, size, dataProvider);
    TestUpdatePrintJobOptionByPrinterId(data, size, dataProvider);
    TestDelayStartDiscovery(data, size, dataProvider);
    TestBuildFDParam(data, size, dataProvider);
    TestAdapterGetFileCallBack(data, size, dataProvider);
    TestAddNativePrintJob(data, size, dataProvider);
    TestIsQueuedJobListEmpty(data, size, dataProvider);
    TestSetPrintJobCanceled(data, size, dataProvider);
    TestCancelUserPrintJobs(data, size, dataProvider);
    TestSendExtensionEvent(data, size, dataProvider);
    TestgetPrinterInfo(data, size, dataProvider);
    TestCallStatusBar(data, size, dataProvider);
    TestUpdatePrintUserMap(data, size, dataProvider);
    TestnotifyAdapterJobChanged(data, size, dataProvider);
    TestRegisterAdapterListener(data, size, dataProvider);
    TestisEprint(data, size, dataProvider);
    TestWritePreferenceToFile(data, size, dataProvider);
    TestBuildPrinterPreferenceByOption(data, size, dataProvider);
    TestBuildPrinterPreference(data, size, dataProvider);
    TestBuildPrinterPreferenceByDefault(data, size, dataProvider);
    TestBuildPrinterPreferenceByOption(data, size, dataProvider);
    TestBuildPrinterAttrComponentByJson(data, size, dataProvider);
    TestCheckIsDefaultPrinter(data, size, dataProvider);
    TestCheckIsLastUsedPrinter(data, size, dataProvider);
    TestSetLastUsedPrinter(data, size, dataProvider);
    TestSendPrintJobEvent(data, size, dataProvider);
    TestReadPreferenceFromFile(data, size, dataProvider);
    TestReportCompletedPrint(data, size, dataProvider);
    TestNotifyAppJobQueueChanged(data, size, dataProvider);
    TestConvertToPrintExtensionInfo(data, size, dataProvider);
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
    OHOS::Print::TestStartService(data, size, &dataProvider);
    OHOS::Print::TestStartPrint(data, size, &dataProvider);
    OHOS::Print::TestStopPrint(data, size, &dataProvider);
    OHOS::Print::TestConnectPrinter(data, size, &dataProvider);
    OHOS::Print::TestDisconnectPrinter(data, size, &dataProvider);
    OHOS::Print::TestStartDiscoverPrinter(data, size, &dataProvider);
    OHOS::Print::TestStopDiscoverPrinter(data, size, &dataProvider);
    // OHOS::Print::TestQueryAllExtension(data, size, &dataProvider);
    OHOS::Print::TestStartPrintJob(data, size, &dataProvider);
    OHOS::Print::TestCancelPrintJob(data, size, &dataProvider);
    OHOS::Print::TestAddPrinters(data, size, &dataProvider);
    OHOS::Print::TestRemovePrinters(data, size, &dataProvider);
    OHOS::Print::TestUpdatePrinters(data, size, &dataProvider);
    OHOS::Print::TestUpdatePrinterState(data, size, &dataProvider);
    OHOS::Print::TestUpdatePrintJobStateOnlyForSystemApp(data, size, &dataProvider);
    OHOS::Print::TestUpdateExtensionInfo(data, size, &dataProvider);
    OHOS::Print::TestRequestPreview(data, size, &dataProvider);
    OHOS::Print::TestQueryPrinterCapability(data, size, &dataProvider);
    OHOS::Print::TestOn(data, size, &dataProvider);
    OHOS::Print::TestOff(data, size, &dataProvider);
    OHOS::Print::TestRegisterPrinterCallback(data, size, &dataProvider);
    OHOS::Print::TestUnregisterPrinterCallback(data, size, &dataProvider);
    OHOS::Print::TestRegisterExtCallback(data, size, &dataProvider);
    OHOS::Print::TestUnregisterAllExtCallback(data, size, &dataProvider);
    OHOS::Print::TestLoadExtSuccess(data, size, &dataProvider);
    OHOS::Print::TestSomePublicFunction(data, size, &dataProvider);
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    return 0;
}