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
    PrintServiceAbilityMockPermission::MockPermission();
    PrintServiceAbility::GetInstance()->OnStart();
    PrintServiceAbility::GetInstance()->ManualStart();
    auto cupsPrinter = std::make_shared<CupsPrinterInfo>();
    PrintServiceAbility::GetInstance()->printSystemData_.addedPrinterMap_.Insert(DEFAULT_PRINTERID, cupsPrinter);
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
}

void TestCancelPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CancelPrintJob(jobId);
}

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
        PrintServiceAbility::GetInstance()->UnregisterAllExtCallback(printExtensionInfo.GetExtensionId());
    }

    std::string extensionCID = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterExtCallback(extensionCID, nullptr);
    PrintServiceAbility::GetInstance()->UnregisterAllExtCallback(extensionCID);
}

void TestLoadExtSuccess(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->LoadExtSuccess(extensionId);
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

void TestPrintByAdapter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintAttributes printAttributes;
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->PrintByAdapter(jobName, printAttributes, taskId);
}

void TestStartGetPrintFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintAttributes printAttributes;
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->StartGetPrintFile(jobId, printAttributes, fd);
}

void TestQueryPrinterInfoByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(JOB_OPTIONS);
    PrintServiceAbility::GetInstance()->QueryPrinterInfoByPrinterId(printerId, printerInfo);
}

void TestNotifyPrintService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyPrintService(jobId, type);
}

void TestQueryAddedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerNameList;
    printerNameList.push_back(printerName);
    PrintServiceAbility::GetInstance()->QueryAddedPrinter(printerNameList);
}

void TestQueryPrinterProperties(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
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
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->UpdatePrintJobState(jobId, state, subState);
}

void TestGetPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->GetPrinterPreference(printerId, printerPreference);
}

void TestSetPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetPrinterPreference(printerId, printerPreference);
}

void TestSetDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t type = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->SetDefaultPrinter(printerId, type);
}

void TestDeletePrinterFromCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DeletePrinterFromCups(printerName);
}

void TestDiscoverUsbPrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    std::vector<PrinterInfo> printers;
    printers.push_back(printerInfo);
    PrintServiceAbility::GetInstance()->DiscoverUsbPrinters(printers);
}

void TestStartNativePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob testJob;
    testJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    testJob.SetOption(JOB_OPTIONS);
    PrintServiceAbility::GetInstance()->StartNativePrintJob(testJob);
}

void TestNotifyPrintServiceEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t event = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->NotifyPrintServiceEvent(jobId, event);
}

// below are private test
void TestUpdateQueuedJobList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(printJobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->UpdateQueuedJobList(printJobId, printJob);
}

void TestUpdatePrintJobOptionByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<uint32_t> files = {0};
    printJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPageSize(pageSize);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->UpdatePrintJobOptionByPrinterId(printJob);
}

void TestDelayStartDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DelayStartDiscovery(extensionId);
}

void TestAdapterGetFileCallBack(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->AdapterGetFileCallBack(jobId, state, subState);
}

void TestAddNativePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJob printJob;
    PrintServiceAbility::GetInstance()->AddNativePrintJob(jobId, printJob);
}

void TestIsQueuedJobListEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->IsQueuedJobListEmpty(jobId);
}

void TestSetPrintJobCanceled(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    std::string printerid = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printJob.SetPrinterId(printerid);
    PrintServiceAbility::GetInstance()->SetPrintJobCanceled(printJob);
}

void TestCancelUserPrintJobs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->CancelUserPrintJobs(userId);
    PrintServiceAbility::GetInstance()->CallStatusBar();
}

void TestSendExtensionEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SendExtensionEvent(extensionId, extInfo);
    PrintServiceAbility::GetInstance()->UpdatePrintUserMap();
}

void TestNotifyAdapterJobChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->notifyAdapterJobChanged(jobId, state, subState);
}

void TestRegisterAdapterListener(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterAdapterListener(jobId);
}

void TestisEprint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->isEprint(printerId);
    PrintServiceAbility::GetInstance()->GetPrintJobOrderId();
    PrintServiceAbility::GetInstance()->WritePreferenceToFile();
}

void TestBuildPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string option = "{\
        \"cupsOptions\" : {\
            \"orientation-requested-supported\" : \"String\",\
            \"print-quality-supported\" : \"String\"\
        }\
    }";
    PrinterCapability cap;
    cap.SetOption(option);
    PrinterPreference printPreference;
    PrintServiceAbility::GetInstance()->BuildPrinterPreference(cap, printPreference);
    std::string optionRandom = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    cap.SetOption(optionRandom);
    PrintServiceAbility::GetInstance()->BuildPrinterPreference(cap, printPreference);
}

void TestBuildPrinterPreferenceByDefault(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string optJson = "{\
        \"defaultPageSizeId\" : \"String\",\
        \"orientation-requested-default\" : \"String\",\
        \"sides-default\" : \"String\",\
        \"print-quality-default\" : \"String\"\
    }";
    nlohmann::json capOpt = nlohmann::json::parse(optJson);
    PreferenceSetting printerDefaultAttr;
    PrintServiceAbility::GetInstance()->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
    printerDefaultAttr.pagesizeId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
}

void TestBuildPrinterPreferenceByOption(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string supportedOpts = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string optAttr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> optAttrs;
    optAttrs.push_back(optAttr);
    PrintServiceAbility::GetInstance()->BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
}

void TestBuildPrinterAttrComponentByJson(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string arrObject = "{\
        \"cupsOptions\" : [\
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

void TestReportHisysEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->ReportHisysEvent(printJob, printerId, subState);
}

void TestNotifyAppJobQueueChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string applyResult = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyAppJobQueueChanged(applyResult);
}

void TestSendPrinterChangeEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int event = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
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
    uint32_t subState = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetListeningState(subState);
}

void TestChangeDefaultPrinterForDelete(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto userData = std::make_shared<PrintUserData>();
    PrintServiceAbility::GetInstance()->ChangeDefaultPrinterForDelete(userData, printerId);
}

void TestGetUserDataByUserId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetUserDataByUserId(userId);
}

void TestDetermineUserJobStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::map<std::string, std::shared_ptr<PrintJob>> jobList;
    jobList[jobId] = printJob;
    PrintServiceAbility::GetInstance()->DetermineUserJobStatus(jobList);
}

void TestNotifyCurrentUserChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->NotifyCurrentUserChanged(userId);
}

void TestWriteEprinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintPageSize> pageSizeList;
    pageSizeList.push_back(pageSize);
    printerCaps.SetSupportedPageSize(pageSizeList);
    PrintServiceAbility::GetInstance()->WriteEprinterPreference(printerId, printerCaps);
}

void TestWritePrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintPageSize pageSize;
    pageSize.SetId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::vector<PrintPageSize> pageSizeList;
    pageSizeList.push_back(pageSize);
    printerCaps.SetSupportedPageSize(pageSizeList);
    printerCaps.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->WritePrinterPreference(printerId, printerCaps);
}

void TestReadPreferenceFromFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printPreference = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReadPreferenceFromFile(printerId, printPreference);
}

void TestMoreFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestChangeDefaultPrinterForDelete(data, size, dataProvider);
    TestGetUserDataByUserId(data, size, dataProvider);
    TestDetermineUserJobStatus(data, size, dataProvider);
    TestNotifyCurrentUserChanged(data, size, dataProvider);
    TestWriteEprinterPreference(data, size, dataProvider);
    TestWritePrinterPreference(data, size, dataProvider);
    TestReadPreferenceFromFile(data, size, dataProvider);
}

void TestNotPublicFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestDiscoverUsbPrinters(data, size, dataProvider);
    TestStartNativePrintJob(data, size, dataProvider);
    TestNotifyPrintServiceEvent(data, size, dataProvider);
    TestUpdateQueuedJobList(data, size, dataProvider);
    TestUpdatePrintJobOptionByPrinterId(data, size, dataProvider);
    TestDelayStartDiscovery(data, size, dataProvider);
    TestAdapterGetFileCallBack(data, size, dataProvider);
    TestAddNativePrintJob(data, size, dataProvider);
    TestIsQueuedJobListEmpty(data, size, dataProvider);
    TestSetPrintJobCanceled(data, size, dataProvider);
    TestCancelUserPrintJobs(data, size, dataProvider);
    TestSendExtensionEvent(data, size, dataProvider);
    TestNotifyAdapterJobChanged(data, size, dataProvider);
    TestRegisterAdapterListener(data, size, dataProvider);
    TestisEprint(data, size, dataProvider);
    TestBuildPrinterPreferenceByOption(data, size, dataProvider);
    TestBuildPrinterPreference(data, size, dataProvider);
    TestBuildPrinterPreferenceByDefault(data, size, dataProvider);
    TestBuildPrinterPreferenceByOption(data, size, dataProvider);
    TestBuildPrinterAttrComponentByJson(data, size, dataProvider);
    TestCheckIsDefaultPrinter(data, size, dataProvider);
    TestCheckIsLastUsedPrinter(data, size, dataProvider);
    TestSetLastUsedPrinter(data, size, dataProvider);
    TestSendPrintJobEvent(data, size, dataProvider);
    TestStartPrintJobCB(data, size, dataProvider);
    TestCheckPrinterUriDifferent(data, size, dataProvider);
    TestUpdatePrinterCapability(data, size, dataProvider);
    TestReportCompletedPrint(data, size, dataProvider);
    TestReportHisysEvent(data, size, dataProvider);
    TestNotifyAppJobQueueChanged(data, size, dataProvider);
    TestSendPrinterChangeEvent(data, size, dataProvider);
    TestCheckJobQueueBlocked(data, size, dataProvider);
    TestGetListeningState(data, size, dataProvider);
    TestMoreFunction(data, size, dataProvider);
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
    OHOS::Print::TestStartPrint(data, size, &dataProvider);
    OHOS::Print::TestStopPrint(data, size, &dataProvider);
    OHOS::Print::TestConnectPrinter(data, size, &dataProvider);
    OHOS::Print::TestDisconnectPrinter(data, size, &dataProvider);
    OHOS::Print::TestStartDiscoverPrinter(data, size, &dataProvider);
    OHOS::Print::TestQueryAllExtension(data, size, &dataProvider);
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
    OHOS::Print::TestCallback(data, size, &dataProvider);
    OHOS::Print::TestLoadExtSuccess(data, size, &dataProvider);
    OHOS::Print::TestQueryAllPrintJob(data, size, &dataProvider);
    OHOS::Print::TestQueryPrintJobById(data, size, &dataProvider);
    OHOS::Print::TestAddPrinterToCups(data, size, &dataProvider);
    OHOS::Print::TestQueryPrinterCapabilityByUri(data, size, &dataProvider);
    OHOS::Print::TestPrintByAdapter(data, size, &dataProvider);
    OHOS::Print::TestStartGetPrintFile(data, size, &dataProvider);
    OHOS::Print::TestNotifyPrintService(data, size, &dataProvider);
    OHOS::Print::TestQueryPrinterInfoByPrinterId(data, size, &dataProvider);
    OHOS::Print::TestQueryAddedPrinter(data, size, &dataProvider);
    OHOS::Print::TestQueryPrinterProperties(data, size, &dataProvider);
    OHOS::Print::TestUpdatePrintJobState(data, size, &dataProvider);
    OHOS::Print::TestGetPrinterPreference(data, size, &dataProvider);
    OHOS::Print::TestSetPrinterPreference(data, size, &dataProvider);
    OHOS::Print::TestSetDefaultPrinter(data, size, &dataProvider);
    OHOS::Print::TestDeletePrinterFromCups(data, size, &dataProvider);
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    return 0;
}
