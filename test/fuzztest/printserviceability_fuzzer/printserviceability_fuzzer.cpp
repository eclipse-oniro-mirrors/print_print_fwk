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

void TestSetPrinterPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterPreferences printerPreference;
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
    AAFwk::Want want;
    want.SetElementName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
        dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->StartPluginPrintIconExtAbility(want);
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

void TestHandleExtensionConnectPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->HandleExtensionConnectPrinter(printerId);
}

void TestSendQueuePrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SendQueuePrintJob(printerId);
}

void TestUnloadSystemAbility(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->UnloadSystemAbility();
}

void TestAddPrinterToDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->AddPrinterToDiscovery(printerInfo);
}

void TestUpdatePrinterInDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->UpdatePrinterInDiscovery(printerInfo);
}

void TestRemovePrinterFromDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RemovePrinterFromDiscovery(printerId);
}

void TestUpdatePrinterInSystem(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->UpdatePrinterInSystem(printerInfo);
}

void TestDeletePrinterFromUserData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->DeletePrinterFromUserData(printerId);
}

void TestNotifyAppDeletePrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyAppDeletePrinter(printerId);
}

void TestAddVendorPrinterToDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->AddVendorPrinterToDiscovery(globalVendorName, printerInfo);
}

void TestUpdateVendorPrinterToDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->UpdateVendorPrinterToDiscovery(globalVendorName, printerInfo);
}

void TestRemoveVendorPrinterFromDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RemoveVendorPrinterFromDiscovery(globalVendorName, printerId);
}

void TestAddVendorPrinterToCupsWithPpd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdData = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->AddVendorPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
}

void TestRemoveVendorPrinterFromCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RemoveVendorPrinterFromCups(globalVendorName, printerId);
}

void TestOnVendorStatusUpdate(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterVendorStatus printerVendorStatus;
    PrintServiceAbility::GetInstance()->OnVendorStatusUpdate(globalVendorName, printerId, printerVendorStatus);
}

void TestQueryVendorPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->QueryVendorPrinterInfo(printerId, printerInfo);
}

void TestHandlePrinterStateChangeRegister(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string eventType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->HandlePrinterStateChangeRegister(eventType);
}

void TestHandlePrinterChangeRegister(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string eventType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->HandlePrinterChangeRegister(eventType);
}

void TestUpdateAddedPrinterInCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->UpdateAddedPrinterInCups(printerId, printerUri);
}

void TestRenamePrinterWhenAdded(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->RenamePrinterWhenAdded(printerInfo);
}

void TestQueryDiscoveredPrinterInfoById(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryDiscoveredPrinterInfoById(printerId);
}

void TestCheckUserIdInEventType(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckUserIdInEventType(type);
}

void TestCallSpooler(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::vector<std::string> fileList = { dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH) };
    std::vector<uint32_t> fdList = { dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER) };
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CallSpooler(fileList, fdList, taskId);
}

void TestReportPrinterIdle(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReportPrinterIdle(printerId);
}

void TestQueryPPDInformation(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string makeModel = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppd = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryPPDInformation(makeModel, ppd);
}

void TestAddIpPrinterToSystemData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->AddIpPrinterToSystemData(globalVendorName, printerInfo);
}

void TestAddIpPrinterToCupsWithPpd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string globalVendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdData = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
}

void TestStartPrintJobInternal(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->StartPrintJobInternal(printJob);
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

void TestDelayEnterLowPowerMode(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->DelayEnterLowPowerMode();
}

void TestExitLowPowerMode(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->ExitLowPowerMode();
}

void TestMoreFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestChangeDefaultPrinterForDelete(data, size, dataProvider);
    TestGetUserDataByUserId(data, size, dataProvider);
    TestDetermineUserJobStatus(data, size, dataProvider);
    TestNotifyCurrentUserChanged(data, size, dataProvider);
    TestHandleExtensionConnectPrinter(data, size, dataProvider);
    TestSendQueuePrintJob(data, size, dataProvider);
    TestUnloadSystemAbility(data, size, dataProvider);
    TestAddPrinterToDiscovery(data, size, dataProvider);
    TestUpdatePrinterInDiscovery(data, size, dataProvider);
    TestRemovePrinterFromDiscovery(data, size, dataProvider);
    TestUpdatePrinterInSystem(data, size, dataProvider);
    TestDeletePrinterFromUserData(data, size, dataProvider);
    TestNotifyAppDeletePrinter(data, size, dataProvider);
    TestAddVendorPrinterToDiscovery(data, size, dataProvider);
    TestUpdateVendorPrinterToDiscovery(data, size, dataProvider);
    TestRemoveVendorPrinterFromDiscovery(data, size, dataProvider);
    TestAddVendorPrinterToCupsWithPpd(data, size, dataProvider);
    TestRemoveVendorPrinterFromCups(data, size, dataProvider);
    TestOnVendorStatusUpdate(data, size, dataProvider);
    TestQueryVendorPrinterInfo(data, size, dataProvider);
    TestHandlePrinterStateChangeRegister(data, size, dataProvider);
    TestHandlePrinterChangeRegister(data, size, dataProvider);
    TestUpdateAddedPrinterInCups(data, size, dataProvider);
    TestRenamePrinterWhenAdded(data, size, dataProvider);
    TestQueryDiscoveredPrinterInfoById(data, size, dataProvider);
    TestCheckUserIdInEventType(data, size, dataProvider);
    TestCallSpooler(data, size, dataProvider);
    TestReportPrinterIdle(data, size, dataProvider);
    TestQueryPPDInformation(data, size, dataProvider);
    TestStartPrintJobInternal(data, size, dataProvider);
    TestDelayEnterLowPowerMode(data, size, dataProvider);
    TestExitLowPowerMode(data, size, dataProvider);
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
    TestMoreFunction(data, size, dataProvider);
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
    TestAddPrinters(data, size, dataProvider);
    TestRemovePrinters(data, size, dataProvider);
    TestUpdatePrinters(data, size, dataProvider);
    TestUpdatePrinterState(data, size, dataProvider);
    TestUpdatePrintJobStateOnlyForSystemApp(data, size, dataProvider);
    TestUpdateExtensionInfo(data, size, dataProvider);
    TestRequestPreview(data, size, dataProvider);
    TestQueryPrinterCapability(data, size, dataProvider);
    TestOn(data, size, dataProvider);
    TestOff(data, size, dataProvider);
    TestCallback(data, size, dataProvider);
    TestLoadExtSuccess(data, size, dataProvider);
    TestQueryAllActivePrintJob(data, size, dataProvider);
    TestQueryPrintJobById(data, size, dataProvider);
    TestAddPrinterToCups(data, size, dataProvider);
    TestQueryPrinterCapabilityByUri(data, size, dataProvider);
    TestPrintByAdapter(data, size, dataProvider);
    TestStartGetPrintFile(data, size, dataProvider);
    TestNotifyPrintService(data, size, dataProvider);
    TestQueryPrinterInfoByPrinterId(data, size, dataProvider);
    TestQueryAddedPrinter(data, size, dataProvider);
    TestQueryPrinterProperties(data, size, dataProvider);
    TestUpdatePrintJobState(data, size, dataProvider);
    TestSetPrinterPreference(data, size, dataProvider);
    TestSetDefaultPrinter(data, size, dataProvider);
    TestDeletePrinterFromCups(data, size, dataProvider);
    TestNotPublicFunction(data, size, dataProvider);
    TestAddIpPrinterToSystemData(data, size, dataProvider);
    TestAddIpPrinterToCupsWithPpd(data, size, dataProvider);
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
