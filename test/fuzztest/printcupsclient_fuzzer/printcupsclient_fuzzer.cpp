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
#include "printcupsclient_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "printer_capability.h"
#include "print_log.h"
#include "print_cups_client.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr int POLICY_ENUM_MAX = 3;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestQueryPPDInformation(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string makeModel = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppd = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->QueryPPDInformation(makeModel, ppd);
    PrintCupsClient::GetInstance()->StopCupsdService();
}

void TestAddPrinterToCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerMake = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    PrintCupsClient::GetInstance()->JobSentCallback();
}

void TestQueryPrinterAttributesByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nic = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int num = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::string pattrs = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    char **pattrsArray = new char *[1];
    pattrsArray[0] = new char[pattrs.length() + 1];
    if (strcpy_s(pattrsArray[0], MAX_SET_NUMBER, pattrs.c_str()) != EOK) {
        delete[] pattrsArray[0];
        delete[] pattrsArray;
        return;
    }
    PrintCupsClient::GetInstance()->QueryPrinterAttributesByUri(printerUri, nic, num, pattrsArray);
    delete[] pattrsArray[0];
    delete[] pattrsArray;
}

void TestQueryPrinterCapabilityByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintCupsClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerName, printerCaps);
}

void TestQueryPrinterStatusByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
    PrintCupsClient::GetInstance()->QueryPrinterStatusByUri(printerUri, status);
}

void TestDeleteCupsPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerNameStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->DeleteCupsPrinter(printerNameStr.c_str());
}

void TestAddCupsPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    PrintJob jobInfo;
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    jobInfo.SetOption(option);
    std::string userName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->AddCupsPrintJob(jobInfo, userName);
}

void TestCancelCupsJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->CancelCupsJob(serviceJobId);
}

void TestQueryAddedPrinterList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerNameStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerName;
    printerName.push_back(printerNameStr);
    PrintCupsClient::GetInstance()->QueryAddedPrinterList(printerName);
}

void TestSetDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->SetDefaultPrinter(printerName);
}

void TestQueryPrinterAttrList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> keyList;
    keyList.push_back(key);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> valueList;
    valueList.push_back(value);
    PrintCupsClient::GetInstance()->QueryPrinterAttrList(printerName, keyList, valueList);
}

void TestQueryPrinterInfoByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo info;
    PrintCupsClient::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
}

void TestCheckPrinterMakeModel(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    JobParameters jobParams;
    jobParams.printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    bool driverMissing = false;
    PrintCupsClient::GetInstance()->CheckPrinterMakeModel(&jobParams, driverMissing);
}

void TestDeletePrinterFromCups(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintCupsClient::GetInstance()->InitCupsResources();
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->DeleteCupsPrinter(printerName.c_str());
}

void TestCheckPrinterOnline(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->CheckPrinterOnline(monitorParams);
}

void TestGetIpAddress(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    unsigned int number = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->GetIpAddress(number);
}

void TestIsIpConflict(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nic = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->IsIpConflict(printerId, nic);
}

void TestConvertInchTo100MM(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int num = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->ConvertInchTo100MM(num);
}

void TestGetColorString(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t colorCode = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->GetColorString(colorCode);
}

void TestGetDulpexString(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t duplexCode = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->GetDulpexString(duplexCode);
}

void TestGetMedieSize(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintCupsClient::GetInstance()->GetMedieSize(printJob);
}

void TestDumpJobParameters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    JobParameters jobParams;
    jobParams.serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->DumpJobParameters(&jobParams);
}

void TestBuildJobParameters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string userName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->BuildJobParameters(printJob, userName);
}

void TestCheckPrinterDriverExist(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string makeModel = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->CheckPrinterDriverExist(makeModel);
}

void TestStartMonitor(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintCupsClient::GetInstance()->StartMonitor();
}

void TestJobStatusCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    PrintCupsClient::GetInstance()->JobStatusCallback(monitorParams);
}

void TestIfContinueToHandleJobState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    PrintCupsClient::GetInstance()->IfContinueToHandleJobState(monitorParams);
}

void TestQueryJobState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    PrintCupsClient::GetInstance()->QueryJobState(monitorParams->http, monitorParams);
}

void TestBuildMonitorPolicy(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    PrintCupsClient::GetInstance()->BuildMonitorPolicy(monitorParams);
}

void TestParseStateReasons(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    PrintCupsClient::GetInstance()->ParseStateReasons(monitorParams);
}

void TestGetBlockedAndUpdateSubstate(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto monitorParams = std::make_shared<JobMonitorParam>();
    monitorParams->serviceAbility = PrintServiceAbility::GetInstance();
    monitorParams->serviceJobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->cupsJobId = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    monitorParams->printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    monitorParams->printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string job_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_state_reasons.copy(monitorParams->job_state_reasons, job_state_reasons.length() + 1);
    std::string job_printer_state_reasons = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    job_printer_state_reasons.copy(monitorParams->job_printer_state_reasons, job_printer_state_reasons.length() + 1);
    StatePolicy policy = (StatePolicy)dataProvider->ConsumeIntegralInRange<unsigned int>(0, POLICY_ENUM_MAX);
    std::string substateString = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJobSubState jobSubstate = (PrintJobSubState)dataProvider->
        ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->GetBlockedAndUpdateSubstate(monitorParams, policy, substateString, jobSubstate);
}

void TestGetNewSubstate(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t substate = dataProvider->ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    PrintJobSubState singleSubstate = (PrintJobSubState)dataProvider->
        ConsumeIntegralInRange<unsigned int>(0, MAX_SET_NUMBER);
    PrintCupsClient::GetInstance()->GetNewSubstate(substate, singleSubstate);
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

    if (size < OHOS::Print::U32_AT_SIZE || size > OHOS::Print::FOO_MAX_LEN) {
    }

    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Print::TestQueryPPDInformation,
        &OHOS::Print::TestAddPrinterToCups,
        &OHOS::Print::TestQueryPrinterAttributesByUri,
        &OHOS::Print::TestQueryPrinterCapabilityByUri,
        &OHOS::Print::TestQueryPrinterStatusByUri,
        &OHOS::Print::TestDeleteCupsPrinter,
        &OHOS::Print::TestAddCupsPrintJob,
        &OHOS::Print::TestCancelCupsJob,
        &OHOS::Print::TestQueryAddedPrinterList,
        &OHOS::Print::TestSetDefaultPrinter,
        &OHOS::Print::TestQueryPrinterAttrList,
        &OHOS::Print::TestQueryPrinterInfoByPrinterId,
        &OHOS::Print::TestCheckPrinterMakeModel,
        &OHOS::Print::TestDeletePrinterFromCups,
        &OHOS::Print::TestCheckPrinterOnline,
        &OHOS::Print::TestGetIpAddress,
        &OHOS::Print::TestIsIpConflict,
        &OHOS::Print::TestConvertInchTo100MM,
        &OHOS::Print::TestGetColorString,
        &OHOS::Print::TestGetDulpexString,
        &OHOS::Print::TestGetMedieSize,
        &OHOS::Print::TestDumpJobParameters,
        &OHOS::Print::TestBuildJobParameters,
        &OHOS::Print::TestCheckPrinterDriverExist,
        &OHOS::Print::TestStartMonitor,
        &OHOS::Print::TestJobStatusCallback,
        &OHOS::Print::TestIfContinueToHandleJobState,
        &OHOS::Print::TestQueryJobState,
        &OHOS::Print::TestBuildMonitorPolicy,
        &OHOS::Print::TestParseStateReasons,
        &OHOS::Print::TestGetBlockedAndUpdateSubstate,
        &OHOS::Print::TestGetNewSubstate
    };
    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
