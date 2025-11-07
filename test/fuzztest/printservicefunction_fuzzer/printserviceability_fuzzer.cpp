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

void TestAuthPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string userName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    const char* userPasswd = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH).c_str();
    std::vector<char> userPasswdCstr(userPasswd, userPasswd + strlen(userPasswd) + 1);
    PrintServiceAbility::GetInstance()->AuthPrintJob(jobId, userName, userPasswdCstr.data());
}

void TestAnalyzePrintEvents(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string detail;
    PrintServiceAbility::GetInstance()->AnalyzePrintEvents(printerId, type, detail);
}

void TestAddPrintEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t code = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->AddPrintEvent(printerId, type, code);
}

void TestSavePdfFileJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->SavePdfFileJob(jobId, fd);
}

void TestPrintFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestChangeDefaultPrinterForDelete(data, size, dataProvider);
    TestGetUserDataByUserId(data, size, dataProvider);
    TestDetermineUserJobStatus(data, size, dataProvider);
    TestNotifyCurrentUserChanged(data, size, dataProvider);
    TestHandleExtensionConnectPrinter(data, size, dataProvider);
    TestSendQueuePrintJob(data, size, dataProvider);
    TestAddPrinterToDiscovery(data, size, dataProvider);
    TestUpdatePrinterInDiscovery(data, size, dataProvider);
    TestRemovePrinterFromDiscovery(data, size, dataProvider);
    TestUpdatePrinterInSystem(data, size, dataProvider);
    TestDeletePrinterFromUserData(data, size, dataProvider);
    TestNotifyAppDeletePrinter(data, size, dataProvider);
    TestAddVendorPrinterToDiscovery(data, size, dataProvider);
    TestAuthPrintJob(data, size, dataProvider);
    TestAnalyzePrintEvents(data, size, dataProvider);
    TestAddPrintEvent(data, size, dataProvider);
    TestSavePdfFileJob(data, size, dataProvider);
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
    OHOS::Print::TestPrintFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestPrintFunction(data, size, &dataProvider);
    return 0;
}
