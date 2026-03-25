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
#include "printserviceprinterupdatefunction_fuzzer.h"
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

void TestPrintFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("multithreading is running at function TestPrintFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestAddPrinterToDiscovery,
        &TestUpdatePrinterInDiscovery,
        &TestRemovePrinterFromDiscovery,
        &TestUpdatePrinterInSystem,
        &TestDeletePrinterFromUserData,
        &TestNotifyAppDeletePrinter,
        &TestAddVendorPrinterToDiscovery,
        &TestAnalyzePrintEvents,
        &TestAddPrintEvent,
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
    OHOS::Print::TestPrintFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestPrintFunction(data, size, &dataProvider);
    return 0;
}
