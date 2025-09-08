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

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
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
