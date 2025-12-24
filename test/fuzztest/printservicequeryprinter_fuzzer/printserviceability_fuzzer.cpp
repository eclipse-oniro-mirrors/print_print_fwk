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

void TestQueryRawAddedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> printerNameList;
    printerNameList.push_back(printerName);

    PrintServiceAbility::GetInstance()->QueryRawAddedPrinter(printerNameList);
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

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
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
    TestQueryRawAddedPrinter(data, size, dataProvider);
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
