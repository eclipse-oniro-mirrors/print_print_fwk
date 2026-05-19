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
#include "printserviceabilityprinterppd_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "printer_capability.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr size_t U32_AT_SIZE = 4;

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

void TestQueryAllPrinterPpds(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::vector<PpdInfo> ppdInfos;
    PrintServiceAbility::GetInstance()->QueryAllPrinterPpds(ppdInfos);
}

void TestQueryPrinterInfoByIp(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerIp = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->QueryPrinterInfoByIp(printerIp);
}

void TestConnectPrinterByIpAndPpd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerIp = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string protocol = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ConnectPrinterByIpAndPpd(printerIp, protocol, ppdName);
}

void TestQueryRecommendDriversById(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<PpdInfo> ppds;
    PrintServiceAbility::GetInstance()->QueryRecommendDriversById(printerId, ppds);
}

void TestConnectPrinterByIdAndPpd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string protocol = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ConnectPrinterByIdAndPpd(printerId, protocol, ppdName);
}

void TestGetPpdNameByPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName;
    PrintServiceAbility::GetInstance()->GetPpdNameByPrinterId(printerId, ppdName);
}

void TestIsPrinterPpdUpdateRequired(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string standardPrinterName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdHashCode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->IsPrinterPpdUpdateRequired(standardPrinterName, ppdHashCode);
}

void TestGetConnectUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo info;
    std::string uri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string protocol = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    info.SetUri(uri);
    info.SetOption(option);
    PrintServiceAbility::GetInstance()->GetConnectUri(info, protocol);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("Multithreading is running at function TestAllFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestAddPrinterToCups,
        &TestQueryPrinterCapabilityByUri,
        &TestQueryAllPrinterPpds,
        &TestQueryPrinterInfoByIp,
        &TestConnectPrinterByIpAndPpd,
        &TestQueryRecommendDriversById,
        &TestConnectPrinterByIdAndPpd,
        &TestGetPpdNameByPrinterId,
        &TestIsPrinterPpdUpdateRequired,
        &TestGetConnectUri,
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
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
