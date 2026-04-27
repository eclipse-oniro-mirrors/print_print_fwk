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
#include "printserviceppdqueryfunction_fuzzer.h"
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

void TestQueryPrinterCapabilityByUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterCapability printerCaps;
    PrintServiceAbility::GetInstance()->SetHelper(nullptr);
    PrintServiceAbility::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

void TestUpdateBsuniPrinterAdvanceOptions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    PrinterCapability printerCaps;

    Json::Value optionJson;
    Json::Value cupsOptionJson;
    Json::Value mediaSourceSupportJson;

    mediaSourceSupportJson.append(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    cupsOptionJson["media-source-supported"] = mediaSourceSupportJson;
    cupsOptionJson["media-source-default"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    optionJson["cupsOptions"] = cupsOptionJson;

    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    PrintServiceAbility::GetInstance()->UpdateBsuniPrinterAdvanceOptions(printerInfo);
}

void TestParseSingleAdvanceOptJson(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Json::Value singleAdvanceOptJson;
    Json::Value singleOptArray;
    singleOptArray.append(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string keyword = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ParseSingleAdvanceOptJson(keyword, singleOptArray, singleAdvanceOptJson);
}

void TestGetConnectUri(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::vector<std::string> protocols = {"ipp", "ipps", "lpd", "socket"};
    PrinterInfo printerInfo;
    std::string uri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printerInfo.SetUri(uri);
    Json::Value optionJson;

    std::string optionProtocol = protocols[dataProvider->ConsumeIntegralInRange<uint32_t>(0, protocols.size() - 1)];
    optionJson[optionProtocol] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string optionStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printerInfo.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    std::string connectProtocol = protocols[dataProvider->ConsumeIntegralInRange<uint32_t>(0, protocols.size() - 1)];
    std::string result = PrintServiceAbility::GetInstance()->GetConnectUri(printerInfo, connectProtocol);
}

void TestAddPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string options = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->AddPrinter(printerName, printerUri, ppdName, options);
}

void TestPrintFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("multithreading is running at function TestPrintFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestQueryAllPrinterPpds,
        &TestQueryPrinterInfoByIp,
        &TestConnectPrinterByIpAndPpd,
        &TestQueryRecommendDriversById,
        &TestQueryPrinterCapabilityByUri,
        &TestUpdateBsuniPrinterAdvanceOptions,
        &TestParseSingleAdvanceOptJson,
        &TestGetConnectUri,
        &TestAddPrinter,
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
