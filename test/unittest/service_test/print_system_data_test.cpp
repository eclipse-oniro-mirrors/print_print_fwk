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

#include <gtest/gtest.h>
#include <string>
#include <fstream>
#include <map>
#include "printer_info.h"
#define private public
#include "print_system_data.h"
#undef private
#include "print_log.h"
#include "print_constant.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintSystemDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintSystemDataTest::SetUpTestCase(void) {}

void PrintSystemDataTest::TearDownTestCase(void) {}

void PrintSystemDataTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintSystemDataTest_%{public}d", ++testNo);
}

void PrintSystemDataTest::TearDown(void) {}

/**
 * @tc.name: PrintSystemDataTest_0001
 * @tc.desc: Verify the PrintSystemData function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0001, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    const std::string PRINTER_LIST_FILE = "/data/service/el2/public/print_service/printer_list.json";
    std::ifstream f(PRINTER_LIST_FILE.c_str());
    EXPECT_EQ(systemData->Init(), f.good());
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0002, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
    cupsPrinterInfo.name = "HUAWEI_PixLab_V1-0105";
    cupsPrinterInfo.uri = "ipp://192.168.186.1:631/ipp/print";
    cupsPrinterInfo.maker = "HUAWEI PixLab V1";
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
    std::map<std::string, std::shared_ptr<CupsPrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    EXPECT_EQ(addedPrinterMap.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0004, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerName = "Direct Pixlab1620";
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0005, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerName = "Direct Pixlab1620";
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "");
    std::string re = systemData->QueryPrinterIdByStandardizeName(printerName);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct Pixlab1620";
    std::map<std::string, std::shared_ptr<CupsPrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    EXPECT_EQ(addedPrinterMap.size(), 1);
    if (cupsPrinterInfo.name == printerName) {
        re = printerId;
    }
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0006, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo1;
    cupsPrinterInfo1.name = "Direct Pixlab1620";
    CupsPrinterInfo cupsPrinterInfo2;
    EXPECT_EQ(systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2), false);
    std::map<std::string, std::shared_ptr<CupsPrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo1);
    EXPECT_EQ(addedPrinterMap.size(), 1);
    if (addedPrinterMap.count(printerId)) {
        cupsPrinterInfo2 = cupsPrinterInfo1;
        EXPECT_EQ(cupsPrinterInfo2.name, cupsPrinterInfo1.name);
    }
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0007, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertPrinterInfo(printerId, printerInfo);
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterInfoList;
    addedPrinterInfoList[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    EXPECT_EQ(addedPrinterInfoList.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0008, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    EXPECT_EQ(systemData->QueryPrinterInfoByPrinterId(printerId), nullptr);
    std::shared_ptr<PrinterInfo> result = std::make_shared<PrinterInfo>();
    systemData->QueryPrinterInfoByPrinterId(printerId);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("123");
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterInfoList;
    addedPrinterInfoList[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    EXPECT_EQ(addedPrinterInfoList.size(), 1);
    if (addedPrinterInfoList.count(printerId)) {
        result = addedPrinterInfoList[printerId];
        EXPECT_EQ(result->GetPrinterName(), "123");
    }
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0009, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerJson["id"] = "com.ohos.spooler:mdns://9e9561ad-0e30-1000-8000-9c9561ad0e30";
    printerJson["maker"] = "HUAWEI PixLab V1";
    printerJson["name"] = "HUAWEI_PixLab_V1-0105";
    printerJson["uri"] = "ipp://192.168.186.1:631/ipp/print";
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0010, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    printerMapJson["printer"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
    printerMapJson["printer_list"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0011, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->SavePrinterFile("1");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0012, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    std::string printerName = "Direct";
    systemData->QueryPrinterIdByStandardizeName(printerName);
    systemData->SavePrinterFile("1");
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("2", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->QueryPrinterIdByStandardizeName(printerName);
    cupsPrinterInfo.name = "223";
    systemData->addedPrinterMap_.Insert("4", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->QueryPrinterIdByStandardizeName(printerName);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0013, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo2;
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
    systemData->SavePrinterFile("1");
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct Pixlab1620";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("123", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    CupsPrinterInfo cupsPrinterInfo3;
    systemData->addedPrinterMap_.Insert("11", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo3));
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0014, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertPrinterInfo(printerId, printerInfo);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->InsertPrinterInfo(printerId, printerInfo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0015, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->addedPrinterInfoList_["1"] = nullptr;
    systemData->QueryPrinterInfoByPrinterId(printerId);
    systemData->addedPrinterInfoList_["1234"] = std::make_shared<PrinterInfo>(printerInfo);
    systemData->QueryPrinterInfoByPrinterId(printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0016, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
    systemData->addedPrinterMap_.Insert("1234", nullptr);
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0017, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerJson["id"] = 123;
    printerJson["maker"] = 123;
    printerJson["name"] = 132;
    printerJson["uri"] = 123;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0018, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);

    Json::Value printerJson2;
    printerJson2["id"] = "123";
    printerMapJson.append(printerJson2);
    Json::Value jsonObject2;
    jsonObject2["version"] = "v1";
    jsonObject2["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject2);

    Json::Value printerJson3;
    printerJson3["id"] = "123";
    printerJson3["name"] = 132;
    printerMapJson.append(printerJson3);
    Json::Value jsonObject3;
    jsonObject3["version"] = "v1";
    jsonObject3["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject3);

    Json::Value printerJson4;
    printerJson4["id"] = "123";
    printerJson4["name"] = "132";
    printerMapJson.append(printerJson4);
    Json::Value jsonObject4;
    jsonObject4["version"] = "v1";
    jsonObject4["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject4);

    Json::Value printerJson5;
    printerJson5["id"] = "123";
    printerJson5["name"] = "132";
    printerJson5["uri"] = 123;
    printerMapJson.append(printerJson5);
    Json::Value jsonObject5;
    jsonObject5["version"] = "v1";
    jsonObject5["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject5);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0019, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);

    Json::Value printerJson6;
    printerJson6["id"] = "123";
    printerJson6["name"] = "132";
    printerJson6["uri"] = "123";
    printerMapJson.append(printerJson6);
    Json::Value jsonObject6;
    jsonObject6["version"] = "v1";
    jsonObject6["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject6);

    Json::Value printerJson7;
    printerJson7["id"] = "123";
    printerJson7["name"] = "132";
    printerJson7["uri"] = "123";
    printerJson7["maker"] = 123;
    printerMapJson.append(printerJson7);
    Json::Value jsonObject7;
    jsonObject7["version"] = "v1";
    jsonObject7["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject7);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0020, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerJson["id"] = "123";
    printerJson["name"] = "132";
    printerJson["uri"] = "123";
    printerJson["maker"] = "123";
    Json::Value capsJson;
    printerJson["capability"] = capsJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0021, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerJson["id"] = "123";
    printerJson["name"] = "132";
    printerJson["uri"] = "123";
    printerJson["maker"] = "123";
    Json::Value capsJson;
    printerJson["capability"] = capsJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0022, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0023, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    std::string printerName = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->DeleteCupsPrinter(printerId, printerName);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0024, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_.Insert("1", nullptr);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("2", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    CupsPrinterInfo cupsPrinterInfo2;
    cupsPrinterInfo2.name = "Direct";
    cupsPrinterInfo2.uri = "123";
    cupsPrinterInfo2.maker = "print";
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo2));
    systemData->UpdatePrinterStatus(printerId, PRINTER_STATUS_IDLE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0025, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_.Insert("1", nullptr);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("2", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0026, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("1", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0027, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0028, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    printerCapability.SetMinMargin(minMargin);
    std::vector<PrintResolution> resolutionList;
    printerCapability.SetResolution(resolutionList);
    std::string ops = "test";
    printerCapability.SetOption(ops);
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0029, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    printerCapability.SetMinMargin(minMargin);
    std::vector<PrintResolution> resolutionList;
    printerCapability.SetResolution(resolutionList);
    Json::Value ops;
    ops["key"] = "value";
    printerCapability.SetOption(PrintJsonUtil::WriteString(ops));
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0030, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    printerCapability.SetMinMargin(minMargin);
    Json::Value capsJson;
    systemData->ConvertPrintMarginToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0031, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    minMargin.SetTop(100);
    minMargin.SetBottom(100);
    minMargin.SetLeft(100);
    minMargin.SetRight(100);
    printerCapability.SetMinMargin(minMargin);
    Json::Value capsJson;
    systemData->ConvertPrintMarginToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0032, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    capsJson["colorMode"] = "string";
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    capsJson["colorMode"] = 123;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    capsJson["duplexMode"] = "string";
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    capsJson["duplexMode"] = 123;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value marginJson;
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value marginJson2;
    capsJson["minMargin"] = marginJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value pageSizeJson;
    capsJson["pageSize"] = pageSizeJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value pageSizeJson2;
    Json::Value pageSize;
    pageSizeJson2.append(pageSize);
    capsJson["pageSize"] = pageSizeJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value pageSizeJson3;
    capsJson["pageSize"] = pageSizeJson3;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value resolutionJson;
    capsJson["resolution"] = resolutionJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value resolutionJson2;
    Json::Value resolution;
    resolutionJson2.append(resolution);
    capsJson["resolution"] = resolutionJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value resolutionJson3;
    capsJson["resolution"] = resolutionJson3;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value opsJson;
    capsJson["options"] = opsJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    Json::Value opsJson2;
    capsJson["options"] = opsJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0033, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value resolutionListJson;
    Json::Value resolutionItem;
    resolutionListJson.append(resolutionItem);
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson2;
    Json::Value resolutionItem2;
    resolutionListJson2.append(resolutionItem2);
    capsJson["resolution"] = resolutionListJson2;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson3;
    Json::Value resolutionItem3;
    resolutionItem3["id"] = 123;
    resolutionListJson3.append(resolutionItem3);
    capsJson["resolution"] = resolutionListJson3;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson4;
    Json::Value resolutionItem4;
    resolutionItem4["id"] = "123";
    resolutionListJson4.append(resolutionItem4);
    capsJson["resolution"] = resolutionListJson4;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0034, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value resolutionListJson;
    Json::Value resolutionItem;
    resolutionItem["id"] = "123";
    resolutionItem["horizontalDpi"] = "123";
    resolutionListJson.append(resolutionItem);
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson2;
    Json::Value resolutionItem2;
    resolutionItem2["id"] = "123";
    resolutionItem2["horizontalDpi"] = 123;
    resolutionListJson2.append(resolutionItem2);
    capsJson["resolution"] = resolutionListJson2;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson3;
    Json::Value resolutionItem3;
    resolutionItem3["id"] = "123";
    resolutionItem3["horizontalDpi"] = 123;
    resolutionItem3["verticalDpi"] = "123";
    resolutionListJson3.append(resolutionItem3);
    capsJson["resolution"] = resolutionListJson3;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    Json::Value resolutionListJson4;
    Json::Value resolutionItem4;
    resolutionItem4["id"] = "123";
    resolutionItem4["horizontalDpi"] = 123;
    resolutionItem4["verticalDpi"] = 123;
    resolutionListJson4.append(resolutionItem4);
    capsJson["resolution"] = resolutionListJson4;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0035, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value resolutionListJson;
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0036, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value pageSizeListJson;
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson2;
    Json::Value pageSizeItem2;
    pageSizeListJson2.append(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson3;
    Json::Value pageSizeItem3;
    pageSizeItem3["id"] = 123;
    pageSizeListJson3.append(pageSizeItem3);
    capsJson["pageSize"] = pageSizeListJson3;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson4;
    Json::Value pageSizeItem4;
    pageSizeItem4["id"] = "123";
    pageSizeListJson4.append(pageSizeItem4);
    capsJson["pageSize"] = pageSizeListJson4;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0037, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value pageSizeListJson;
    Json::Value pageSizeItem;
    pageSizeItem["id"] = "123";
    pageSizeItem["name"] = 123;
    pageSizeListJson.append(pageSizeItem);
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson2;
    Json::Value pageSizeItem2;
    pageSizeItem2["id"] = "123";
    pageSizeItem2["name"] = "123";
    pageSizeListJson2.append(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson3;
    Json::Value pageSizeItem3;
    pageSizeItem3["id"] = "123";
    pageSizeItem3["name"] = "123";
    pageSizeItem3["width"] = "123";
    pageSizeListJson3.append(pageSizeItem3);
    capsJson["pageSize"] = pageSizeListJson3;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson4;
    Json::Value pageSizeItem4;
    pageSizeItem4["id"] = "123";
    pageSizeItem4["name"] = "123";
    pageSizeItem4["width"] = 123;
    pageSizeListJson4.append(pageSizeItem4);
    capsJson["pageSize"] = pageSizeListJson4;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0038, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value pageSizeListJson;
    Json::Value pageSizeItem;
    pageSizeItem["id"] = "123";
    pageSizeItem["name"] = "123";
    pageSizeItem["width"] = 123;
    pageSizeItem["height"] = "123";
    pageSizeListJson.append(pageSizeItem);
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    Json::Value pageSizeListJson2;
    Json::Value pageSizeItem2;
    pageSizeItem2["id"] = "123";
    pageSizeItem2["name"] = "123";
    pageSizeItem2["width"] = 123;
    pageSizeItem2["height"] = 123;
    pageSizeListJson2.append(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0039, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value marginJson;
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson2;
    marginJson2["top"] = "123";
    capsJson["minMargin"] = marginJson2;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson3;
    marginJson3["top"] = 123;
    capsJson["minMargin"] = marginJson3;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson4;
    marginJson4["top"] = 123;
    marginJson4["bottom"] = "123";
    capsJson["minMargin"] = marginJson4;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson5;
    marginJson5["top"] = 123;
    marginJson5["bottom"] = 123;
    capsJson["minMargin"] = marginJson5;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson6;
    marginJson6["top"] = 123;
    marginJson6["bottom"] = 123;
    marginJson6["left"] = "123";
    capsJson["minMargin"] = marginJson6;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson7;
    marginJson7["top"] = 123;
    marginJson7["bottom"] = 123;
    marginJson7["left"] = 123;
    capsJson["minMargin"] = marginJson7;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0040, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value marginJson;
    marginJson["top"] = 123;
    marginJson["bottom"] = 123;
    marginJson["left"] = 123;
    marginJson["right"] = "123";
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    Json::Value marginJson2;
    marginJson2["top"] = 123;
    marginJson2["bottom"] = 123;
    marginJson2["left"] = 123;
    marginJson2["right"] = 123;
    capsJson["minMargin"] = marginJson2;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0041, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    CupsPrinterInfo cupsPrinter;
    std::string printerId = "123";
    PrinterCapability printerCapability;
    systemData->GetPrinterCapabilityFromSystemData(cupsPrinter, printerId, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0042, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    CupsPrinterInfo cupsPrinter;
    std::string printerId = "123";
    PrinterCapability printerCapability;
    PrinterCapability printerCapability2;
    Json::Value opsJson;
    opsJson["key"] = "value";
    printerCapability2.SetOption(PrintJsonUtil::WriteString(opsJson));
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    printerCapability2.SetSupportedPageSize(pageSizeList);
    cupsPrinter.printerCapability = printerCapability2;
    systemData->GetPrinterCapabilityFromSystemData(cupsPrinter, printerId, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0043, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value object;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0044, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value object;
    object["id"] = 123;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);

    Json::Value object2;
    object2["id"] = "12";
    systemData->CheckPrinterInfoJson(object2, printerId);

    Json::Value object3;
    object3["id"] = "123";
    systemData->CheckPrinterInfoJson(object3, printerId);

    Json::Value object4;
    object4["id"] = "123";
    object4["name"] = 123;
    systemData->CheckPrinterInfoJson(object4, printerId);

    Json::Value object5;
    object5["id"] = "123";
    object5["name"] = "123";
    systemData->CheckPrinterInfoJson(object5, printerId);

    Json::Value object6;
    object6["id"] = "123";
    object6["name"] = "123";
    object6["uri"] = 123;
    systemData->CheckPrinterInfoJson(object6, printerId);

    Json::Value object7;
    object7["id"] = "123";
    object7["name"] = "123";
    object7["uri"] = "123";
    systemData->CheckPrinterInfoJson(object7, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0045, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value object;
    object["id"] = "123";
    object["name"] = "123";
    object["uri"] = "123";
    object["maker"] = 123;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);

    Json::Value object2;
    object2["id"] = "123";
    object2["name"] = "123";
    object2["uri"] = "123";
    object2["maker"] = "123";
    systemData->CheckPrinterInfoJson(object2, printerId);

    Json::Value object3;
    object3["id"] = "123";
    object3["name"] = "123";
    object3["uri"] = "123";
    object3["maker"] = "123";
    object3["capability"] = "123";
    systemData->CheckPrinterInfoJson(object3, printerId);

    Json::Value object4;
    object4["id"] = "123";
    object4["name"] = "123";
    object4["uri"] = "123";
    object4["maker"] = "123";
    Json::Value capsJson;
    object4["capability"] = capsJson;
    systemData->CheckPrinterInfoJson(object4, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0046, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "123";
    systemData->IsPrinterAdded(printerId);
    systemData->addedPrinterMap_.Insert("123", nullptr);
    systemData->IsPrinterAdded(printerId);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("123", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->IsPrinterAdded(printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0047, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->QueryPrinterInfoById(printerId, printerInfo);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct Pixlab1620";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->QueryPrinterInfoById(printerId, printerInfo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0048, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    Json::Value jsonObject;
    PrinterCapability printerCapability;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);

    Json::Value printerMapJson;
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);

    Json::Value jsonObject2;
    Json::Value printerMapJson2;
    jsonObject2["printer_list"] = printerMapJson2;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject2, printerCapability);

    Json::Value jsonObject3;
    Json::Value printerMapJson3;
    Json::Value item;
    item["key"] = "value";
    printerMapJson3.append(item);
    jsonObject3["printer_list"] = printerMapJson3;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject3, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0049, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    PrinterCapability printerCapability;
    Json::Value jsonObject;
    Json::Value printerMapJson;
    Json::Value item;
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    Json::Value capsJson;
    capsJson["key"] = "value";
    item["capability"] = capsJson;
    printerMapJson.append(item);
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0050, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    PrinterCapability printerCapability;
    Json::Value jsonObject;
    Json::Value printerMapJson;
    Json::Value item;
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
    item["capability"] = capsJson;
    printerMapJson.append(item);
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0051, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "123";
    PrinterCapability printerCapability;
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    printerCapability.SetSupportedPageSize(pageSizeList);
    Json::Value opsJson;
    opsJson["printerName"] = "123";
    printerCapability.SetOption(PrintJsonUtil::WriteString(opsJson));
    Json::Value jsonObject;
    Json::Value printerMapJson;
    Json::Value item;
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
    item["capability"] = capsJson;
    printerMapJson.append(item);
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0052, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "";
    std::string printerName = "";
    systemData->DeleteCupsPrinter(printerId, printerName);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0053, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    std::string printerAlias = "1234";
    systemData->UpdatePrinterAlias(printerId, printerAlias);

    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.alias = printerAlias;
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));

    bool ret = systemData->UpdatePrinterAlias(printerId, "");
    EXPECT_EQ(ret, true);

    systemData->UpdatePrinterAlias(printerId, printerAlias);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0054, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId1 = "1";
    CupsPrinterInfo cupsPrinterInfo1;
    systemData->addedPrinterMap_.Insert(printerId1, std::make_shared<CupsPrinterInfo>(cupsPrinterInfo1));
    systemData->CheckPrinterBusy(printerId1);

    std::string printerId2 = "2";
    CupsPrinterInfo cupsPrinterInfo2;
    cupsPrinterInfo2.printerStatus = PRINTER_STATUS_BUSY;
    systemData->addedPrinterMap_.Insert(printerId2, std::make_shared<CupsPrinterInfo>(cupsPrinterInfo2));
    bool ret = systemData->CheckPrinterBusy(printerId2);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0055, TestSize.Level1)
{
    auto systemData = std::make_shared<PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId1 = "1";
    std::string printerId2 = "2";
    std::string printerName = "name";
    auto printerInfo = std::make_shared<PrinterInfo>();
    EXPECT_NE(printerInfo, nullptr);
    printerInfo->SetPrinterId(printerId1);
    printerInfo->SetPrinterName(printerName);
    systemData->AddPrinterToDiscovery(printerInfo);
    EXPECT_EQ(systemData->GetDiscoveredPrinterCount(), 1);
    auto discoveredPrinter = systemData->QueryDiscoveredPrinterInfoById(printerId1);
    EXPECT_NE(discoveredPrinter, nullptr);
    discoveredPrinter = systemData->QueryDiscoveredPrinterInfoById(printerId2);
    EXPECT_EQ(discoveredPrinter, nullptr);
    discoveredPrinter = systemData->QueryDiscoveredPrinterInfoByName(printerName);
    EXPECT_NE(discoveredPrinter, nullptr);
    discoveredPrinter = systemData->QueryDiscoveredPrinterInfoByName(printerId2);
    EXPECT_EQ(discoveredPrinter, nullptr);
    systemData->RemovePrinterFromDiscovery(printerId1);
    EXPECT_EQ(systemData->GetDiscoveredPrinterCount(), 0);
    systemData->ClearDiscoveredPrinterList();
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0056, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    CupsPrinterInfo info;
    Json::Value printerJson;
    systemData->ConvertInnerJsonToCupsPrinterInfo(printerJson, info);
    printerJson["alias"] = 123;
    printerJson["printerStatus"] = "132";
    printerJson["preferences"] = "123";
    systemData->ConvertInnerJsonToCupsPrinterInfo(printerJson, info);
    printerJson["alias"] = "123";
    printerJson["printerStatus"] = 123;
    Json::Value preferencesJson;
    printerJson["preferences"] = preferencesJson;
    systemData->ConvertInnerJsonToCupsPrinterInfo(printerJson, info);
    EXPECT_EQ(info.alias, printerJson["alias"]);
    EXPECT_EQ(info.printerStatus, printerJson["printerStatus"]);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0057, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0058, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value settingJson;
    EXPECT_EQ(systemData->ParsePreviousPreferencesSetting(settingJson, preferences), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0059, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value settingJson;
    settingJson["pagesizeId"] = 123;
    settingJson["orientation"] = 123;
    settingJson["duplex"] = 123;
    settingJson["quality"] = 123;
    settingJson["mediaType"] = 123;
    settingJson["hasMargin"] = "123";
    EXPECT_EQ(systemData->ParsePreviousPreferencesSetting(settingJson, preferences), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0060, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value settingJson;
    settingJson["pagesizeId"] = "";
    settingJson["orientation"] = "";
    settingJson["duplex"] = "";
    settingJson["quality"] = "";
    settingJson["mediaType"] = "";
    settingJson["hasMargin"] = true;
    EXPECT_EQ(systemData->ParsePreviousPreferencesSetting(settingJson, preferences), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0061, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value settingJson;
    settingJson["pagesizeId"] = "123";
    settingJson["orientation"] = "123";
    settingJson["duplex"] = "123";
    settingJson["quality"] = "123";
    settingJson["mediaType"] = "123";
    settingJson["hasMargin"] = false;
    EXPECT_EQ(systemData->ParsePreviousPreferencesSetting(settingJson, preferences), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0062, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterPreferences preferences;
    preferences.SetBorderless(true);
    systemData->UpdatePrinterPreferences(printerId, preferences);

    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.printPreferences = preferences;
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<CupsPrinterInfo>(cupsPrinterInfo));
    systemData->UpdatePrinterPreferences(printerId, preferences);
    CupsPrinterInfo cupsPrinter;
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter);
    EXPECT_EQ(cupsPrinter.printPreferences.GetBorderless(), preferences.GetBorderless());
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0063, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value preferencesJson;
    systemData->ConvertJsonToPrinterPreferences(preferencesJson, preferences);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0064, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value preferencesJson;
    preferencesJson["pagesizeId"] = 123;
    preferencesJson["orientation"] = "123";
    preferencesJson["duplex"] = "123";
    preferencesJson["quality"] = "123";
    preferencesJson["mediaType"] = 123;
    preferencesJson["hasMargin"] = "123";
    preferencesJson["options"] = "123";
    systemData->ConvertJsonToPrinterPreferences(preferencesJson, preferences);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0065, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value preferencesJson;
    preferencesJson["pagesizeId"] = "123";
    preferencesJson["orientation"] = 123;
    preferencesJson["duplex"] = 123;
    preferencesJson["quality"] = 123;
    preferencesJson["mediaType"] = "123";
    preferencesJson["hasMargin"] = true;
    Json::Value optionJson;
    preferencesJson["options"] = optionJson;
    systemData->ConvertJsonToPrinterPreferences(preferencesJson, preferences);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0066, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0067, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    cap.SetOption("test");
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0068, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    Json::Value optionJson;
    optionJson["key"] = "value";
    cap.SetOption(PrintJsonUtil::WriteString(optionJson));
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0069, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    Json::Value optionJson;
    optionJson["cupsOptions"] = "value";
    cap.SetOption(PrintJsonUtil::WriteString(optionJson));
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_NONE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0070, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    EXPECT_EQ(systemData->ParseDefaultPageSizeId(cap, capOpt), "");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0071, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["defaultPageSizeId"] = 123;
    std::vector<PrintPageSize> supportedPageSize;
    PrintPageSize pageSize1;
    pageSize1.SetId("ISO_A3");
    PrintPageSize pageSize2;
    pageSize2.SetId("ISO_A4");
    supportedPageSize.emplace_back(pageSize1);
    supportedPageSize.emplace_back(pageSize2);
    cap.SetSupportedPageSize(supportedPageSize);
    EXPECT_EQ(systemData->ParseDefaultPageSizeId(cap, capOpt), "ISO_A3");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0072, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["defaultPageSizeId"] = "123";
    EXPECT_EQ(systemData->ParseDefaultPageSizeId(cap, capOpt), "123");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0073, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    EXPECT_EQ(systemData->ParseDefaultOrientation(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0074, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["orientation-requested-default"] = 123;
    EXPECT_EQ(systemData->ParseDefaultOrientation(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0075, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["orientation-requested-default"] = "0";
    EXPECT_EQ(systemData->ParseDefaultOrientation(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0076, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    EXPECT_EQ(systemData->ParseDefaultDuplexMode(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0077, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt ;
    capOpt["sides-default"] = 123;
    std::vector<uint32_t> supportedDuplexModeList;
    supportedDuplexModeList.emplace_back(2);
    cap.SetSupportedDuplexMode(supportedDuplexModeList);
    EXPECT_EQ(systemData->ParseDefaultDuplexMode(cap, capOpt), 2);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0078, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["sides-default"] = 123;
    std::vector<uint32_t> supportedDuplexModeList;
    supportedDuplexModeList.emplace_back(0);
    cap.SetSupportedDuplexMode(supportedDuplexModeList);
    EXPECT_EQ(systemData->ParseDefaultDuplexMode(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0079, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["sides-default"] = "0";
    EXPECT_EQ(systemData->ParseDefaultDuplexMode(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0080, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    EXPECT_EQ(systemData->ParseDefaultPrintQuality(cap, capOpt), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0081, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["print-quality-default"] = 123;
    std::vector<uint32_t> supportedQualityList;
    supportedQualityList.emplace_back(2);
    supportedQualityList.emplace_back(4);
    cap.SetSupportedQuality(supportedQualityList);
    EXPECT_EQ(systemData->ParseDefaultPrintQuality(cap, capOpt), 4);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0082, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["print-quality-default"] = "4";
    EXPECT_EQ(systemData->ParseDefaultPrintQuality(cap, capOpt), 4);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0083, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    EXPECT_EQ(systemData->ParseDefaultMediaType(cap, capOpt), "");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0084, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["media-type-default"] = 123;
    std::vector<std::string> supportedMediaTypeList;
    supportedMediaTypeList.emplace_back("photo");
    supportedMediaTypeList.emplace_back("stationery");
    cap.SetSupportedMediaType(supportedMediaTypeList);
    EXPECT_EQ(systemData->ParseDefaultMediaType(cap, capOpt), "stationery");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0085, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    Json::Value capOpt;
    capOpt["media-type-default"] = "stationery";
    EXPECT_EQ(systemData->ParseDefaultMediaType(cap, capOpt), "stationery");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0086, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0087, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    std::string printerId = "testPrinterId";
    Json::Value printer;
    Json::Value printPreferenceJson;
    printer[printerId] = printPreferenceJson;
    printerListJson.append(printer);
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0088, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    std::string printerId = "testPrinterId";
    Json::Value printer;
    Json::Value printPreferenceJson;
    Json::Value setting;
    printPreferenceJson["setting"] = setting;
    printer[printerId] = printPreferenceJson;
    printerListJson.append(printer);
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0089, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    std::string printerId = "testPrinterId";
    Json::Value printer;
    Json::Value printPreferenceJson;
    Json::Value setting;
    printPreferenceJson["setting"] = setting;
    printer[printerId] = printPreferenceJson;
    printerListJson.append(printer);
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0090, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    std::string printerId = "testPrinterId";
    Json::Value printer;
    Json::Value printPreferenceJson;
    Json::Value setting;
    setting["pagesizeId"] = "ISO_A4";
    printPreferenceJson["setting"] = setting;
    printer[printerId] = printPreferenceJson;
    printerListJson.append(printer);
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), true);
}
}  // namespace Print
}  // namespace OHOS
