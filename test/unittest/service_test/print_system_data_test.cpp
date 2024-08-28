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
#include <map>
#include <nlohmann/json.hpp>
#include "printer_info.h"
#define private public
#include "print_system_data.h"
#undef private
#include "print_log.h"
#include "print_constant.h"

using namespace testing::ext;
using json = nlohmann::json;

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
    EXPECT_NE(systemData, nullptr);
    EXPECT_EQ(systemData->Init(), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0002, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, false);
    cupsPrinterInfo.name = "HUAWEI_PixLab_V1-0105";
    cupsPrinterInfo.uri = "ipp://192.168.186.1:631/ipp/print";
    cupsPrinterInfo.maker = "HUAWEI PixLab V1";
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, false);
    std::map<std::string, std::shared_ptr<CupsPrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    EXPECT_EQ(addedPrinterMap.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0003, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    EXPECT_EQ(systemData->SaveCupsPrinterMap(), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0004, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerName = "Direct Pixlab1620";
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "");
    systemData->addedPrinterMap_["1234"] = nullptr;
    systemData->QueryPrinterIdByStandardizeName(printerName);
    EXPECT_EQ(systemData->SaveCupsPrinterMap(), true);
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
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerJson["id"] = "com.ohos.spooler:mdns://9e9561ad-0e30-1000-8000-9c9561ad0e30";
    printerJson["maker"] = "HUAWEI PixLab V1";
    printerJson["name"] = "HUAWEI_PixLab_V1-0105";
    printerJson["uri"] = "ipp://192.168.186.1:631/ipp/print";
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);
    std::string printerName = systemData->QueryPrinterIdByStandardizeName("HUAWEI_PixLab_V1-0105");
    EXPECT_EQ(systemData->SaveCupsPrinterMap(), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0010, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson;
    printerMapJson["printer"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
    printerMapJson["printer_list"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0011, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_["1"] = nullptr;
    systemData->SaveCupsPrinterMap();
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "print";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["2"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->SaveCupsPrinterMap();
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0012, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_["1"] = nullptr;
    std::string printerName = "Direct";
    systemData->QueryPrinterIdByStandardizeName(printerName);
    systemData->SaveCupsPrinterMap();
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["2"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->QueryPrinterIdByStandardizeName(printerName);
    cupsPrinterInfo.name = "223";
    systemData->addedPrinterMap_["4"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->QueryPrinterIdByStandardizeName(printerName);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0013, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo2;
    systemData->addedPrinterMap_["1"] = nullptr;
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
    systemData->SaveCupsPrinterMap();
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct Pixlab1620";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["123"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    CupsPrinterInfo cupsPrinterInfo3;
    systemData->addedPrinterMap_["11"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo3);
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinterInfo2);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0014, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertPrinterInfo(printerId, printerInfo);
    systemData->addedPrinterMap_["1"] = nullptr;
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
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, false);
    systemData->addedPrinterMap_["1234"] = nullptr;
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, false);
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0017, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerJson["id"] = 123;
    printerJson["maker"] = 123;
    printerJson["name"] = 132;
    printerJson["uri"] = 123;
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0018, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);

    nlohmann::json printerJson2;
    printerJson2["id"] = "123";
    printerMapJson.push_back(printerJson2);
    nlohmann::json jsonObject2;
    jsonObject2["version"] = "v1";
    jsonObject2["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject2);

    nlohmann::json printerJson3;
    printerJson3["id"] = "123";
    printerJson3["name"] = 132;
    printerMapJson.push_back(printerJson3);
    nlohmann::json jsonObject3;
    jsonObject3["version"] = "v1";
    jsonObject3["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject3);

    nlohmann::json printerJson4;
    printerJson4["id"] = "123";
    printerJson4["name"] = "132";
    printerMapJson.push_back(printerJson4);
    nlohmann::json jsonObject4;
    jsonObject4["version"] = "v1";
    jsonObject4["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject4);

    nlohmann::json printerJson5;
    printerJson5["id"] = "123";
    printerJson5["name"] = "132";
    printerJson5["uri"] = 123;
    printerMapJson.push_back(printerJson5);
    nlohmann::json jsonObject5;
    jsonObject5["version"] = "v1";
    jsonObject5["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject5);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0019, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);

    nlohmann::json printerJson6;
    printerJson6["id"] = "123";
    printerJson6["name"] = "132";
    printerJson6["uri"] = "123";
    printerMapJson.push_back(printerJson6);
    nlohmann::json jsonObject6;
    jsonObject6["version"] = "v1";
    jsonObject6["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject6);

    nlohmann::json printerJson7;
    printerJson7["id"] = "123";
    printerJson7["name"] = "132";
    printerJson7["uri"] = "123";
    printerJson7["maker"] = 123;
    printerMapJson.push_back(printerJson7);
    nlohmann::json jsonObject7;
    jsonObject7["version"] = "v1";
    jsonObject7["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject7);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0020, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerJson["id"] = "123";
    printerJson["name"] = "132";
    printerJson["uri"] = "123";
    printerJson["maker"] = 123;
    nlohmann::json capsJson = nlohmann::json::array();
    printerJson["capability"] = capsJson;
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    systemData->ParsePrinterListJsonV1(jsonObject);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0021, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json printerJson;
    printerJson["id"] = "123";
    printerJson["name"] = "132";
    printerJson["uri"] = "123";
    printerJson["maker"] = 123;
    nlohmann::json capsJson = nlohmann::json::object();
    printerJson["capability"] = capsJson;
    printerMapJson.push_back(printerJson);
    nlohmann::json jsonObject;
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
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->InsertCupsPrinter(printerId, cupsPrinterInfo, true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0023, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    CupsPrinterInfo cupsPrinterInfo;
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->DeleteCupsPrinter(printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0024, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_["1"] = nullptr;
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["2"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    CupsPrinterInfo cupsPrinterInfo2;
    cupsPrinterInfo2.name = "Direct";
    cupsPrinterInfo2.uri = "123";
    cupsPrinterInfo2.maker = "print";
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo2);
    systemData->UpdatePrinterStatus(printerId, PRINTER_STATUS_IDLE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0025, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_["1"] = nullptr;
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["2"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0026, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    systemData->addedPrinterMap_["1"] = nullptr;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["1"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0027, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    nlohmann::json capsJson;
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
    nlohmann::json capsJson;
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
    nlohmann::json ops;
    ops["key"] = "value";
    printerCapability.SetOption(ops.dump());
    nlohmann::json capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0030, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    printerCapability.SetMinMargin(minMargin);
    nlohmann::json capsJson;
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
    nlohmann::json capsJson;
    systemData->ConvertPrintMarginToJson(printerCapability, capsJson);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0032, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
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
    nlohmann::json marginJson = nlohmann::json::array();
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json marginJson2 = nlohmann::json::object();
    capsJson["minMargin"] = marginJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json pageSizeJson = nlohmann::json::object();
    capsJson["pageSize"] = pageSizeJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json pageSizeJson2 = nlohmann::json::array();
    nlohmann::json pageSize = nlohmann::json::array();
    pageSizeJson2.push_back(pageSize);
    capsJson["pageSize"] = pageSizeJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json pageSizeJson3 = nlohmann::json::array();
    capsJson["pageSize"] = pageSizeJson3;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json resolutionJson = nlohmann::json::object();
    capsJson["resolution"] = resolutionJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json resolutionJson2 = nlohmann::json::array();
    nlohmann::json resolution = nlohmann::json::array();
    resolutionJson2.push_back(resolution);
    capsJson["resolution"] = resolutionJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json resolutionJson3 = nlohmann::json::array();
    capsJson["resolution"] = resolutionJson3;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json opsJson = nlohmann::json::array();
    capsJson["options"] = opsJson;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
    nlohmann::json opsJson2 = nlohmann::json::object();
    capsJson["options"] = opsJson2;
    systemData->ConvertJsonToPrinterCapability(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0033, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json resolutionListJson = nlohmann::json::array();
    nlohmann::json resolutionItem = nlohmann::json::array();
    resolutionListJson.push_back(resolutionItem);
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson2 = nlohmann::json::array();
    nlohmann::json resolutionItem2 = nlohmann::json::object();
    resolutionListJson2.push_back(resolutionItem2);
    capsJson["resolution"] = resolutionListJson2;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson3 = nlohmann::json::array();
    nlohmann::json resolutionItem3 = nlohmann::json::object();
    resolutionItem3["id"] = 123;
    resolutionListJson3.push_back(resolutionItem3);
    capsJson["resolution"] = resolutionListJson3;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson4 = nlohmann::json::array();
    nlohmann::json resolutionItem4 = nlohmann::json::object();
    resolutionItem4["id"] = "123";
    resolutionListJson4.push_back(resolutionItem4);
    capsJson["resolution"] = resolutionListJson4;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0034, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json resolutionListJson = nlohmann::json::array();
    nlohmann::json resolutionItem = nlohmann::json::object();
    resolutionItem["id"] = "123";
    resolutionItem["horizontalDpi"] = "123";
    resolutionListJson.push_back(resolutionItem);
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson2 = nlohmann::json::array();
    nlohmann::json resolutionItem2 = nlohmann::json::object();
    resolutionItem2["id"] = "123";
    resolutionItem2["horizontalDpi"] = 123;
    resolutionListJson2.push_back(resolutionItem2);
    capsJson["resolution"] = resolutionListJson2;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson3 = nlohmann::json::array();
    nlohmann::json resolutionItem3 = nlohmann::json::object();
    resolutionItem3["id"] = "123";
    resolutionItem3["horizontalDpi"] = 123;
    resolutionItem3["verticalDpi"] = "123";
    resolutionListJson3.push_back(resolutionItem3);
    capsJson["resolution"] = resolutionListJson3;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    nlohmann::json resolutionListJson4 = nlohmann::json::array();
    nlohmann::json resolutionItem4 = nlohmann::json::object();
    resolutionItem4["id"] = "123";
    resolutionItem4["horizontalDpi"] = 123;
    resolutionItem4["verticalDpi"] = 123;
    resolutionListJson4.push_back(resolutionItem4);
    capsJson["resolution"] = resolutionListJson4;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0035, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json resolutionListJson = nlohmann::json::array();
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0036, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json pageSizeListJson = nlohmann::json::array();
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson2 = nlohmann::json::array();
    nlohmann::json pageSizeItem2 = nlohmann::json::array();
    pageSizeListJson2.push_back(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson3 = nlohmann::json::array();
    nlohmann::json pageSizeItem3 = nlohmann::json::object();
    pageSizeItem3["id"] = 123;
    pageSizeListJson3.push_back(pageSizeItem3);
    capsJson["pageSize"] = pageSizeListJson3;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson4 = nlohmann::json::array();
    nlohmann::json pageSizeItem4 = nlohmann::json::object();
    pageSizeItem4["id"] = "123";
    pageSizeListJson4.push_back(pageSizeItem4);
    capsJson["pageSize"] = pageSizeListJson4;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0037, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json pageSizeListJson = nlohmann::json::array();
    nlohmann::json pageSizeItem = nlohmann::json::object();
    pageSizeItem["id"] = "123";
    pageSizeItem["name"] = 123;
    pageSizeListJson.push_back(pageSizeItem);
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson2 = nlohmann::json::array();
    nlohmann::json pageSizeItem2 = nlohmann::json::object();
    pageSizeItem2["id"] = "123";
    pageSizeItem2["name"] = "123";
    pageSizeListJson2.push_back(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson3 = nlohmann::json::array();
    nlohmann::json pageSizeItem3 = nlohmann::json::object();
    pageSizeItem3["id"] = "123";
    pageSizeItem3["name"] = "123";
    pageSizeItem3["width"] = "123";
    pageSizeListJson3.push_back(pageSizeItem3);
    capsJson["pageSize"] = pageSizeListJson3;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson4 = nlohmann::json::array();
    nlohmann::json pageSizeItem4 = nlohmann::json::object();
    pageSizeItem4["id"] = "123";
    pageSizeItem4["name"] = "123";
    pageSizeItem4["width"] = 123;
    pageSizeListJson4.push_back(pageSizeItem4);
    capsJson["pageSize"] = pageSizeListJson4;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0038, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json pageSizeListJson = nlohmann::json::array();
    nlohmann::json pageSizeItem = nlohmann::json::object();
    pageSizeItem["id"] = "123";
    pageSizeItem["name"] = "123";
    pageSizeItem["width"] = 123;
    pageSizeItem["height"] = "123";
    pageSizeListJson.push_back(pageSizeItem);
    capsJson["pageSize"] = pageSizeListJson;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);

    nlohmann::json pageSizeListJson2 = nlohmann::json::array();
    nlohmann::json pageSizeItem2 = nlohmann::json::object();
    pageSizeItem2["id"] = "123";
    pageSizeItem2["name"] = "123";
    pageSizeItem2["width"] = 123;
    pageSizeItem2["height"] = 123;
    pageSizeListJson2.push_back(pageSizeItem2);
    capsJson["pageSize"] = pageSizeListJson2;
    systemData->ConvertJsonToPageSize(capsJson, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0039, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json marginJson = nlohmann::json::object();
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson2 = nlohmann::json::object();
    marginJson2["top"] = "123";
    capsJson["minMargin"] = marginJson2;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson3 = nlohmann::json::object();
    marginJson3["top"] = 123;
    capsJson["minMargin"] = marginJson3;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson4 = nlohmann::json::object();
    marginJson4["top"] = 123;
    marginJson4["bottom"] = "123";
    capsJson["minMargin"] = marginJson4;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson5 = nlohmann::json::object();
    marginJson5["top"] = 123;
    marginJson5["bottom"] = 123;
    capsJson["minMargin"] = marginJson5;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson6 = nlohmann::json::object();
    marginJson6["top"] = 123;
    marginJson6["bottom"] = 123;
    marginJson6["left"] = "123";
    capsJson["minMargin"] = marginJson6;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson7 = nlohmann::json::object();
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
    nlohmann::json capsJson;
    PrinterCapability printerCapability;
    nlohmann::json marginJson = nlohmann::json::object();
    marginJson["top"] = 123;
    marginJson["bottom"] = 123;
    marginJson["left"] = 123;
    marginJson["right"] = "123";
    capsJson["minMargin"] = marginJson;
    systemData->ConvertJsonToPrintMargin(capsJson, printerCapability);

    nlohmann::json marginJson2 = nlohmann::json::object();
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
    nlohmann::json opsJson;
    opsJson["key"] = "value";
    printerCapability2.SetOption(opsJson.dump());
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
    nlohmann::json object;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0044, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json object;
    object["id"] = 123;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);

    nlohmann::json object2;
    object2["id"] = "12";
    systemData->CheckPrinterInfoJson(object2, printerId);

    nlohmann::json object3;
    object3["id"] = "123";
    systemData->CheckPrinterInfoJson(object3, printerId);

    nlohmann::json object4;
    object4["id"] = "123";
    object4["name"] = 123;
    systemData->CheckPrinterInfoJson(object4, printerId);

    nlohmann::json object5;
    object5["id"] = "123";
    object5["name"] = "123";
    systemData->CheckPrinterInfoJson(object5, printerId);

    nlohmann::json object6;
    object6["id"] = "123";
    object6["name"] = "123";
    object6["uri"] = 123;
    systemData->CheckPrinterInfoJson(object6, printerId);

    nlohmann::json object7;
    object7["id"] = "123";
    object7["name"] = "123";
    object7["uri"] = "123";
    systemData->CheckPrinterInfoJson(object7, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0045, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    nlohmann::json object;
    object["id"] = "123";
    object["name"] = "123";
    object["uri"] = "123";
    object["maker"] = 123;
    std::string printerId = "123";
    systemData->CheckPrinterInfoJson(object, printerId);

    nlohmann::json object2;
    object2["id"] = "123";
    object2["name"] = "123";
    object2["uri"] = "123";
    object2["maker"] = "123";
    systemData->CheckPrinterInfoJson(object2, printerId);

    nlohmann::json object3;
    object3["id"] = "123";
    object3["name"] = "123";
    object3["uri"] = "123";
    object3["maker"] = "123";
    object3["capability"] = "123";
    systemData->CheckPrinterInfoJson(object3, printerId);

    nlohmann::json object4;
    object4["id"] = "123";
    object4["name"] = "123";
    object4["uri"] = "123";
    object4["maker"] = "123";
    nlohmann::json capsJson = nlohmann::json::object();
    object4["capability"] = capsJson;
    systemData->CheckPrinterInfoJson(object4, printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0046, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "123";
    systemData->IsPrinterAdded(printerId);
    systemData->addedPrinterMap_["123"] = nullptr;
    systemData->IsPrinterAdded(printerId);
    CupsPrinterInfo cupsPrinterInfo;
    cupsPrinterInfo.name = "Direct";
    cupsPrinterInfo.uri = "123";
    cupsPrinterInfo.maker = "print";
    systemData->addedPrinterMap_["123"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
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
    systemData->addedPrinterMap_["1234"] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);
    systemData->QueryPrinterInfoById(printerId, printerInfo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0048, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    nlohmann::json jsonObject;
    PrinterCapability printerCapability;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);

    nlohmann::json printerMapJson = nlohmann::json::object();
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);

    nlohmann::json jsonObject2;
    nlohmann::json printerMapJson2 = nlohmann::json::array();
    jsonObject2["printer_list"] = printerMapJson2;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject2, printerCapability);

    nlohmann::json jsonObject3;
    nlohmann::json printerMapJson3 = nlohmann::json::array();
    nlohmann::json item = nlohmann::json::object();
    item["key"] = "value";
    printerMapJson3.push_back(item);
    jsonObject3["printer_list"] = printerMapJson3;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject3, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0049, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    PrinterCapability printerCapability;
    nlohmann::json jsonObject;
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json item = nlohmann::json::object();
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    nlohmann::json capsJson = nlohmann::json::object();
    capsJson["key"] = "value";
    item["capability"] = capsJson;
    printerMapJson.push_back(item);
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0050, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId;
    PrinterCapability printerCapability;
    nlohmann::json jsonObject;
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json item = nlohmann::json::object();
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    nlohmann::json capsJson = nlohmann::json::object();
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
    item["capability"] = capsJson;
    printerMapJson.push_back(item);
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
    nlohmann::json opsJson;
    opsJson["printerName"] = "123";
    printerCapability.SetOption(opsJson.dump());
    nlohmann::json jsonObject;
    nlohmann::json printerMapJson = nlohmann::json::array();
    nlohmann::json item = nlohmann::json::object();
    item["id"] = "123";
    item["name"] = "123";
    item["uri"] = "123";
    item["maker"] = "123";
    nlohmann::json capsJson = nlohmann::json::object();
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
    item["capability"] = capsJson;
    printerMapJson.push_back(item);
    jsonObject["printer_list"] = printerMapJson;
    systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0052, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "";
    systemData->DeleteCupsPrinter(printerId);
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
    systemData->addedPrinterMap_[printerId] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo);

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
    systemData->addedPrinterMap_[printerId1] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo1);
    systemData->CheckPrinterBusy(printerId1);

    std::string printerId2 = "2";
    CupsPrinterInfo cupsPrinterInfo2;
    cupsPrinterInfo2.printerStatus = PRINTER_STATUS_BUSY;
    systemData->addedPrinterMap_[printerId2] = std::make_shared<CupsPrinterInfo>(cupsPrinterInfo2);
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
}  // namespace Print
}  // namespace OHOS
