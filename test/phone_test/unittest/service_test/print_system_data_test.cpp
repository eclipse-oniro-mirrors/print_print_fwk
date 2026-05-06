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
};

void PrintSystemDataTest::SetUpTestCase(void)
{}

void PrintSystemDataTest::TearDownTestCase(void)
{}

void PrintSystemDataTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintSystemDataTest_%{public}d", ++testNo);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0002_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertAddedPrinter(printerId, printerInfo);
    printerInfo.SetPrinterName("HW_PixLab_V1-0105");
    printerInfo.SetUri("ipp://192.168.186.1:631/ipp/print");
    printerInfo.SetPrinterMake("HW PixLab V1");
    systemData->InsertAddedPrinter(printerId, printerInfo);
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    EXPECT_EQ(addedPrinterMap.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0004_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerName = "Direct Pixlab1620";
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0005_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerName = "Direct Pixlab1620";
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "");
    std::string re = systemData->QueryPrinterIdByStandardizeName(printerName);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct Pixlab1620");
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    EXPECT_EQ(addedPrinterMap.size(), 1);
    if (printerInfo.GetPrinterName() == printerName) {
        re = printerId;
    }
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0006_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo1;
    printerInfo1.SetPrinterName("Direct Pixlab1620");
    PrinterInfo printerInfo2;
    EXPECT_EQ(systemData->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo2), false);
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterMap;
    addedPrinterMap[printerId] = std::make_shared<PrinterInfo>(printerInfo1);
    EXPECT_EQ(addedPrinterMap.size(), 1);
    if (addedPrinterMap.count(printerId)) {
        printerInfo2 = printerInfo1;
        EXPECT_EQ(printerInfo2.GetPrinterName(), printerInfo1.GetPrinterName());
    }
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0007_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertAddedPrinter(printerId, printerInfo);
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterInfoList;
    addedPrinterInfoList[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    EXPECT_EQ(addedPrinterInfoList.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0008_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    std::shared_ptr<PrinterInfo> result = std::make_shared<PrinterInfo>();
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0009_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0010_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    printerMapJson["printer"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
    printerMapJson["printer_list"] = "1234";
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(printerMapJson), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0011_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->SavePrinterFile("1");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0012_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    std::string printerName = "Direct";
    systemData->QueryPrinterIdByStandardizeName(printerName);
    systemData->SavePrinterFile("1");
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("2", std::make_shared<PrinterInfo>(printerInfo));
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "2");
    printerInfo.SetPrinterName("223");
    systemData->addedPrinterMap_.Insert("4", std::make_shared<PrinterInfo>(printerInfo));
    EXPECT_EQ(systemData->QueryPrinterIdByStandardizeName(printerName), "2");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0013_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo2;
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo2);
    systemData->SavePrinterFile("1");
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct Pixlab1620");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("123", std::make_shared<PrinterInfo>(printerInfo));
    PrinterInfo printerInfo3;
    systemData->addedPrinterMap_.Insert("11", std::make_shared<PrinterInfo>(printerInfo3));
    EXPECT_EQ(systemData->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo2), false);
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo));
    EXPECT_EQ(systemData->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo2), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0014_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertAddedPrinter(printerId, printerInfo);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 1);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->InsertAddedPrinter(printerId, printerInfo);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0016_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->InsertAddedPrinter(printerId, printerInfo);
    systemData->addedPrinterMap_.Insert("1234", nullptr);
    systemData->InsertAddedPrinter(printerId, printerInfo);
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo));
    systemData->InsertAddedPrinter(printerId, printerInfo);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0017_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0018_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);

    Json::Value printerJson2;
    printerJson2["id"] = "123";
    printerMapJson.append(printerJson2);
    Json::Value jsonObject2;
    jsonObject2["version"] = "v1";
    jsonObject2["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject2), true);

    Json::Value printerJson3;
    printerJson3["id"] = "123";
    printerJson3["name"] = 132;
    printerMapJson.append(printerJson3);
    Json::Value jsonObject3;
    jsonObject3["version"] = "v1";
    jsonObject3["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject3), true);

    Json::Value printerJson4;
    printerJson4["id"] = "123";
    printerJson4["name"] = "132";
    printerMapJson.append(printerJson4);
    Json::Value jsonObject4;
    jsonObject4["version"] = "v1";
    jsonObject4["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject4), true);

    Json::Value printerJson5;
    printerJson5["id"] = "123";
    printerJson5["name"] = "132";
    printerJson5["uri"] = 123;
    printerMapJson.append(printerJson5);
    Json::Value jsonObject5;
    jsonObject5["version"] = "v1";
    jsonObject5["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject5), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0019_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value printerMapJson;
    Json::Value printerJson;
    printerMapJson.append(printerJson);
    Json::Value jsonObject;
    jsonObject["version"] = "v1";
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);

    Json::Value printerJson6;
    printerJson6["id"] = "123";
    printerJson6["name"] = "132";
    printerJson6["uri"] = "123";
    printerMapJson.append(printerJson6);
    Json::Value jsonObject6;
    jsonObject6["version"] = "v1";
    jsonObject6["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject6), true);

    Json::Value printerJson7;
    printerJson7["id"] = "123";
    printerJson7["name"] = "132";
    printerJson7["uri"] = "123";
    printerJson7["maker"] = 123;
    printerMapJson.append(printerJson7);
    Json::Value jsonObject7;
    jsonObject7["version"] = "v1";
    jsonObject7["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject7), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0020_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0021_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->ParsePrinterListJsonV1(jsonObject), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0022_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    printerInfo.SetAlias("test");
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo));
    systemData->InsertAddedPrinter(printerId, printerInfo);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0023_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    std::string printerName = "1234";
    PrinterInfo printerInfo;
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo));
    systemData->DeleteAddedPrinter(printerId, printerName);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0024_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_.Insert("1", nullptr);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("2", std::make_shared<PrinterInfo>(printerInfo));
    PrinterInfo printerInfo2;
    printerInfo2.SetPrinterName("Direct");
    printerInfo2.SetUri("123");
    printerInfo2.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo2));
    systemData->UpdatePrinterStatus(printerId, PRINTER_STATUS_IDLE);
    PrinterInfo printerInfo3;
    systemData->QueryAddedPrinterInfoByPrinterId(printerId, printerInfo3);
    EXPECT_EQ(printerInfo3.GetPrinterStatus(), PRINTER_STATUS_IDLE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0025_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    systemData->addedPrinterMap_.Insert("1", nullptr);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("2", std::make_shared<PrinterInfo>(printerInfo));
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    EXPECT_EQ(printerNameList.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0026_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<std::string> printerNameList;
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    systemData->addedPrinterMap_.Insert("1", nullptr);
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("1", std::make_shared<PrinterInfo>(printerInfo));
    systemData->GetAddedPrinterListFromSystemData(printerNameList);
    EXPECT_EQ(printerNameList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0027_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    Json::Value capsJson;
    systemData->ConvertPrinterCapabilityToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["colorMode"].asInt(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0028_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(capsJson["colorMode"].asInt(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0029_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(capsJson["colorMode"].asInt(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0030_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    PrintMargin minMargin;
    printerCapability.SetMinMargin(minMargin);
    Json::Value capsJson;
    systemData->ConvertPrintMarginToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["minMargin"].isNull(), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0031_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(capsJson["minMargin"]["top"].asInt(), 100);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0032_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(printerCapability.GetColorMode(), 123);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0033_NeedRename, TestSize.Level1)
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
    std::vector<PrintResolution> resolutionList;
    printerCapability.GetResolution(resolutionList);
    EXPECT_EQ(resolutionList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0034_NeedRename, TestSize.Level1)
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
    std::vector<PrintResolution> resolutionList;
    printerCapability.GetResolution(resolutionList);
    EXPECT_EQ(resolutionList.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0035_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capsJson;
    PrinterCapability printerCapability;
    Json::Value resolutionListJson;
    capsJson["resolution"] = resolutionListJson;
    systemData->ConvertJsonToPrintResolution(capsJson, printerCapability);
    std::vector<PrintResolution> resolutionList;
    printerCapability.GetResolution(resolutionList);
    EXPECT_EQ(resolutionList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0036_NeedRename, TestSize.Level1)
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
    std::vector<PrintPageSize> supportedPageSizeList;
    printerCapability.GetSupportedPageSize(supportedPageSizeList);
    EXPECT_EQ(supportedPageSizeList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0037_NeedRename, TestSize.Level1)
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
    std::vector<PrintPageSize> supportedPageSizeList;
    printerCapability.GetSupportedPageSize(supportedPageSizeList);
    EXPECT_EQ(supportedPageSizeList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0038_NeedRename, TestSize.Level1)
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
    std::vector<PrintPageSize> supportedPageSizeList;
    printerCapability.GetSupportedPageSize(supportedPageSizeList);
    EXPECT_EQ(supportedPageSizeList.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0039_NeedRename, TestSize.Level1)
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
    PrintMargin margin;
    printerCapability.GetMinMargin(margin);
    EXPECT_EQ(margin.GetTop(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0040_NeedRename, TestSize.Level1)
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
    PrintMargin margin;
    printerCapability.GetMinMargin(margin);
    EXPECT_EQ(margin.GetTop(), 123);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0041_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterInfo printer;
    std::string printerId = "123";
    PrinterCapability printerCapability;
    EXPECT_EQ(systemData->GetPrinterCapabilityFromSystemData(printer, printerId, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0042_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterInfo printer;
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
    printer.SetCapability(printerCapability2);
    systemData->GetPrinterCapabilityFromSystemData(printer, printerId, printerCapability);
    EXPECT_EQ(systemData->GetPrinterCapabilityFromSystemData(printer, printerId, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0043_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value object;
    std::string printerId = "123";
    EXPECT_EQ(systemData->CheckPrinterInfoJson(object, printerId), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0044_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->CheckPrinterInfoJson(object7, printerId), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0045_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->CheckPrinterInfoJson(object4, printerId), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0046_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "123";
    systemData->IsPrinterAdded(printerId);
    systemData->addedPrinterMap_.Insert("123", nullptr);
    systemData->IsPrinterAdded(printerId);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Direct");
    printerInfo.SetUri("123");
    printerInfo.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("123", std::make_shared<PrinterInfo>(printerInfo));
    EXPECT_EQ(systemData->IsPrinterAdded(printerId), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0047_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterInfo printerInfo;
    systemData->QueryPrinterInfoById(printerId, printerInfo);
    PrinterInfo printerInfo1;
    printerInfo1.SetPrinterName("Direct Pixlab1620");
    printerInfo1.SetUri("123");
    printerInfo1.SetPrinterMake("print");
    systemData->addedPrinterMap_.Insert("1234", std::make_shared<PrinterInfo>(printerInfo1));
    systemData->QueryPrinterInfoById(printerId, printerInfo);
    EXPECT_EQ(printerInfo.GetUri(), "123");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0048_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject3, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0049_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0050_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0051_NeedRename, TestSize.Level1)
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
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0052_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "";
    std::string printerName = "";
    systemData->DeleteAddedPrinter(printerId, printerName);
    EXPECT_EQ(systemData->addedPrinterMap_.GetKeyList().size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0053_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    std::string printerAlias = "1234";
    systemData->UpdatePrinterAlias(printerId, printerAlias);

    PrinterInfo printerInfo;
    printerInfo.SetAlias(printerAlias);
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));

    bool ret = systemData->UpdatePrinterAlias(printerId, "");
    EXPECT_EQ(ret, true);

    systemData->UpdatePrinterAlias(printerId, printerAlias);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0054_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId1 = "1";
    PrinterInfo printerInfo1;
    systemData->addedPrinterMap_.Insert(printerId1, std::make_shared<PrinterInfo>(printerInfo1));
    systemData->CheckPrinterBusy(printerId1);

    std::string printerId2 = "2";
    PrinterInfo printerInfo2;
    printerInfo2.SetPrinterStatus(PRINTER_STATUS_BUSY);
    systemData->addedPrinterMap_.Insert(printerId2, std::make_shared<PrinterInfo>(printerInfo2));
    bool ret = systemData->CheckPrinterBusy(printerId2);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0055_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0056_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    std::vector<uint32_t> supportedColorModeList;
    supportedColorModeList.push_back(1);
    printerCapability.SetSupportedColorMode(supportedColorModeList);
    Json::Value capsJson;
    systemData->ConvertSupportedColorModeToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["supportedColorMode"].isNull(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0057_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    std::vector<uint32_t> supportedDuplexModeList;
    supportedDuplexModeList.push_back(1);
    printerCapability.SetSupportedDuplexMode(supportedDuplexModeList);
    Json::Value capsJson;
    systemData->ConvertSupportedDuplexModeToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["supportedDuplexMode"].isNull(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0058_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    std::vector<std::string> supportedMediaTypeList;
    supportedMediaTypeList.push_back("type1");
    printerCapability.SetSupportedMediaType(supportedMediaTypeList);
    Json::Value capsJson;
    systemData->ConvertSupportedMediaTypeToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["supportedMediaType"].isNull(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0059_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability printerCapability;
    std::vector<uint32_t> supportedQualityList;
    supportedQualityList.push_back(1);
    printerCapability.SetSupportedQuality(supportedQualityList);
    Json::Value capsJson;
    systemData->ConvertSupportedQualityToJson(printerCapability, capsJson);
    EXPECT_EQ(capsJson["supportedQuality"].isNull(), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0060_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterInfo info;
    Json::Value printerJson;
    systemData->ConvertInnerJsonToPrinterInfo(printerJson, info);
    printerJson["alias"] = 123;
    printerJson["printerStatus"] = "132";
    printerJson["preferences"] = "123";
    systemData->ConvertInnerJsonToPrinterInfo(printerJson, info);
    printerJson["alias"] = "123";
    printerJson["printerStatus"] = 123;
    Json::Value preferencesJson;
    printerJson["preferences"] = preferencesJson;
    systemData->ConvertInnerJsonToPrinterInfo(printerJson, info);
    EXPECT_EQ(info.GetAlias(), printerJson["alias"].asString());
    EXPECT_EQ(info.GetPrinterStatus(), static_cast<PrinterStatus>(printerJson["printerStatus"].asInt()));
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0061_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0062_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    Json::Value settingJson;
    EXPECT_EQ(systemData->ParsePreviousPreferencesSetting(settingJson, preferences), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0063_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0064_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0065_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0066_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "1234";
    PrinterPreferences preferences;
    preferences.SetBorderless(true);
    systemData->UpdatePrinterPreferences(printerId, preferences);

    PrinterInfo printerInfo;
    printerInfo.SetPreferences(preferences);
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));
    systemData->UpdatePrinterPreferences(printerId, preferences);
    PrinterInfo printer;
    systemData->QueryAddedPrinterInfoByPrinterId(printerId, printer);
    PrinterPreferences preferences1;
    printer.GetPreferences(preferences1);
    EXPECT_EQ(preferences1.GetBorderless(), preferences.GetBorderless());
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0070_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_NONE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0071_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    cap.SetOption("test");
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_NONE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0072_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterPreferences preferences;
    PrinterCapability cap;
    Json::Value optionJson;
    optionJson["key"] = "value";
    cap.SetOption(PrintJsonUtil::WriteString(optionJson));
    EXPECT_EQ(systemData->BuildPrinterPreference(cap, preferences), E_PRINT_NONE);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0073_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0074_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    EXPECT_EQ(systemData->ParseDefaultPageSizeId(cap), "");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0075_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    std::vector<PrintPageSize> supportedPageSize;
    PrintPageSize pageSize1;
    pageSize1.SetId("ISO_A3");
    PrintPageSize pageSize2;
    pageSize2.SetId("ISO_A4");
    supportedPageSize.emplace_back(pageSize1);
    supportedPageSize.emplace_back(pageSize2);
    cap.SetSupportedPageSize(supportedPageSize);
    EXPECT_EQ(systemData->ParseDefaultPageSizeId(cap), "ISO_A3");
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0090_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value jsonObject;
    Json::Value printerListJson;
    jsonObject["printer_list"] = printerListJson;
    EXPECT_EQ(systemData->ParsePrinterPreferencesJson(jsonObject), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0091_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0092_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0093_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0094_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0095_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "testPrinterId";
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    systemData->connectingIpPrinterInfoList_[printerId] = printerInfo;
    EXPECT_EQ(systemData->QueryIpPrinterInfoById(printerId)->GetPrinterId(), printerId);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0096_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    systemData->AddIpPrinterToList(nullptr);
    EXPECT_EQ(systemData->connectingIpPrinterInfoList_.size(), 0);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0097_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    systemData->AddIpPrinterToList(printerInfo);
    EXPECT_EQ(systemData->connectingIpPrinterInfoList_.size(), 1);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0098_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<int32_t> allPrintUserList;
    Json::Value jsonObject;
    EXPECT_EQ(systemData->ParseUserListJsonV1(jsonObject, allPrintUserList), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0099_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<int32_t> allPrintUserList;
    Json::Value jsonObject;
    Json::Value userDataJson;
    jsonObject["print_user_data"] = userDataJson;
    EXPECT_EQ(systemData->ParseUserListJsonV1(jsonObject, allPrintUserList), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0100_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<int32_t> allPrintUserList;
    Json::Value jsonObject;
    Json::Value userDataJson;
    jsonObject["print_user_data"] = userDataJson;
    EXPECT_EQ(systemData->ParseUserListJsonV1(jsonObject, allPrintUserList), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0101_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::vector<int32_t> allPrintUserList;
    Json::Value jsonObject;
    Json::Value userDataJson;
    userDataJson[""] = "user1";
    userDataJson["100"] = "user2";
    jsonObject["print_user_data"] = userDataJson;
    EXPECT_EQ(systemData->ParseUserListJsonV1(jsonObject, allPrintUserList), true);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0102_NeedRename, TestSize.Level1)
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
    printerMapJson.append(item);
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0103_NeedRename, TestSize.Level1)
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
    item["capability"] = capsJson;
    printerMapJson.append(item);
    jsonObject["printer_list"] = printerMapJson;
    EXPECT_EQ(systemData->GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability), false);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_0104_NeedRename, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    std::string printerId = "1234";
    std::string uri = "testUri";
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetUri(uri);
    systemData->UpdatePrinterUri(printerInfo);

    PrinterInfo printerInfo1;
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo1));
    systemData->UpdatePrinterUri(printerInfo);
    PrinterInfo printer;
    systemData->QueryAddedPrinterInfoByPrinterId(printerId, printer);
    EXPECT_EQ(printer.GetUri(), uri);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_GetRawAddedPrinterListFromSystemData_HaveRawPrinter, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);

    std::string printerId = "printer_001";
    std::string printerName = "RAW_Printer";
    std::string printerUri = "ipp://test_printer";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(printerName);
    printerInfo.SetUri(printerUri);

    Json::Value optionJson;
    optionJson["driver"]= "RAW";
    std::string option = PrintJsonUtil::WriteString(optionJson);
    printerInfo.SetOption(option);
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));
    std::vector<std::string> printerNameList;
    systemData->GetRawAddedPrinterListFromSystemData(printerNameList);
    EXPECT_EQ(printerNameList.size(), 1);
    EXPECT_EQ(printerNameList[0], printerName);
}

HWTEST_F(PrintSystemDataTest, PrintSystemDataTest_GetRawAddedPrinterListFromSystemData_NoRawPrinter, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    std::string printerId = "printer_002";
    std::string printerName = "Non_RAW_Printer";
    std::string printerUri = "ipp://test_printer";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(printerName);
    printerInfo.SetUri(printerUri);

    Json::Value optionJson;
    optionJson["driver"] = "ipp";
    std::string option = PrintJsonUtil::WriteString(optionJson);
    printerInfo.SetOption(option);
    systemData->addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));

    std::vector<std::string> printerNameList;
    systemData->GetRawAddedPrinterListFromSystemData(printerNameList);
    EXPECT_EQ(printerNameList.size(), 0);
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceByDefault_WrongTypeValueInJson_HasDefaultPageSizeIdReturnFalse,
    TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capOpt;
    PrinterPreferences printPreferences;
    capOpt["defaultPageSizeId"] = 1;
    capOpt["orientation-requested-default"] = 1;
    capOpt["sides-default"] = 1;
    capOpt["print-quality-default"] = 1;
    capOpt["media-type-default"] = 1;
    capOpt["defaultColorMode"] = 1;
    capOpt["advanceDefault"] = 1;
    systemData->BuildPrinterPreferenceByDefault(capOpt, printPreferences);
    EXPECT_EQ(printPreferences.HasDefaultPageSizeId(), false);
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceByDefault_CorrectValueInJson_GetDefaultPageSizeIdReturnSameValue,
    TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capOpt;
    PrinterPreferences printPreferences;
    capOpt["defaultPageSizeId"] = "ISO_A4";
    capOpt["orientation-requested-default"] = "1";
    capOpt["sides-default"] = "1";
    capOpt["print-quality-default"] = "1";
    capOpt["media-type-default"] = "plain";
    capOpt["defaultColorMode"] = "1";
    capOpt["advanceDefault"] = "1";
    systemData->BuildPrinterPreferenceByDefault(capOpt, printPreferences);
    EXPECT_EQ(printPreferences.GetDefaultPageSizeId(), "ISO_A4");
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceBySupport_SetValue_HasBorderlessReturnTrue, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    PrinterPreferences printPreferences;
    printPreferences.SetDefaultPageSizeId("ISO_A4");
    printPreferences.SetDefaultDuplexMode(0);
    printPreferences.SetDefaultPrintQuality(0);
    printPreferences.SetDefaultMediaType("plain");
    printPreferences.SetDefaultColorMode(0);
    systemData->BuildPrinterPreferenceBySupport(cap, printPreferences);
    EXPECT_EQ(printPreferences.HasBorderless(), true);
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceBySupport_SetCap_HasBorderlessReturnTrue, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    PrinterPreferences printPreferences;
    std::vector<uint32_t> supportedDuplexModeList;
    supportedDuplexModeList.emplace_back(0);
    cap.SetSupportedDuplexMode(supportedDuplexModeList);
    std::vector<uint32_t> supportedQualityList;
    supportedQualityList.emplace_back(0);
    cap.SetSupportedQuality(supportedQualityList);
    std::vector<std::string> supportedMediaTypeList;
    supportedMediaTypeList.emplace_back("plain");
    cap.SetSupportedMediaType(supportedMediaTypeList);
    std::vector<uint32_t> supportedColorModeList;
    supportedColorModeList.emplace_back(0);
    cap.SetSupportedColorMode(supportedColorModeList);
    systemData->BuildPrinterPreferenceBySupport(cap, printPreferences);
    EXPECT_EQ(printPreferences.HasBorderless(), true);
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceByDefault_SetPreferencesValue_GetDefaultPageSizeIdReturnSameValue,
    TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capOpt;
    PrinterPreferences printPreferences;
    printPreferences.SetDefaultPageSizeId("ISO_A5");
    printPreferences.SetDefaultOrientation(PRINT_ORIENTATION_MODE_PORTRAIT);
    printPreferences.SetDefaultDuplexMode(DUPLEX_MODE_LONG_EDGE);
    printPreferences.SetDefaultPrintQuality(PRINT_QUALITY_DRAFT);
    printPreferences.SetDefaultMediaType("photo");
    capOpt["defaultPageSizeId"] = "ISO_A4";
    capOpt["orientation-requested-default"] = "1";
    capOpt["sides-default"] = "1";
    capOpt["print-quality-default"] = "1";
    capOpt["media-type-default"] = "plain";
    capOpt["defaultColorMode"] = "1";
    capOpt["advanceDefault"] = "1";
    systemData->BuildPrinterPreferenceByDefault(capOpt, printPreferences);
    EXPECT_EQ(printPreferences.GetDefaultPageSizeId(), "ISO_A5");
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceByDefault_NullValueInJson_HasDefaultPageSizeIdReturnfalse,
    TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    Json::Value capOpt;
    PrinterPreferences printPreferences;
    systemData->BuildPrinterPreferenceByDefault(capOpt, printPreferences);
    EXPECT_EQ(printPreferences.HasDefaultPageSizeId(), false);
}

HWTEST_F(PrintSystemDataTest, BuildPrinterPreferenceBySupport_NoValueSet_HasBorderlessReturnTrue, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    EXPECT_NE(systemData, nullptr);
    PrinterCapability cap;
    PrinterPreferences printPreferences;
    systemData->BuildPrinterPreferenceBySupport(cap, printPreferences);
    EXPECT_EQ(printPreferences.HasBorderless(), true);
}

HWTEST_F(PrintSystemDataTest, CheckPrinterVersionFile_FileExist_ReturnTrue, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->CheckPrinterVersionFile();
    EXPECT_EQ(systemData->CheckPrinterVersionFile(), true);
}

HWTEST_F(PrintSystemDataTest, AddPrintEvent_ShouldAddNewEvent_WhenPrinterIdNotFound, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->AddPrintEvent("", "test_type", 1);
    systemData->AddPrintEvent("printer1", "", 1);
    systemData->AddPrintEvent("printer1", "test_type", 123);
    auto eventContainer = systemData->printEventMap_.Find("printer1");
    EXPECT_NE(eventContainer, nullptr);
}

HWTEST_F(PrintSystemDataTest, AddPrintEvent_ShouldAddNewEvent_WhenPrinterIdFound, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->AddPrintEvent("printer1", "test_type", 123);
    systemData->AddPrintEvent("printer1", "test_type", 456);
    auto eventContainer = systemData->printEventMap_.Find("printer1");
    EXPECT_NE(eventContainer, nullptr);
}

HWTEST_F(PrintSystemDataTest, ClearPrintEvents_ShouldClearEvents_WhenPrinterIdFound, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->AddPrintEvent("printer1", "test_type", 123);
    systemData->ClearPrintEvents("printer2", "test_type");
    systemData->ClearPrintEvents("printer1", "test_type");
    auto eventContainer = systemData->printEventMap_.Find("printer1");
    EXPECT_NE(eventContainer, nullptr);
}

HWTEST_F(PrintSystemDataTest, AnalyzePrintEvents_ShouldReturnEmptyString_WhenPrinterIdNotFound, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->AddPrintEvent("printer1", "test_type", 123);
    std::string result = systemData->AnalyzePrintEvents("printer2", "test_type");
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintSystemDataTest, AnalyzePrintEvents_ShouldReturnJsonString_WhenPrinterIdFound, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    systemData->AddPrintEvent("printer1", "test_type", 123);
    std::string result = systemData->AnalyzePrintEvents("printer1", "test_type");
    EXPECT_FALSE(result.empty());
}

HWTEST_F(PrintSystemDataTest, ConvertJsonToPrinterInfoTest, TestSize.Level1)
{
    auto systemData = std::make_shared<OHOS::Print::PrintSystemData>();
    Json::Value object;
    object["id"] = "id";
    object["name"] = "name";
    object["uri"] = "uri";
    EXPECT_FALSE(systemData->ConvertJsonToPrinterInfo(object));
    object["maker"] = "maker";
    EXPECT_FALSE(systemData->ConvertJsonToPrinterInfo(object));
    object["selectedDriver"] = "selectedDriver";
    EXPECT_FALSE(systemData->ConvertJsonToPrinterInfo(object));
    PpdInfo ppd;
    ppd.SetPpdInfo("TestManu", "TestNick", "Test.ppd");
    object["selectedDriver"] = ppd.ConvertToJson();
    EXPECT_TRUE(object["selectedDriver"].isObject());
    EXPECT_FALSE(systemData->ConvertJsonToPrinterInfo(object));
}
}  // namespace Print
}  // namespace OHOS
