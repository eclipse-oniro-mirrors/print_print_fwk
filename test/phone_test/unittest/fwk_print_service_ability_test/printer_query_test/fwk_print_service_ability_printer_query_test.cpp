/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "print_service_ability_test_common.h"

namespace OHOS {
namespace Print {

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0022_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "1234";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    EXPECT_EQ(service->printSystemData_.QueryDiscoveredPrinterInfoById(printerId), info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0031_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0032_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    keyList.push_back("printerId");
    keyList.push_back("printerName");
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0033_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    printerInfo->SetAlias("testAlias");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0045_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerUri = "111.222.333";
    std::string printerId = "pixlab_0759";
    PrinterCapability printerCaps;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0064_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    PrinterCapability caps;
    Json::Value opsJson;
    opsJson["key"] = "value";
    caps.SetOption(PrintJsonUtil::WriteString(opsJson));
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    caps.SetSupportedPageSize(pageSizeList);
    printerInfo->SetCapability(caps);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0065_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0066_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    std::string savePrinterPreference = "test";
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0067_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0068_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0069_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterCapability printerCaps;
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    service->printSystemData_.discoveredPrinterInfoList_["123"] = nullptr;
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_["456"] = printerInfo;
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0087_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "1234";
    auto ret = service->QueryPrinterCapability(printerId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    ret = service->QueryPrinterCapability(printerId);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0126_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerName = "testPrinterName";
    EXPECT_EQ(service->printSystemData_.QueryPrinterIdByStandardizeName(printerName), "");
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0128_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "Pixlab_0759";
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0131_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrinterInSystem_EnterpriseManagePrintPermission, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->helper_ = mockHelper;
    
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly([](const std::string &permission) {
            if (permission == PERMISSION_NAME_ENTERPRISE_MANAGE_PRINT) {
                return true;
            }
            return false;
        });
    
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0140_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "testPrinterId";
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0141_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:testPrinterId";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    service->printSystemData_.AddPrinterToDiscovery(infoPtr);
    std::string extensionId = "com.huawei.hmos.spooler";
    EXPECT_EQ(service->AddSinglePrinterInfo(info, extensionId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0144_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.huawei.hmos.spooler:testPrinterId";
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, QueryPrinterCapabilityByUri_WhenHasMake_ShouldSucc, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    info->SetPrinterMake("test");
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    // success call to cupsd but response is nothing
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, QueryPrinterCapabilityByUri_WhenNotHasMake_ShouldFailed, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0147_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    Json::Value opsJson;
    opsJson["key"] = "value";
    info->SetOption(PrintJsonUtil::WriteString(opsJson));
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0148_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    Json::Value opsJson;
    opsJson["make"] = 123;
    info->SetOption(PrintJsonUtil::WriteString(opsJson));
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0149_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "testPrinterId";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0150_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_QueryRawAddedPrinter_EmptyList, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryRawAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_QueryRawAddedPrinter_Success, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerlist;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "testPrinterId";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryRawAddedPrinter(printerlist), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_QueryRawAddedPrinter_EmptyId, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryRawAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, QueryInfoByIpTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->vendorManager.wlanGroupDriver = nullptr;

    EXPECT_EQ(service->QueryPrinterInfoByIp(""), E_PRINT_INVALID_PRINTER);
    std::string ip = "192.168.1.1";
    EXPECT_EQ(service->QueryPrinterInfoByIp(ip), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(service->QueryPrinterInfoByIp(ip), E_PRINT_NONE);
    PrinterInfo info;
    info.SetPrinterId(ip);

    service->OnQueryCallBackEvent(info);
    EXPECT_EQ(service->QueryPrinterInfoByIp(ip), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, QueryRecommendDriversByIdTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::string printerId = "testId";
    std::vector<PpdInfo> ppds;
    EXPECT_EQ(service->QueryRecommendDriversById(printerId, ppds), E_PRINT_NO_PERMISSION);
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockHelper, QueryAccounts(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int>{100}), Return(true)));
    service->SetHelper(mockHelper);
    EXPECT_EQ(service->QueryRecommendDriversById(printerId, ppds), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest,
    ReportPrinterIdle_PrinterBusy, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string id = "test";
    PrinterInfo info, printer;
    info.SetPrinterId(id);
    info.SetPrinterStatus(PRINTER_STATUS_BUSY);
    service->printSystemData_.InsertAddedPrinter(id, info);
    service->ReportPrinterIdle(id);
    service->printSystemData_.QueryAddedPrinterInfoByPrinterId(id, printer);
    EXPECT_EQ(printer.GetPrinterStatus(), PRINTER_STATUS_IDLE);
}

HWTEST_F(PrintServiceAbilityTest,
    ReportPrinterIdle_Unavailable, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string id = "test";
    PrinterInfo info, printer;
    info.SetPrinterId(id);
    info.SetPrinterStatus(PRINTER_STATUS_UNAVAILABLE);
    service->printSystemData_.InsertAddedPrinter(id, info);
    service->ReportPrinterIdle(id);
    service->printSystemData_.QueryAddedPrinterInfoByPrinterId(id, printer);
    EXPECT_EQ(printer.GetPrinterStatus(), PRINTER_STATUS_UNAVAILABLE);
}

HWTEST_F(PrintServiceAbilityTest, QueryAddedPrintersByOriginId_ShouldReturnEmpty, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto printers = service->QueryAddedPrintersByOriginId("");
    EXPECT_EQ(printers.empty(), true);
}

/**
* @tc.name: UpdateSinglePrinterInfo_InvalidPrinterId
* @tc.desc: Test UpdateSinglePrinterInfo with invalid printer id
* @tc.type: FUNC
* @tc.require: Should return false
*/
HWTEST_F(PrintServiceAbilityTest, UpdateSinglePrinterInfo_InvalidPrinterId, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    
    std::string extensionId = DEFAULT_EXTENSION_ID;
    std::string printerId = "invalid printer id";

    PrinterInfo info;
    info.SetPrinterName("TestPrinter");
    info.SetPrinterMake("TestMake");
    info.SetPrinterId(printerId);
    bool result = service->UpdateSinglePrinterInfo(info, extensionId);
    
    EXPECT_FALSE(result);
}

/**
* @tc.name: UpdateSinglePrinterInfo_HasPrinterMake_QueryPPDInformationReturnsEmpty
* @tc.desc: Test UpdateSinglePrinterInfo when printer does not have make
* @tc.type: FUNC
* @tc.require: Should skip PPD capability query
*/
HWTEST_F(PrintServiceAbilityTest,
    UpdateSinglePrinterInfo_HasPrinterMake_QueryPPDInformationReturnsEmpty, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string extensionId = DEFAULT_EXTENSION_ID;
    std::string printerId = DEFAULT_EXT_PRINTER_ID;

    auto info = std::make_shared<PrinterInfo>();
    EXPECT_NE(info, nullptr);
    info->SetPrinterId(printerId);

    service->printSystemData_.AddPrinterToDiscovery(info);

    bool result = service->UpdateSinglePrinterInfo(*info, extensionId);
    
    EXPECT_FALSE(result);
}

/**
* @tc.name: UpdatePrinterInSystem_EmptyPrinterInfo
* @tc.desc: Test UpdatePrinterInSystem with empty printer info
* @tc.type: FUNC
* @tc.require: UpdatePrinterInSystem should return E_PRINT_INVALID_PRINTER when printer info is empty
*/
HWTEST_F(PrintServiceAbilityTest, UpdatePrinterInSystem_EmptyPrinterInfo, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->helper_ = mockHelper;
    
    PrinterInfo info;
    
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrinterInSystem_UpdateAliasAndOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->SetHelper(mockHelper);
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));

    std::string printerId = "com.example.ext:TestPrinter";
    PrinterInfo addedInfo;
    addedInfo.SetPrinterId(printerId);
    addedInfo.SetPrinterName("TestPrinter");
    addedInfo.SetAlias("OldAlias");
    service->printSystemData_.InsertAddedPrinter(printerId, addedInfo);

    auto discoveredInfo = std::make_shared<PrinterInfo>(addedInfo);
    service->printSystemData_.AddPrinterToDiscovery(discoveredInfo);

    PrinterInfo updateInfo;
    updateInfo.SetPrinterId(printerId);
    updateInfo.SetAlias("NewAlias");
    updateInfo.SetOption("NewOption");

    EXPECT_EQ(service->UpdatePrinterInSystem(updateInfo), E_PRINT_NONE);

    auto queriedDiscovered = service->printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    EXPECT_NE(queriedDiscovered, nullptr);
    EXPECT_EQ(queriedDiscovered->GetAlias(), "NewAlias");

    PrinterInfo queriedAdded;
    EXPECT_TRUE(service->printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, queriedAdded));
    EXPECT_EQ(queriedAdded.GetAlias(), "NewAlias");
}

/**
* @tc.name: UpdateSinglePrinterInfo_HasPrinterMake_IsEprint
* @tc.desc: Test UpdateSinglePrinterInfo when printer is eprint, should skip PPd query
* @tc.type: FUNC
* @tc.require: should skip PPd query for eprint printer
*/
HWTEST_F(PrintServiceAbilityTest, UpdateSinglePrinterInfo_HasPrinterMake_IsEprint, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).Times(0);

    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterName("TestPrinter");
    std::string eprintPrinterId = PrintUtils::GetGlobalId(PRINT_EXTENSION_BUNDLE_NAME, EPRINTID);
    info->SetPrinterId(eprintPrinterId);
    info->SetPrinterMake("TestMake");
    service->printSystemData_.AddPrinterToDiscovery(info);
    bool result = service->UpdateSinglePrinterInfo(*info, PRINT_EXTENSION_BUNDLE_NAME);
    EXPECT_FALSE(result);
}

/**
* @tc.name: UpdateSinglePrinterInfo_NoPrinterMake_IsEprint
* @tc.desc: Test UpdateSinglePrinterInfo when printer has no make and is eprint
* @tc.type: FUNC
* @tc.require: should skip PPd query
*/
HWTEST_F(PrintServiceAbilityTest, UpdateSinglePrinterInfo_NoPrinterMake_IsEprint, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).Times(0);

    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterName("TestPrinter");
    std::string eprintPrinterId = PrintUtils::GetGlobalId(PRINT_EXTENSION_BUNDLE_NAME, EPRINTID);
    info->SetPrinterId(eprintPrinterId);
    service->printSystemData_.AddPrinterToDiscovery(info);
    bool result = service->UpdateSinglePrinterInfo(*info, PRINT_EXTENSION_BUNDLE_NAME);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RemoveSinglePrinterInfo_AddedPrinter_ShouldSetUnavailable
 * @tc.desc: Test RemoveSinglePrinterInfo when printer is added
 * @tc.type: FUNC
 * @tc.require: Should set PRINTER_STATUS_UNAVAILABLE when printer is added
 */
HWTEST_F(PrintServiceAbilityTest, RemoveSinglePrinterInfo_AddedPrinter_ShouldSetUnavailable, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.test.ext:TestPrinter_001";

    auto discoveredInfo = std::make_shared<PrinterInfo>();
    discoveredInfo->SetPrinterId(printerId);
    discoveredInfo->SetPrinterName("TestPrinter");
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = discoveredInfo;

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(printerId);
    addedPrinter.SetPrinterName("TestPrinter");
    addedPrinter.SetPrinterStatus(PRINTER_STATUS_IDLE);
    service->printSystemData_.InsertAddedPrinter(printerId, addedPrinter);

    EXPECT_TRUE(service->RemoveSinglePrinterInfo(printerId));

    auto addedInfo = service->printSystemData_.addedPrinterMap_.Find(printerId);
    ASSERT_NE(addedInfo, nullptr);
    EXPECT_EQ(addedInfo->GetPrinterStatus(), PRINTER_STATUS_UNAVAILABLE);
}

/**
* @tc.name: RenamePrinterWhenAdded_ExistingPrinterId_ReturnStoredName
* @tc.desc: When printerId already exists in addedPrinterMap, return the previously stored printer name
* @tc.type: FUNC
* @tc.require: Fix line-4450 bug: should return stored name, not the incoming name
*/
HWTEST_F(PrintServiceAbilityTest, RenamePrinterWhenAdded_ExistingPrinterId_ReturnStoredName, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "fwk.driver.printer.driver.com.example:TestPrinter";
    PrinterInfo existingInfo;
    existingInfo.SetPrinterId(printerId);
    existingInfo.SetPrinterName("StoredDisplayName");
    service->printSystemData_.InsertAddedPrinter(printerId, existingInfo);

    PrinterInfo newInfo;
    newInfo.SetPrinterId(printerId);
    newInfo.SetPrinterName("NewDifferentName");
    std::string result = service->RenamePrinterWhenAdded(newInfo);
    EXPECT_EQ(result, "StoredDisplayName");
}

/**
* @tc.name: RenamePrinterWhenAdded_NoConflict_ReturnOriginalName
* @tc.desc: When no name conflict exists, return the original printer name unchanged
* @tc.type: FUNC
* @tc.require: Normal case with no existing printers
*/
HWTEST_F(PrintServiceAbilityTest, RenamePrinterWhenAdded_NoConflict_ReturnOriginalName, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    info.SetPrinterId("fwk.driver.printer.driver.com.example:NewPrinter");
    info.SetPrinterName("NewPrinter");
    std::string result = service->RenamePrinterWhenAdded(info);
    EXPECT_EQ(result, "NewPrinter");
}

/**
* @tc.name: RenamePrinterWhenAdded_ExactNameConflict_AppendSuffix
* @tc.desc: When an exact display name conflict exists, append numeric suffix
* @tc.type: FUNC
* @tc.require: "EPSON L3251" already added, adding another "EPSON L3251" yields "EPSON L3251 1"
*/
HWTEST_F(PrintServiceAbilityTest, RenamePrinterWhenAdded_ExactNameConflict_AppendSuffix, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo existingInfo;
    existingInfo.SetPrinterId("fwk.driver.printer.driver.com.example:EPSON_L3251");
    existingInfo.SetPrinterName("EPSON L3251");
    service->printSystemData_.InsertAddedPrinter(
        "fwk.driver.printer.driver.com.example:EPSON_L3251", existingInfo);

    PrinterInfo newInfo;
    newInfo.SetPrinterId("fwk.driver.printer.driver.com.other:EPSON_L3251");
    newInfo.SetPrinterName("EPSON L3251");
    std::string result = service->RenamePrinterWhenAdded(newInfo);
    EXPECT_EQ(result, "EPSON L3251 1");
}

/**
* @tc.name: RenamePrinterWhenAdded_CrossFormatConflict_AppendSuffix
* @tc.desc: Cross-format name conflict detected via StandardizePrinterName comparison
* @tc.type: FUNC
* @tc.require: "EPSON L3251" standardizes to "EPSON_L3251"; adding "EPSON_L3251" should detect conflict
*/
HWTEST_F(PrintServiceAbilityTest, RenamePrinterWhenAdded_CrossFormatConflict_AppendSuffix, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo existingInfo;
    existingInfo.SetPrinterId("fwk.driver.printer.driver.com.example:EPSON_L3251");
    existingInfo.SetPrinterName("EPSON L3251");
    service->printSystemData_.InsertAddedPrinter(
        "fwk.driver.printer.driver.com.example:EPSON_L3251", existingInfo);

    // "EPSON_L3251" standardizes to same "EPSON_L3251" as "EPSON L3251" -> conflict
    PrinterInfo newInfo;
    newInfo.SetPrinterId("fwk.driver.printer.driver.com.other:EPSON_L3251_v2");
    newInfo.SetPrinterName("EPSON_L3251");
    std::string result = service->RenamePrinterWhenAdded(newInfo);
    EXPECT_EQ(result, "EPSON_L3251 1");
}

/**
 * @tc.name: SetPrinterCapabilityAndRegister_QueryPPDFailed_Error
 * @tc.desc: QueryPrinterCapabilityFromPPD returns error propagates error
 * @tc.type: FUNC
 * @tc.require: PPD capability query failure handling
 */
HWTEST_F(PrintServiceAbilityTest, SetPrinterCapabilityAndRegister_QueryPPDFailed_Error, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrinterCapabilityFromPPD(_, _, _)).WillOnce(Return(E_PRINT_GENERIC_FAILURE));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("test_printer_id");
    printerInfo->SetPrinterName("TestPrinter");
    int32_t ret = service->SetPrinterCapabilityAndRegister(
        "TestPrinter", "valid.ppd", "test_printer_id", printerInfo);
    EXPECT_EQ(ret, E_PRINT_GENERIC_FAILURE);
}

/**
 * @tc.name: SetPrinterCapabilityAndRegister_ParseJsonFailed_Error
 * @tc.desc: Parse JSON option fails returns E_PRINT_GENERIC_FAILURE
 * @tc.type: FUNC
 * @tc.require: JSON parsing failure handling when extracting make from capability
 */
HWTEST_F(PrintServiceAbilityTest, SetPrinterCapabilityAndRegister_ParseJsonFailed_Error, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    PrinterCapability printerCaps;
    printerCaps.SetOption("invalid json");
    EXPECT_CALL(*service, QueryPrinterCapabilityFromPPD(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerCaps), Return(E_PRINT_NONE)));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("test_printer_id");
    printerInfo->SetPrinterName("TestPrinter");
    printerInfo->SetPrinterMake("");
    int32_t ret = service->SetPrinterCapabilityAndRegister(
        "TestPrinter", "valid.ppd", "test_printer_id", printerInfo);
    EXPECT_EQ(ret, E_PRINT_GENERIC_FAILURE);
}

/**
 * @tc.name: SetPrinterCapabilityAndRegister_FindMakeFailed_Error
 * @tc.desc: FindJsonStringMember fails to find make returns E_PRINT_GENERIC_FAILURE
 * @tc.type: FUNC
 * @tc.require: JSON member extraction failure handling
 */
HWTEST_F(PrintServiceAbilityTest, SetPrinterCapabilityAndRegister_FindMakeFailed_Error, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    PrinterCapability printerCaps;
    printerCaps.SetOption("{\"no_make\":\"value\"}");
    EXPECT_CALL(*service, QueryPrinterCapabilityFromPPD(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerCaps), Return(E_PRINT_NONE)));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("test_printer_id");
    printerInfo->SetPrinterName("TestPrinter");
    printerInfo->SetPrinterMake("");
    int32_t ret = service->SetPrinterCapabilityAndRegister(
        "TestPrinter", "valid.ppd", "test_printer_id", printerInfo);
    EXPECT_EQ(ret, E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_withoutUri, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
 
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetAlias(printerId);
 
    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_INVALID_PRINTER);
}
 
HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_uriMatch, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId1 = "device1";
    std::string printerId2 = "device2";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId1 = PrintUtils::GetGlobalId(extensionId, printerId1);
    std::string uri = "test_uri";
 
    PrinterInfo existingPrinter;
    existingPrinter.SetPrinterId(printerId1);
    existingPrinter.SetPrinterName(printerId1);
    existingPrinter.SetAlias(printerId1);
    existingPrinter.SetUri(uri);
    existingPrinter.SetDeviceId(printerId1);
 
    service->printSystemData_.addedPrinterMap_.Insert(globalId1, std::make_shared<PrinterInfo>(existingPrinter));
 
    PrinterInfo newPrinter;
    newPrinter.SetPrinterId(printerId2);
    newPrinter.SetPrinterName(printerId2);
    newPrinter.SetAlias(printerId2);
    newPrinter.SetUri(uri);
    newPrinter.SetDeviceId(printerId2);
 
    EXPECT_EQ(service->AddRemotePrinterInfo(newPrinter, extensionId), E_PRINT_NONE);
}
 
HWTEST_F(PrintServiceAbilityTest, PrinterInfo_deviceId, TestSize.Level1)
{
    PrinterInfo info;
    
    std::string deviceId = "test_device_id";
    info.SetDeviceId(deviceId);
    EXPECT_EQ(info.GetDeviceId(), deviceId);
 
    std::string emptyDeviceId = "";
    info.SetDeviceId(emptyDeviceId);
    EXPECT_EQ(info.GetDeviceId(), emptyDeviceId);
}
 
HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_uriMatch_changeAlias, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId1 = "device1";
    std::string printerId2 = "device2";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId1 = PrintUtils::GetGlobalId(extensionId, printerId1);
    std::string uri = "test_uri";
 
    PrinterInfo existingPrinter;
    existingPrinter.SetPrinterId(printerId1);
    existingPrinter.SetPrinterName(printerId1);
    existingPrinter.SetAlias("old_alias");
    existingPrinter.SetUri(uri);
    existingPrinter.SetDeviceId(printerId1);
 
    service->printSystemData_.addedPrinterMap_.Insert(globalId1, std::make_shared<PrinterInfo>(existingPrinter));
 
    PrinterInfo newPrinter;
    newPrinter.SetPrinterId(printerId2);
    newPrinter.SetPrinterName(printerId2);
    newPrinter.SetAlias("new_alias");
    newPrinter.SetUri(uri);
    newPrinter.SetDeviceId(printerId2);
 
    EXPECT_EQ(service->AddRemotePrinterInfo(newPrinter, extensionId), E_PRINT_NONE);
}
 
HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_uriNotMatch, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId1 = "device1";
    std::string printerId2 = "device2";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId1 = PrintUtils::GetGlobalId(extensionId, printerId1);
 
    PrinterInfo existingPrinter;
    existingPrinter.SetPrinterId(printerId1);
    existingPrinter.SetPrinterName(printerId1);
    existingPrinter.SetAlias(printerId1);
    existingPrinter.SetUri("uri1");
    existingPrinter.SetDeviceId(printerId1);
 
    service->printSystemData_.addedPrinterMap_.Insert(globalId1, std::make_shared<PrinterInfo>(existingPrinter));
 
    PrinterInfo newPrinter;
    newPrinter.SetPrinterId(printerId2);
    newPrinter.SetPrinterName(printerId2);
    newPrinter.SetAlias(printerId2);
    newPrinter.SetUri("uri2");
    newPrinter.SetDeviceId(printerId2);
 
    EXPECT_EQ(service->AddRemotePrinterInfo(newPrinter, extensionId), E_PRINT_NONE);
}
 
HWTEST_F(PrintServiceAbilityTest, MatchPrinterByUri_success, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId = "device1";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);
    std::string uri = "test_uri";
 
    PrinterInfo existingPrinter;
    existingPrinter.SetPrinterId(printerId);
    existingPrinter.SetPrinterName(printerId);
    existingPrinter.SetUri(uri);
 
    service->printSystemData_.addedPrinterMap_.Insert(globalId, std::make_shared<PrinterInfo>(existingPrinter));
 
    std::string matchedPrinterId;
    PrinterInfo matchedPrinter;
    EXPECT_TRUE(service->MatchPrinterByUri(uri, matchedPrinterId, matchedPrinter));
    EXPECT_EQ(matchedPrinterId, globalId);
}
 
HWTEST_F(PrintServiceAbilityTest, MatchPrinterByUri_notFound, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string uri = "test_uri";
    std::string matchedPrinterId;
    PrinterInfo matchedPrinter;
    EXPECT_FALSE(service->MatchPrinterByUri(uri, matchedPrinterId, matchedPrinter));
}
 
HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobOptionByPrinterId_withDeviceId, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
 
    std::string printerId = "device1";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);
    std::string deviceId = "test_device_id";
 
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("printer");
    printerInfo.SetUri("uri");
    printerInfo.SetDeviceId(deviceId);
 
    service->printSystemData_.addedPrinterMap_.Insert(globalId, std::make_shared<PrinterInfo>(printerInfo));
 
    PrintJob printJob;
    printJob.SetPrinterId(globalId);
    printJob.SetOption("{}");
 
    EXPECT_TRUE(service->UpdatePrintJobOptionByPrinterId(printJob));
    EXPECT_NE(printJob.GetOption().find(deviceId), std::string::npos);
}

}  // namespace Print
}  // namespace OHOS
