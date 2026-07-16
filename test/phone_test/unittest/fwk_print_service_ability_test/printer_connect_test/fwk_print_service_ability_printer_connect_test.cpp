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

/**
 * @tc.name: PrintServiceAbilityTest_0008
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC ConnectPrinter
 * @tc.require:
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "1234";
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    service->ConnectPrinter(printerId);
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "1234";
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    service->DisconnectPrinter(printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, GetConnectUriTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    Json::Value option;
    std::string ppdName = "test.ppd";
    std::string ppdData = "ppd";
    info.SetUri("ipp://192.168.1.1:631/ipp/print");
    service->vendorManager.connectingProtocol = "ipp";
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    option["ipp"] = "ipp://192.168.1.1:631/ipp/print";
    info.SetOption(PrintJsonUtil::WriteString(option));
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    service->vendorManager.connectingProtocol = "ipps";
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    option["ipps"] = "ipps:192.168.1.1:12345";
    info.SetOption(PrintJsonUtil::WriteString(option));
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    service->vendorManager.connectingProtocol = "lpd";
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    option["lpd"] = "lpd://192.168.1.1:515/";
    info.SetOption(PrintJsonUtil::WriteString(option));
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    service->vendorManager.connectingProtocol = "socket";
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
    option["socket"] = "socket://192.168.1.1:9100/";
    info.SetOption(PrintJsonUtil::WriteString(option));
    EXPECT_FALSE(service->DoAddPrinterToCups(std::make_shared<PrinterInfo>(info), ppdName, ppdData));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0135_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    EXPECT_EQ(service->TryConnectPrinterByIp(""), E_PRINT_INVALID_PRINTER);
    std::string param = "{\"protocol\":\"ipp\"}";
    EXPECT_EQ(service->TryConnectPrinterByIp(param), E_PRINT_INVALID_PRINTER);
    param = "{\"protocol\":\"ipp\",\"ip\":\"a.b.c.d\"}";
    EXPECT_EQ(service->TryConnectPrinterByIp(param), E_PRINT_INVALID_PRINTER);
    param = "{\"protocol\":\"ipp\",\"ip\":\"1.1.1.1\"}";
    EXPECT_EQ(service->TryConnectPrinterByIp(param), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintServiceAbilityTest_0157
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC ConnectPrinter
 * @tc.require: use old version printerId
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0157_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("1234");
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_INVALID_PRINTER);
    info->SetPrinterId("com.ohos.spooler:mdns://testId");
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_INVALID_PRINTER);
    PrinterInfo printer;
    service->printSystemData_.InsertAddedPrinter(info->GetPrinterId(), printer);
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, ConnectPrinter_UsbPrinterId_InvalidPrinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.ohos.spooler:USB-printer-1";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    service->printSystemData_.AddPrinterToDiscovery(infoPtr);
    EXPECT_EQ(service->ConnectPrinter(info.GetPrinterId()), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, ConnectUsbPrinter_NoMake_InvalidPrinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "printerId";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    service->printSystemData_.AddPrinterToDiscovery(infoPtr);
    EXPECT_EQ(service->ConnectUsbPrinter(printerId), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, ConnectUsbPrinter_HasMake_ServerFailure, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "printerId";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterMake("testMake");
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    service->printSystemData_.AddPrinterToDiscovery(infoPtr);
    EXPECT_EQ(service->ConnectUsbPrinter(printerId), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, ConnectPrinterByIpAndPpdTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string ip = "192.168.1.1";
    std::string protocol = "ipp";
    std::string ppdName = BSUNI_PPD_NAME;
    EXPECT_EQ(service->ConnectPrinterByIpAndPpd("1", protocol, ppdName), E_PRINT_INVALID_PRINTER);
    service->vendorManager.wlanGroupDriver = nullptr;
    EXPECT_EQ(service->ConnectPrinterByIpAndPpd(ip, protocol, ppdName), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, ConnectPrinterByIdAndPpdTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::string printerId = "testId";
    std::string protocol = "ipp";
    std::string ppdName = BSUNI_PPD_NAME;
    EXPECT_EQ(service->ConnectPrinterByIdAndPpd(printerId, protocol, ppdName), E_PRINT_NO_PERMISSION);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->ManualStart();
    EXPECT_EQ(service->ConnectPrinterByIdAndPpd(printerId, protocol, ppdName), E_PRINT_SERVER_FAILURE);
    printerId = "testId:";
    EXPECT_EQ(service->ConnectPrinterByIdAndPpd(printerId, protocol, ppdName), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, RefreshIpPrinterToIdle, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string ip = "1.1.1.1";
    std::string id = "printer";
    PrinterInfo info, ipInfo;
 
    info.SetPrinterId(id);
    info.SetPrinterName(id);
    info.SetPrinterStatus(PRINTER_STATUS_UNAVAILABLE);
 
    ipInfo.SetPrinterId(ip);
    ipInfo.SetPrinterName(ip);
    ipInfo.SetPrinterStatus(PRINTER_STATUS_UNAVAILABLE);
 
    service->printSystemData_.InsertAddedPrinter(id, info);
    service->printSystemData_.InsertAddedPrinter(ip, ipInfo);
 
    service->RefreshIpPrinter();
 
    service->printSystemData_.QueryAddedPrinterInfoByPrinterId(id, info);
    service->printSystemData_.QueryAddedPrinterInfoByPrinterId(ip, ipInfo);
 
    EXPECT_EQ(info.GetPrinterStatus(), PRINTER_STATUS_UNAVAILABLE);
    EXPECT_EQ(ipInfo.GetPrinterStatus(), PRINTER_STATUS_IDLE);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToSystemData_PrinterNotExist_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    PrinterInfo info;
    bool result = service->AddIpPrinterToSystemData(globalVendorName, info);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToSystemData_PrinterExistAndUriEmpty_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    std::string globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, "printer_001");
    auto existingPrinterInfo = std::make_shared<PrinterInfo>();
    existingPrinterInfo->SetPrinterId("printer_001");
    existingPrinterInfo->SetUri("");
    service->printSystemData_.connectingIpPrinterInfoList_[globalPrinterId] = existingPrinterInfo;
    PrinterInfo info;
    info.SetPrinterId("printer_001");
    info.SetUri("");
    bool result = service->AddIpPrinterToSystemData(globalVendorName, info);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToSystemData_PrinterExistAndUriSame_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    std::string globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, "printer_001");
    auto existingPrinterInfo = std::make_shared<PrinterInfo>();
    existingPrinterInfo->SetPrinterId("printer_001");
    existingPrinterInfo->SetUri("ipp://192.168.1.1:631/printers/printer1");
    service->printSystemData_.connectingIpPrinterInfoList_[globalPrinterId] = existingPrinterInfo;
    PrinterInfo info;
    info.SetPrinterId("printer_001");
    info.SetUri("ipp://192.168.1.1:631/printers/printer1");
    bool result = service->AddIpPrinterToSystemData(globalVendorName, info);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToSystemData_UriDifferent_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    std::string globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, "printer_001");
    auto existingPrinterInfo = std::make_shared<PrinterInfo>();
    existingPrinterInfo->SetPrinterId("printer_001");
    existingPrinterInfo->SetUri("ipp://192.168.1.1:631/printers/printer1");
    service->printSystemData_.connectingIpPrinterInfoList_[globalPrinterId] = existingPrinterInfo;
    PrinterInfo info;
    info.SetPrinterId("printer_001");
    info.SetUri("ipp://192.168.1.2:631/printers/printer2");
    bool result = service->AddIpPrinterToSystemData(globalVendorName, info);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyncAddedPrinterUri_PrinterNotInAddedMap_ShouldNotUpdate
 * @tc.desc: Test SyncAddedPrinterUri when printer is not in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: CheckPrinterUriDifferent returns false when printer not found
 */
HWTEST_F(PrintServiceAbilityTest, SyncAddedPrinterUri_PrinterNotInAddedMap_ShouldNotUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");
    info.SetUri("ipp://test.local:631/printers/TestPrinter_001");

    service->SyncAddedPrinterUri(std::make_shared<PrinterInfo>(info));

    auto addedPrinter = service->printSystemData_.GetAddedPrinterMap().Find(globalPrinterId);
    EXPECT_EQ(addedPrinter, nullptr);
}

/**
 * @tc.name: SyncAddedPrinterUri_PrinterInAddedMap_ShouldCheckUriUpdate
 * @tc.desc: Test SyncAddedPrinterUri when printer exists in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: CheckPrinterUriDifferent should be called when printer exists
 */
HWTEST_F(PrintServiceAbilityTest, SyncAddedPrinterUri_PrinterInAddedMap_ShouldCheckUriUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string originalUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(originalUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    PrinterInfo newInfo;
    newInfo.SetPrinterId("TestPrinter_001");
    newInfo.SetPrinterName("TestPrinter_001");
    newInfo.SetUri("ipp://test2.local:631/printers/TestPrinter_001");

    service->SyncAddedPrinterUri(std::make_shared<PrinterInfo>(newInfo));

    auto printerAfterSync = service->printSystemData_.GetAddedPrinterMap().Find(globalPrinterId);
    ASSERT_NE(printerAfterSync, nullptr);
}

/**
 * @tc.name: SyncAddedPrinterUri_PrinterInAddedMapWithSameUri_ShouldNotUpdate
 * @tc.desc: Test SyncAddedPrinterUri when printer has same URI in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: When URI is same, should not trigger update logic
 */
HWTEST_F(PrintServiceAbilityTest, SyncAddedPrinterUri_PrinterInAddedMapWithSameUri_ShouldNotUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string originalUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(originalUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    PrinterInfo newInfo;
    newInfo.SetPrinterId("TestPrinter_001");
    newInfo.SetPrinterName("TestPrinter_001");
    newInfo.SetUri(originalUri);

    service->SyncAddedPrinterUri(std::make_shared<PrinterInfo>(newInfo));

    auto printerAfterSync = service->printSystemData_.GetAddedPrinterMap().Find(globalPrinterId);
    ASSERT_NE(printerAfterSync, nullptr);
    EXPECT_EQ(printerAfterSync->GetUri(), originalUri);
}

/**
 * @tc.name: CheckPrinterUriDifferent_PrinterNotInAddedMap_ShouldReturnFalse
 * @tc.desc: Test CheckPrinterUriDifferent when printer not found in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: Should return false when QueryAddedPrinterInfoByPrinterId fails
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_PrinterNotInAddedMap_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("com.test.ext:TestPrinter_001");
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri("ipp://test.local:631/printers/TestPrinter_001");

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckPrinterUriDifferent_EmptyProtocol_ShouldReturnFalse
 * @tc.desc: Test CheckPrinterUriDifferent when protocol from oldUri is empty
 * @tc.type: FUNC
 * @tc.require: Should return false when getScheme returns empty protocol
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_EmptyProtocol_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri("invalid_uri_without_protocol");
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri("ipp://test.local:631/printers/TestPrinter_001");

    bool result = service->CheckPrinterUriDifferent(printerInfo);
#ifdef PHONE_ISOLATION_ENABLE
    EXPECT_TRUE(result);
#else
    EXPECT_FALSE(result);
#endif
}

/**
 * @tc.name: CheckPrinterUriDifferent_UriChanged_ShouldReturnTrue
 * @tc.desc: Test CheckPrinterUriDifferent when URI is different
 * @tc.type: FUNC
 * @tc.require: Should return true when oldUri differs from newUri
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_UriChanged_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string oldUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(oldUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri("ipp://test2.local:631/printers/TestPrinter_001");

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: CheckPrinterUriDifferent_UriSame_ShouldReturnFalse
 * @tc.desc: Test CheckPrinterUriDifferent when URI is the same
 * @tc.type: FUNC
 * @tc.require: Should return false when oldUri equals newUri
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_UriSame_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string sameUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(sameUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri(sameUri);

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_FALSE(result);
}
#ifdef PHONE_ISOLATION_ENABLE

/**
 * @tc.name: CheckPrinterUriDifferent_MacroEnabled_UriChanged_ShouldReturnTrue
 * @tc.desc: Test CheckPrinterUriDifferent when PHONE_ISOLATION_ENABLE is enabled and URI changed
 * @tc.type: FUNC
 * @tc.require: Should return true when oldUri differs from info->GetUri()
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_MacroEnabled_UriChanged_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string oldUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(oldUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri("ipp://test2.local:631/printers/TestPrinter_001");

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: CheckPrinterUriDifferent_MacroEnabled_UriSame_ShouldReturnFalse
 * @tc.desc: Test CheckPrinterUriDifferent when PHONE_ISOLATION_ENABLE is enabled and URI same
 * @tc.type: FUNC
 * @tc.require: Should return false when oldUri equals info->GetUri()
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_MacroEnabled_UriSame_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string sameUri = "ipp://test.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(sameUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri(sameUri);

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckPrinterUriDifferent_MacroEnabled_ShouldNotModifyInfoUri
 * @tc.desc: Test CheckPrinterUriDifferent when PHONE_ISOLATION_ENABLE is enabled, verify no SetUri side effect
 * @tc.type: FUNC
 * @tc.require: Should not modify printerInfo->Uri when macro is enabled
 */
HWTEST_F(PrintServiceAbilityTest, CheckPrinterUriDifferent_MacroEnabled_ShouldNotModifyInfoUri, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string oldUri = "ipp://test.local:631/printers/TestPrinter_001";
    std::string originalUri = "ipp://test2.local:631/printers/TestPrinter_001";

    auto addedPrinterInfo = std::make_shared<PrinterInfo>();
    addedPrinterInfo->SetPrinterId(globalPrinterId);
    addedPrinterInfo->SetPrinterName("TestPrinter_001");
    addedPrinterInfo->SetUri(oldUri);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, addedPrinterInfo);

    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(globalPrinterId);
    printerInfo->SetPrinterName("TestPrinter_001");
    printerInfo->SetUri(originalUri);

    bool result = service->CheckPrinterUriDifferent(printerInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(printerInfo->GetUri(), originalUri);
}

#endif  // PHONE_ISOLATION_ENABLE

#ifdef REMOTE_SERVICE_ENABLE
HWTEST_F(PrintServiceAbilityTest, ConnectRemotePrinter_nullptr, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "invalid";

    EXPECT_EQ(service->ConnectRemotePrinter(printerId), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, ConnectRemotePrinter_not_added, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetUri("test_uri");

    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_NONE);
    EXPECT_EQ(service->ConnectRemotePrinter(globalId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, ConnectRemotePrinter_printer_added, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetUri("ipp://192.168.1.1:631/printers/test");

    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_NONE);
    service->printSystemData_.addedPrinterMap_.Insert(globalId, std::make_shared<PrinterInfo>(info));
    EXPECT_EQ(service->ConnectRemotePrinter(globalId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, Connectprinter_RemotePrinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    EXPECT_EQ(service->ConnectPrinter(globalId), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_notadded, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetAlias(printerId);
    info.SetUri("ipp://192.168.1.1:631/printers/test");

    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_added, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetAlias(printerId);
    info.SetUri("ipp://192.168.1.1:631/printers/test");

    service->printSystemData_.addedPrinterMap_.Insert(globalId, std::make_shared<PrinterInfo>(info));
    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, AddRemotePrinterInfo_changeAlias, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "id";
    std::string extensionId = REMOTE_EXT_BUNDLE_NAME;
    std::string globalId = PrintUtils::GetGlobalId(extensionId, printerId);

    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerId);
    info.SetAlias(printerId);
    info.SetUri("ipp://192.168.1.1:631/printers/test");

    service->printSystemData_.addedPrinterMap_.Insert(globalId, std::make_shared<PrinterInfo>(info));
    info.SetAlias(globalId);
    EXPECT_EQ(service->AddRemotePrinterInfo(info, extensionId), E_PRINT_NONE);
}
#endif  // REMOTE_SERVICE_ENABLE

}  // namespace Print
}  // namespace OHOS
