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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string extensionId = "com.ohos.spooler:0";
    int32_t userId = service->GetCurrentUserId();
    std::string stateKey = PrintUtils::MakeExtensionStateKey(userId, extensionId);
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = "com.ohos.spooler:0";
    int32_t userId = service->GetCurrentUserId();
    std::string stateKey = PrintUtils::MakeExtensionStateKey(userId, extensionId);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    std::string jobId = "job123";
    auto printJob = std::make_shared<PrintJob>();
    service->queuedJobList_.insert(std::make_pair(jobId, printJob));
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0062_NeedRename, TestSize.Level1)
{
    DelayedSingleton<PrintBMSHelper>::GetInstance()->hasBms = false;
    auto service = PrintServiceAbilityTest::CreateService();
    std::vector<std::string> extensionIds;
    std::string extensionId = "com.ohos.spooler";
    extensionIds.push_back(extensionId);
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
    std::vector<PrintExtensionInfo> extensionInfos;
    service->QueryAllExtension(extensionInfos);
    service->StartDiscoverPrinter(extensionIds);
}

HWTEST_F(PrintServiceAbilityTest, DiscoverBackendPrinters_WhenNotExistUsbDevice_ShouldNull, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrinterInfo> printers;
    service->DiscoverUsbPrinters(printers);
    EXPECT_EQ(printers.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, DiscoverBackendPrinters_WhenNotExistVendorDevice_ShouldNull, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrinterInfo> printers;
    service->DiscoverBackendPrinters(printers);
    EXPECT_EQ(printers.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0130_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    EXPECT_EQ(service->AddPrinterToDiscovery(info), E_PRINT_NONE);
    EXPECT_EQ(service->UpdatePrinterInDiscovery(info), E_PRINT_NONE);
    info.SetPrinterId("1234");
    EXPECT_EQ(service->UpdatePrinterInDiscovery(info), E_PRINT_NONE);

    std::shared_ptr<PrinterInfo> info1 = std::make_shared<PrinterInfo>();
    info1->SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    service->printSystemData_.discoveredPrinterInfoList_[DEFAULT_EXT_PRINTER_ID] = info1;
    EXPECT_EQ(service->RemovePrinterFromDiscovery(DEFAULT_EXT_PRINTER_ID), E_PRINT_NONE);
    EXPECT_EQ(service->RemovePrinterFromDiscovery(DEFAULT_EXT_PRINTER_ID), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, ConnectUsbPrinter_NoDiscoveredPrinter_InvalidPrinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "printerId";
    EXPECT_EQ(service->ConnectUsbPrinter(printerId), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest,
    StartDiscoverPrinter_createUserIdFailed, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();

    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*helper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*helper, QueryAccounts(_))
        .WillRepeatedly(Return(false));
    service->SetHelper(helper);

    EXPECT_EQ(service->GetCurrentUserId(), INVALID_USER_ID);

    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintServiceAbilityTest, PostDiscoveryTaskTest_with_nullptr, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    std::string extensionId = "";
    service->helper_ = nullptr;
    service->PostDiscoveryTask(extensionId);
    EXPECT_EQ(service->helper_, nullptr);
}

HWTEST_F(PrintServiceAbilityTest, PostDiscoveryTaskTest_with_syncMode, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    std::string extensionId = "";
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*helper, IsSyncMode())
        .WillRepeatedly(Return(true));
    service->SetHelper(helper);
    service->PostDiscoveryTask(extensionId);
    EXPECT_NE(service->helper_, nullptr);
}

/**
 * @tc.name: PrintServiceAbilityTest_AddVendorPrinterToDiscovery_SyncAlias_001
 * @tc.desc: Test AddVendorPrinterToDiscovery syncs alias from added printer
 * @tc.type: FUNC
 * @tc.require: When discovering a previously added printer, alias should be synced
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_AddVendorPrinterToDiscovery_SyncAlias_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    std::string expectedAlias = "MyPrinter";
    std::string expectedPrinterName = "TestPrinterName";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    addedPrinter.SetAlias(expectedAlias);
    service->printSystemData_.InsertAddedPrinter(globalId, addedPrinter);

    PrinterInfo discoveredPrinter;
    discoveredPrinter.SetPrinterId(printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, discoveredPrinter));

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalId);
    EXPECT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetPrinterName(), expectedPrinterName);
    EXPECT_TRUE(printerInfo->HasAlias());
    EXPECT_EQ(printerInfo->GetAlias(), expectedAlias);
}

/**
 * @tc.name: PrintServiceAbilityTest_AddVendorPrinterToDiscovery_NoAlias_001
 * @tc.desc: Test AddVendorPrinterToDiscovery when added printer has no alias
 * @tc.type: FUNC
 * @tc.require: When added printer has no alias, discovered printer should not have alias
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_AddVendorPrinterToDiscovery_NoAlias_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    std::string expectedPrinterName = "TestPrinterName";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    service->printSystemData_.InsertAddedPrinter(globalId, addedPrinter);

    PrinterInfo discoveredPrinter;
    discoveredPrinter.SetPrinterId(printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, discoveredPrinter));

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalId);
    EXPECT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetPrinterName(), expectedPrinterName);
    EXPECT_FALSE(printerInfo->HasAlias());
}

/**
 * @tc.name: PrintServiceAbilityTest_UpdateVendorPrinterToDiscovery_SyncAlias_001
 * @tc.desc: Test UpdateVendorPrinterToDiscovery syncs alias from added printer
 * @tc.type: FUNC
 * @tc.require: When updating discovered printer, alias should be synced from added printer
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_UpdateVendorPrinterToDiscovery_SyncAlias_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    std::string expectedAlias = "UpdatedAlias";
    std::string expectedPrinterName = "UpdatedPrinterName";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    addedPrinter.SetAlias(expectedAlias);
    service->printSystemData_.InsertAddedPrinter(globalId, addedPrinter);

    PrinterInfo discoveredPrinter;
    discoveredPrinter.SetPrinterId(printerId);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, discoveredPrinter));

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalId);
    EXPECT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetPrinterName(), expectedPrinterName);
    EXPECT_TRUE(printerInfo->HasAlias());
    EXPECT_EQ(printerInfo->GetAlias(), expectedAlias);
}

/**
 * @tc.name: PrintServiceAbilityTest_AddVendorPrinterToDiscovery_QueryAddedPrinterInfoFailed_001
 * @tc.desc: Test AddVendorPrinterToDiscovery when QueryAddedPrinterInfoByPrinterId fails
 * @tc.type: FUNC
 * @tc.require: When printer is added but QueryAddedPrinterInfoByPrinterId fails, should handle gracefully
 */
HWTEST_F(PrintServiceAbilityTest,
    PrintServiceAbilityTest_AddVendorPrinterToDiscovery_QueryAddedPrinterInfoFailed_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    std::string printerName = "TestPrinterName";
    std::string printerUri = "ipp://192.168.1.1:631/ipp/print";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalId);
    addedPrinter.SetPrinterName(printerName);
    addedPrinter.SetUri(printerUri);
    service->printSystemData_.InsertAddedPrinter(globalId, addedPrinter);

    PrinterInfo discoveredPrinter;
    discoveredPrinter.SetPrinterId(printerId);
    discoveredPrinter.SetPrinterName(printerName);
    discoveredPrinter.SetUri(printerUri);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, discoveredPrinter));

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalId);
    EXPECT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetPrinterId(), globalId);
}

HWTEST_F(PrintServiceAbilityTest, StartDiscovery_NoClearConnect, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->vendorManager.SetConnectingPrinter(IP_AUTO, "testIP");
    service->StartDiscoverPrinter();
    EXPECT_FALSE(service->vendorManager.GetConnectingPrinter().empty());
}

HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_NotUpdateIpPrinter, TestSize.Level1)
{
    std::string printerName = "1.1.1.1";
    std::string discoveryPrinterName = "testname";
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);

    PrinterInfo info;
    info.SetPrinterId(globalId);
    info.SetPrinterName(printerName);
    info.SetPrinterStatus(PRINTER_STATUS_IDLE);

    service->printSystemData_.InsertAddedPrinter(globalId, info);

    info.SetPrinterName(discoveryPrinterName);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalId);
    EXPECT_EQ(printerInfo->GetPrinterName(), discoveryPrinterName);
}

/**
* @tc.name: StartSharedHostDiscovery_PermissionAndListenerTest
* @tc.desc: Test StartSharedHostDiscovery behavior with no permission, invalid parameter, and normal case.
* @tc.type: FUNC
* @tc.require: StartSharedHostDiscovery should check permission and listener registration.
*/
HWTEST_F(PrintServiceAbilityTest, StartSharedHostDiscovery_PermissionAndListenerTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->SetHelper(mockHelper);
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(false));
    EXPECT_EQ(service->StartSharedHostDiscovery(), E_PRINT_NO_PERMISSION);
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(service->StartSharedHostDiscovery(), E_PRINT_INVALID_PARAMETER);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(PRINTER_SHARED_HOST_DISCOVER,
        listener));
    EXPECT_EQ(service->StartSharedHostDiscovery(), E_PRINT_NONE);
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
}

/**
 * @tc.name: RemoveSinglePrinterInfo_DiscoveredNotFound_ShouldReturnFalse
 * @tc.desc: Test RemoveSinglePrinterInfo when printer is not in discovery list
 * @tc.type: FUNC
 * @tc.require: Should return false when QueryDiscoveredPrinterInfoById returns nullptr
 */
HWTEST_F(PrintServiceAbilityTest, RemoveSinglePrinterInfo_DiscoveredNotFound_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.test.ext:TestPrinter_001";
    EXPECT_FALSE(service->RemoveSinglePrinterInfo(printerId));
}

/**
 * @tc.name: HandleNewPrinterDiscovery_PrinterNotAdded_ShouldAddToDiscovery
 * @tc.desc: Test HandleNewPrinterDiscovery when printer not in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: Should add printer to discovery without syncing from added printer
 */
HWTEST_F(PrintServiceAbilityTest, HandleNewPrinterDiscovery_PrinterNotAdded_ShouldAddToDiscovery, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    auto result = service->HandleNewPrinterDiscovery(globalPrinterId, info);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPrinterId(), globalPrinterId);

    auto discoveredPrinter = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(discoveredPrinter, nullptr);
}

/**
 * @tc.name: HandleNewPrinterDiscovery_PrinterIsIpAddress_ShouldNotSync
 * @tc.desc: Test HandleNewPrinterDiscovery when printer name is IP address
 * @tc.type: FUNC
 * @tc.require: Should not sync printer info when printer name is IP address
 */
HWTEST_F(PrintServiceAbilityTest, HandleNewPrinterDiscovery_PrinterIsIpAddress_ShouldNotSync, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string ipPrinterName = "10.0.0.1";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalPrinterId);
    addedPrinter.SetPrinterName(ipPrinterName);
    addedPrinter.SetAlias("TestAlias");
    service->printSystemData_.InsertAddedPrinter(globalPrinterId, addedPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("OriginalName");

    auto result = service->HandleNewPrinterDiscovery(globalPrinterId, info);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: HandleNewPrinterDiscovery_HasAlias_ShouldSyncAlias
 * @tc.desc: Test HandleNewPrinterDiscovery when added printer has alias
 * @tc.type: FUNC
 * @tc.require: Should sync printer name and alias from added printer
 */
HWTEST_F(PrintServiceAbilityTest, HandleNewPrinterDiscovery_HasAlias_ShouldSyncAlias, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string expectedPrinterName = "TestPrinterName";
    std::string expectedAlias = "TestAlias";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalPrinterId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    addedPrinter.SetAlias(expectedAlias);
    service->printSystemData_.InsertAddedPrinter(globalPrinterId, addedPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("OriginalName");

    auto result = service->HandleNewPrinterDiscovery(globalPrinterId, info);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPrinterName(), expectedPrinterName);
    EXPECT_TRUE(result->HasAlias());
    EXPECT_EQ(result->GetAlias(), expectedAlias);
}

/**
 * @tc.name: HandleNewPrinterDiscovery_NoAlias_ShouldNotSetAlias
 * @tc.desc: Test HandleNewPrinterDiscovery when added printer has no alias
 * @tc.type: FUNC
 * @tc.require: Should sync printer name but not set alias
 */
HWTEST_F(PrintServiceAbilityTest, HandleNewPrinterDiscovery_NoAlias_ShouldNotSetAlias, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string globalPrinterId = "com.test.ext:TestPrinter_001";
    std::string expectedPrinterName = "TestPrinterName";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalPrinterId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    service->printSystemData_.InsertAddedPrinter(globalPrinterId, addedPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("OriginalName");

    auto result = service->HandleNewPrinterDiscovery(globalPrinterId, info);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPrinterName(), expectedPrinterName);
    EXPECT_FALSE(result->HasAlias());
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_NewPrinter_ShouldAddToDiscovery
 * @tc.desc: Test AddVendorPrinterToDiscovery when printer not in discovery list
 * @tc.type: FUNC
 * @tc.require: Should call HandleNewPrinterDiscovery for new printer
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_NewPrinter_ShouldAddToDiscovery, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, info);
    EXPECT_TRUE(result);

    std::string globalPrinterId = vendorName + ":" + info.GetPrinterId();
    auto discoveredPrinter = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(discoveredPrinter, nullptr);
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_ExistingPrinter_ShouldUpdateState
 * @tc.desc: Test AddVendorPrinterToDiscovery when printer already in discovery list
 * @tc.type: FUNC
 * @tc.require: Should update existing printer state without calling HandleNewPrinterDiscovery
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_ExistingPrinter_ShouldUpdateState, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string globalPrinterId = vendorName + ":TestPrinter_001";

    auto existingPrinter = std::make_shared<PrinterInfo>();
    existingPrinter->SetPrinterId(globalPrinterId);
    existingPrinter->SetPrinterName("TestPrinter_001");
    service->printSystemData_.AddPrinterToDiscovery(existingPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_PrinterNotAdded_ShouldNotSync
 * @tc.desc: Test AddVendorPrinterToDiscovery when printer not in addedPrinterMap
 * @tc.type: FUNC
 * @tc.require: Should not sync printer info when printer not added
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_PrinterNotAdded_ShouldNotSync, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_PrinterBusy_ShouldNotSync
 * @tc.desc: Test AddVendorPrinterToDiscovery when printer is busy
 * @tc.type: FUNC
 * @tc.require: Should not sync printer info when printer is busy
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_PrinterBusy_ShouldNotSync, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string globalPrinterId = vendorName + ":TestPrinter_001";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalPrinterId);
    addedPrinter.SetPrinterName("TestPrinter_001");
    addedPrinter.SetPrinterStatus(PRINTER_STATUS_BUSY);
    service->printSystemData_.InsertAddedPrinter(globalPrinterId, addedPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_CanSyncPrinterInfo_ShouldSync
 * @tc.desc: Test AddVendorPrinterToDiscovery when can sync printer info from added printer
 * @tc.type: FUNC
 * @tc.require: Should sync printer info when printer added and not busy and not IP address
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_CanSyncPrinterInfo_ShouldSync, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string globalPrinterId = vendorName + ":TestPrinter_001";
    std::string expectedPrinterName = "SyncedPrinterName";

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId(globalPrinterId);
    addedPrinter.SetPrinterName(expectedPrinterName);
    service->printSystemData_.InsertAddedPrinter(globalPrinterId, addedPrinter);

    PrinterInfo info;
    info.SetPrinterId("TestPrinter_001");
    info.SetPrinterName("TestPrinter_001");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_InvalidIpType_ShouldSkipUriUpdate
 * @tc.desc: Test AddVendorPrinterToDiscovery when info IP type is invalid
 * @tc.type: FUNC
 * @tc.require: URI update should be skipped when IP type is invalid
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_InvalidIpType_ShouldSkipUriUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string printerId = "TestPrinter_001";
    std::string globalPrinterId = vendorName + ":" + printerId;

    PrinterInfo info;
    info.SetPrinterId(globalPrinterId);
    info.SetPrinterName("TestPrinter_001");
    info.SetUri("ipp://test.local:631/printers/TestPrinter_001");
    info.SetOption("test-option");

    service->printSystemData_.AddPrinterToDiscovery(std::make_shared<PrinterInfo>(info));

    PrinterInfo updatedInfo;
    updatedInfo.SetPrinterId(printerId);
    updatedInfo.SetPrinterName("TestPrinter_001");
    updatedInfo.SetUri("ipp://another-host.local:631/printers/TestPrinter_001");
    updatedInfo.SetOption("updated-option");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, updatedInfo);
    EXPECT_TRUE(result);

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetUri(), "ipp://test.local:631/printers/TestPrinter_001");
    EXPECT_EQ(printerInfo->GetOption(), "test-option");
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_Ipv6ToIpv4_ShouldSkipUriUpdate
 * @tc.desc: Test AddVendorPrinterToDiscovery when info is IPv6 and printerInfo is IPv4
 * @tc.type: FUNC
 * @tc.require: URI update should be skipped when IPv6 tries to downgrade to IPv4
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_Ipv6ToIpv4_ShouldSkipUriUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string printerId = "TestPrinter_001";
    std::string globalPrinterId = vendorName + ":" + printerId;

    PrinterInfo existingInfo;
    existingInfo.SetPrinterId(globalPrinterId);
    existingInfo.SetPrinterName("TestPrinter_001");
    existingInfo.SetUri("ipp://192.168.1.100:631/printers/TestPrinter_001");
    existingInfo.SetOption("ipv4-option");

    service->printSystemData_.AddPrinterToDiscovery(std::make_shared<PrinterInfo>(existingInfo));

    PrinterInfo ipv6Info;
    ipv6Info.SetPrinterId(printerId);
    ipv6Info.SetPrinterName("TestPrinter_001");
    ipv6Info.SetUri("ipp://[2001:db8::1]:631/printers/TestPrinter_001");
    ipv6Info.SetOption("ipv6-option");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, ipv6Info);
    EXPECT_TRUE(result);

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetUri(), "ipp://192.168.1.100:631/printers/TestPrinter_001");
    EXPECT_EQ(printerInfo->GetOption(), "ipv4-option");
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_Ipv4ToIpv4_ShouldUpdateUri
 * @tc.desc: Test AddVendorPrinterToDiscovery when both info and printerInfo are IPv4
 * @tc.type: FUNC
 * @tc.require: URI should be updated when both are IPv4
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_Ipv4ToIpv4_ShouldUpdateUri, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string printerId = "TestPrinter_001";
    std::string globalPrinterId = vendorName + ":" + printerId;

    PrinterInfo existingInfo;
    existingInfo.SetPrinterId(globalPrinterId);
    existingInfo.SetPrinterName("TestPrinter_001");
    existingInfo.SetUri("ipp://192.168.1.50:631/printers/TestPrinter_001");
    existingInfo.SetOption("old-option");

    service->printSystemData_.AddPrinterToDiscovery(std::make_shared<PrinterInfo>(existingInfo));

    PrinterInfo newInfo;
    newInfo.SetPrinterId(printerId);
    newInfo.SetPrinterName("TestPrinter_001");
    newInfo.SetUri("ipp://192.168.1.100:631/printers/TestPrinter_001");
    newInfo.SetOption("new-option");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, newInfo);
    EXPECT_TRUE(result);

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetUri(), "ipp://192.168.1.100:631/printers/TestPrinter_001");
    EXPECT_EQ(printerInfo->GetOption(), "new-option");
}

/**
 * @tc.name: AddVendorPrinterToDiscovery_Ipv4ToInvalid_ShouldSkipUriUpdate
 * @tc.desc: Test AddVendorPrinterToDiscovery when printerInfo is IPv4 and info is invalid (hostname)
 * @tc.type: FUNC
 * @tc.require: URI update should be skipped when info is invalid
 */
HWTEST_F(PrintServiceAbilityTest, AddVendorPrinterToDiscovery_Ipv4ToInvalid_ShouldSkipUriUpdate, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    std::string vendorName = "com.test.ext";
    std::string printerId = "TestPrinter_001";
    std::string globalPrinterId = vendorName + ":" + printerId;

    PrinterInfo existingInfo;
    existingInfo.SetPrinterId(globalPrinterId);
    existingInfo.SetPrinterName("TestPrinter_001");
    existingInfo.SetUri("ipp://192.168.1.100:631/printers/TestPrinter_001");
    existingInfo.SetOption("ipv4-option");

    service->printSystemData_.AddPrinterToDiscovery(std::make_shared<PrinterInfo>(existingInfo));

    PrinterInfo hostnameInfo;
    hostnameInfo.SetPrinterId(printerId);
    hostnameInfo.SetPrinterName("TestPrinter_001");
    hostnameInfo.SetUri("ipp://hostname.local:631/printers/TestPrinter_001");
    hostnameInfo.SetOption("hostname-option");

    bool result = service->AddVendorPrinterToDiscovery(vendorName, hostnameInfo);
    EXPECT_TRUE(result);

    auto printerInfo = service->printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    ASSERT_NE(printerInfo, nullptr);
    EXPECT_EQ(printerInfo->GetUri(), "ipp://192.168.1.100:631/printers/TestPrinter_001");
    EXPECT_EQ(printerInfo->GetOption(), "ipv4-option");
}

}  // namespace Print
}  // namespace OHOS
