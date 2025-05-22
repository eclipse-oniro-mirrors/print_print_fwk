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
#define private public
#include "vendor_manager.h"
#undef private
#include "vendor_ppd_driver.h"
#include "print_constant.h"
#include "print_log.h"
#include "vendor_ipp_everywhere.h"
#include "mock/mock_print_service_ability.h"
#include "mock/mock_vendor_ppd_driver.h"

using namespace testing;
using namespace testing::ext;

namespace {
const int WAIT_TIME_MS = 100;
const std::string PRINTER_TEST_IP = "192.168.2.222";
}

namespace OHOS {
namespace Print {
class VendorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VendorManagerTest::SetUpTestCase(void) {}

void VendorManagerTest::TearDownTestCase(void) {}

void VendorManagerTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorManagerTest_%{public}d", ++testNo);
}

void VendorManagerTest::TearDown(void) {}

HWTEST_F(VendorManagerTest, VendorManagerTest_0001, TestSize.Level0)
{
    std::string vendorName = "test.vendor";
    std::string printerId = "test.printer.id";
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    EXPECT_STREQ(VendorManager::ExtractVendorName(globalVendorName).c_str(), vendorName.c_str());
    EXPECT_STREQ(VendorManager::ExtractGlobalVendorName(globalPrinterId).c_str(), globalVendorName.c_str());
    EXPECT_STREQ(VendorManager::ExtractPrinterId(globalPrinterId).c_str(), printerId.c_str());
    EXPECT_TRUE(VendorManager::ExtractPrinterId("").empty());
    EXPECT_TRUE(VendorManager::ExtractGlobalVendorName("").empty());
    EXPECT_TRUE(VendorManager::ExtractVendorName("").empty());
    EXPECT_STREQ(VendorManager::ExtractPrinterId("fwk.test:").c_str(), "fwk.test:");
    EXPECT_TRUE(VendorManager::ExtractVendorName("test").empty());
    EXPECT_TRUE(VendorManager::ExtractVendorName("fwk.").empty());
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0002, TestSize.Level0)
{
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(nullptr, false));
    EXPECT_TRUE(vendorManager.Init(nullptr, false));
    ThreadSyncWait syncWait;
    vendorManager.StartDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StartStatusMonitor();
    vendorManager.StartStatusMonitor();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopStatusMonitor();
    vendorManager.StopStatusMonitor();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0003, TestSize.Level0)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    ThreadSyncWait syncWait;
    vendorManager.StartDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StartStatusMonitor();
    EXPECT_FALSE(vendorManager.ConnectPrinterByIp(PRINTER_TEST_IP, "ipp"));
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopStatusMonitor();
    EXPECT_FALSE(vendorManager.ConnectPrinterByIp("test", ""));
    EXPECT_FALSE(vendorManager.QueryPrinterInfo("vendor:test", 0));
    EXPECT_FALSE(vendorManager.QueryPrinterInfo("test:", 0));
    EXPECT_FALSE(vendorManager.QueryPrinterInfo(":test", 0));
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0004, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorIppEverywhere = std::make_shared<VendorIppEveryWhere>();
    ASSERT_NE(vendorIppEverywhere, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorIppEverywhere));
    ThreadSyncWait syncWait;
    std::string vendorName = vendorIppEverywhere->GetVendorName();
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    vendorManager.StartDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StartStatusMonitor();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.MonitorPrinterStatus(globalPrinterId, true);
    vendorManager.MonitorPrinterStatus(globalPrinterId, true);
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_CALL(*mock, QueryPrinterCapabilityByUri(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, QueryPrinterStatusByUri(_, _)).WillRepeatedly(Return(true));
    EXPECT_TRUE(vendorManager.ConnectPrinterByIp(PRINTER_TEST_IP, "ipp"));
    EXPECT_FALSE(vendorManager.ConnectPrinter(PRINTER_TEST_IP));
    EXPECT_FALSE(vendorManager.ConnectPrinter(globalPrinterId));
    EXPECT_TRUE(vendorManager.QueryPrinterInfo(globalPrinterId, 0));
    vendorManager.UpdateAllPrinterStatus();
    vendorManager.MonitorPrinterStatus(globalPrinterId, false);
    vendorManager.MonitorPrinterStatus(globalPrinterId, false);
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StopStatusMonitor();
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.UnloadVendorDriver(vendorName);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0005, TestSize.Level0)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorIppEverywhere = std::make_shared<VendorIppEveryWhere>();
    ASSERT_NE(vendorIppEverywhere, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorIppEverywhere));
    std::string vendorName = vendorIppEverywhere->GetVendorName();
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    EXPECT_FALSE(vendorManager.IsConnectingPrinter(globalPrinterId, ""));
    vendorManager.SetConnectingPrinter(ConnectMethod::ID_AUTO, "");
    EXPECT_FALSE(vendorManager.IsConnectingPrinter("", ""));
    vendorManager.SetConnectingPrinter(ConnectMethod::ID_AUTO, globalPrinterId);
    EXPECT_TRUE(vendorManager.IsConnectingPrinter(globalPrinterId, ""));
    vendorManager.SetConnectingPrinter(ConnectMethod::IP_AUTO, printerId);
    EXPECT_TRUE(vendorManager.IsConnectingPrinter(globalPrinterId, ""));
    vendorManager.SetConnectingPrinter(ConnectMethod::IP_IPP, printerId);
    EXPECT_FALSE(vendorManager.IsConnectingPrinter(globalPrinterId, ""));
    EXPECT_TRUE(vendorManager.IsConnectingPrinter(globalPrinterId, printerId));
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0006, TestSize.Level1)
{
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(nullptr, false));
    EXPECT_FALSE(vendorManager.LoadVendorDriver(nullptr));
    PrinterInfo printerInfo;
    std::string ppdDriverVendorName = "driver.ppd";
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery("", printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery(ppdDriverVendorName, printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.UpdatePrinterToDiscovery("", printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.RemovePrinterFromDiscovery("", ""), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.AddPrinterToCupsWithPpd("", "", ""), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.AddPrinterToCupsWithPpd(ppdDriverVendorName, "", ""), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.RemovePrinterFromCups("", ""), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_FALSE(vendorManager.OnPrinterPpdQueried("", PRINTER_TEST_IP, "", ""));
    EXPECT_FALSE(vendorManager.MonitorPrinterStatus(":id", true));
    EXPECT_FALSE(vendorManager.MonitorPrinterStatus("fwk.driver:", true));
    EXPECT_FALSE(vendorManager.MonitorPrinterStatus("fwk.:printer.id", true));
    EXPECT_FALSE(vendorManager.MonitorPrinterStatus("fwk.driver:printer.id", true));
    PrinterCapability printerCap;
    EXPECT_FALSE(vendorManager.QueryPrinterCapabilityByUri(PRINTER_TEST_IP, printerCap));
    PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
    EXPECT_FALSE(vendorManager.QueryPrinterStatusByUri(PRINTER_TEST_IP, status));
    PrinterVendorStatus vendorStatus;
    EXPECT_TRUE(vendorManager.OnPrinterStatusChanged("vendor", PRINTER_TEST_IP, vendorStatus));
    EXPECT_FALSE(vendorManager.QueryPrinterInfoByPrinterId("vendor", PRINTER_TEST_IP, printerInfo));
    std::string mekeModel = "test_makeModel";
    std::string ppdName;
    EXPECT_FALSE(vendorManager.QueryPPDInformation(mekeModel, ppdName));
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0007, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorIppEverywhere = std::make_shared<VendorIppEveryWhere>();
    ASSERT_NE(vendorIppEverywhere, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorIppEverywhere));
    std::string vendorName = vendorIppEverywhere->GetVendorName();
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    PrinterInfo printerInfo;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    EXPECT_CALL(*mock, QueryPrinterStatusByUri(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, QueryPrinterCapabilityByUri(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, AddVendorPrinterToCupsWithPpd(_, _, _, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, OnVendorStatusUpdate(_, _, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, RemoveVendorPrinterFromCups(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, QueryPPDInformation(_, _)).WillRepeatedly(Return(true));
    PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
    EXPECT_FALSE(vendorManager.QueryPrinterStatusByUri(PRINTER_TEST_IP, status));
    EXPECT_TRUE(vendorManager.QueryPrinterStatusByUri(PRINTER_TEST_IP, status));
    PrinterCapability printerCap;
    EXPECT_FALSE(vendorManager.QueryPrinterCapabilityByUri(PRINTER_TEST_IP, printerCap));
    EXPECT_TRUE(vendorManager.QueryPrinterCapabilityByUri(PRINTER_TEST_IP, printerCap));
    std::string ppdName;
    std::string ppdData;
    EXPECT_FALSE(vendorManager.OnPrinterPpdQueried(vendorName, PRINTER_TEST_IP, ppdName, ppdData));
    vendorManager.SetConnectingPrinter(ConnectMethod::ID_AUTO, globalPrinterId);
    EXPECT_FALSE(vendorManager.OnPrinterPpdQueried(vendorName, PRINTER_TEST_IP, ppdName, ppdData));
    EXPECT_TRUE(vendorManager.OnPrinterPpdQueried(vendorName, PRINTER_TEST_IP, ppdName, ppdData));
    PrinterVendorStatus vendorStatus;
    EXPECT_FALSE(vendorManager.OnPrinterStatusChanged(vendorName, PRINTER_TEST_IP, vendorStatus));
    EXPECT_TRUE(vendorManager.OnPrinterStatusChanged(vendorName, PRINTER_TEST_IP, vendorStatus));
    EXPECT_EQ(vendorManager.RemovePrinterFromCups(vendorName, PRINTER_TEST_IP), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.RemovePrinterFromCups(vendorName, PRINTER_TEST_IP), EXTENSION_ERROR_NONE);
    EXPECT_TRUE(vendorManager.QueryPrinterInfoByPrinterId("vendor", PRINTER_TEST_IP, printerInfo));
    std::string makeModel = "test_makeModel";
    EXPECT_TRUE(vendorManager.QueryPPDInformation(makeModel, ppdName));
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0008, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorIppEverywhere = std::make_shared<VendorIppEveryWhere>();
    ASSERT_NE(vendorIppEverywhere, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorIppEverywhere));
    std::string vendorName = vendorIppEverywhere->GetVendorName();
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    std::string ppdData;
    PrinterInfo printerInfo;
    EXPECT_CALL(*mock, AddVendorPrinterToDiscovery(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, UpdateVendorPrinterToDiscovery(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, RemoveVendorPrinterFromDiscovery(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, AddVendorPrinterToCupsWithPpd(_, _, _, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_NONE);
    EXPECT_EQ(vendorManager.UpdatePrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.UpdatePrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_NONE);
    EXPECT_EQ(vendorManager.RemovePrinterFromDiscovery(vendorName, PRINTER_TEST_IP), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.RemovePrinterFromDiscovery(vendorName, PRINTER_TEST_IP), EXTENSION_ERROR_NONE);
    EXPECT_EQ(vendorManager.AddPrinterToCupsWithPpd(vendorName, PRINTER_TEST_IP, ppdData),
              EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(vendorManager.AddPrinterToCupsWithPpd(vendorName, PRINTER_TEST_IP, ppdData), EXTENSION_ERROR_NONE);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0009, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, true));
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StartDiscovery();
    vendorManager.UnInit();
    vendorManager.UnInit();
    EXPECT_TRUE(vendorManager.Init(mock, true));
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0010, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorPpdDriver = std::make_shared<VendorPpdDriver>();
    ASSERT_NE(vendorPpdDriver, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorPpdDriver));
    std::string vendorName = vendorPpdDriver->GetVendorName();
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    std::string ppdData;
    PrinterInfo printerInfo;
    EXPECT_CALL(*mock, AddVendorPrinterToDiscovery(_, _)).WillRepeatedly(Return(false));
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_CALLBACK_FAIL);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0011, TestSize.Level0)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    MockVendorPpdDriver mockVendorPpdDriver;
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorPpdDriver = std::make_shared<VendorPpdDriver>();
    ASSERT_NE(vendorPpdDriver, nullptr);
    EXPECT_TRUE(vendorManager.LoadVendorDriver(vendorPpdDriver));
    std::string vendorName = "driver.bsuni";
    std::string globalVendorName = VendorManager::GetGlobalVendorName(vendorName);
    std::string printerId = PRINTER_TEST_IP;
    std::string globalPrinterId = VendorManager::GetGlobalPrinterId(globalVendorName, printerId);
    std::string ppdData;
    PrinterInfo printerInfo;

    std::string option = "{\"bsunidriverSupport\": \"true\"}";
    printerInfo.SetOption(option);
    EXPECT_CALL(*mock, AddVendorPrinterToDiscovery(_, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(vendorManager.AddPrinterToDiscovery(vendorName, printerInfo), EXTENSION_ERROR_NONE);
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0012, TestSize.Level1)
{
    VendorManager vendorManager;
    std::string vendorName = "test";
    EXPECT_FALSE(vendorManager.IsPrivatePpdDriver(vendorName));
    vendorName = "driver.bsuni";
    EXPECT_FALSE(vendorManager.IsPrivatePpdDriver(vendorName));
    EXPECT_TRUE(vendorManager.IsPrivatePpdDriver(VENDOR_PPD_DRIVER));
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0013, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    PrinterInfo info;
    std::string printerId = PRINTER_TEST_IP;
    PrinterVendorStatus status;
    vendorManager.AddPrinterToDiscovery(VENDOR_BSUNI_DRIVER, info);
    vendorManager.UpdatePrinterToDiscovery(VENDOR_BSUNI_DRIVER, info);
    vendorManager.RemovePrinterFromDiscovery(VENDOR_BSUNI_DRIVER, printerId);
    vendorManager.OnPrinterPpdQueried(VENDOR_BSUNI_DRIVER, printerId, "test_ppd_name", "test_ppd_data");
    vendorManager.OnPrinterStatusChanged(VENDOR_BSUNI_DRIVER, printerId, status);

    vendorManager.wlanGroupDriver = nullptr;
    vendorManager.AddPrinterToDiscovery(VENDOR_BSUNI_DRIVER, info);
    vendorManager.UpdatePrinterToDiscovery(VENDOR_BSUNI_DRIVER, info);
    vendorManager.RemovePrinterFromDiscovery(VENDOR_BSUNI_DRIVER, printerId);
    vendorManager.OnPrinterPpdQueried(VENDOR_BSUNI_DRIVER, printerId, "test_ppd_name", "test_ppd_data");
    vendorManager.OnPrinterStatusChanged(VENDOR_BSUNI_DRIVER, printerId, status);
    vendorManager.UnInit();
}
}  // namespace Print
}  // namespace OHOS