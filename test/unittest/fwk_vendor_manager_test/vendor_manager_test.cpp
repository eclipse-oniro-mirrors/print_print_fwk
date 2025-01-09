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

HWTEST_F(VendorManagerTest, VendorManagerTest_0001, TestSize.Level1)
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
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0002, TestSize.Level1)
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

HWTEST_F(VendorManagerTest, VendorManagerTest_0003, TestSize.Level1)
{
    MockPrintServiceAbility mock;
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(&mock, false));
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

HWTEST_F(VendorManagerTest, VendorManagerTest_0005, TestSize.Level2)
{
    MockPrintServiceAbility mock;
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(&mock, false));
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
    EXPECT_FALSE(vendorManager.IsConnectingPrinter(globalPrinterId, ""));
    EXPECT_TRUE(vendorManager.IsConnectingPrinter(globalPrinterId, printerId));
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0006, TestSize.Level2)
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
    EXPECT_FALSE(vendorManager.OnPrinterPpdQueried("", PRINTER_TEST_IP, ""));
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
    vendorManager.UnInit();
}

HWTEST_F(VendorManagerTest, VendorManagerTest_0009, TestSize.Level2)
{
    MockPrintServiceAbility mock;
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(&mock, true));
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    vendorManager.StartDiscovery();
    vendorManager.UnInit();
    vendorManager.UnInit();
    EXPECT_TRUE(vendorManager.Init(&mock, true));
    syncWait.Wait(WAIT_TIME_MS);
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
}  // namespace Print
}  // namespace OHOS