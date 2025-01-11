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
#include "vendor_ipp_everywhere.h"
#undef private
#include "print_constant.h"
#include "print_log.h"
#include "mock/mock_vendor_manager.h"

namespace {
const int WAIT_TIME_MS = 100;
const std::string PRINTER_TEST_IP = "192.168.2.222";
}
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class VendorDriverBaseTest : public VendorDriverBase {
public:
    std::string GetVendorName() override
    {
        return "driver.base.test";
    }
};
class VendorIppEverywhereTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VendorIppEverywhereTest::SetUpTestCase(void) {}

void VendorIppEverywhereTest::TearDownTestCase(void) {}

void VendorIppEverywhereTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorIppEverywhereTest_%{public}d", ++testNo);
}

void VendorIppEverywhereTest::TearDown(void) {}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0001, TestSize.Level1)
{
    VendorIppEveryWhere vendorDriver;
    EXPECT_EQ(vendorDriver.Init(nullptr), false);
    vendorDriver.OnCreate();
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnStartDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnStopDiscovery();
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnDestroy();
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.UnInit();
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0002, TestSize.Level2)
{
    VendorIppEveryWhere vendorDriver;
    EXPECT_EQ(vendorDriver.Init(nullptr), false);
    EXPECT_FALSE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "protocol"));
    EXPECT_FALSE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "auto"));
    EXPECT_FALSE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"));
    std::vector<std::string> propertyKeys;
    EXPECT_FALSE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES);
    EXPECT_FALSE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    vendorDriver.OnCreate();
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_TRUE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"));
    EXPECT_TRUE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0));
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnDestroy();
    vendorDriver.UnInit();
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0003, TestSize.Level2)
{
    MockVendorManager mock;
    VendorIppEveryWhere vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    std::vector<std::string> propertyKeys;
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES);
    EXPECT_FALSE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    vendorDriver.OnCreate();
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_CALL(mock, QueryPrinterStatusByUri(_, _)).Times(2).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, QueryPrinterCapabilityByUri(_, _)).Times(1).WillRepeatedly(Return(false));
    EXPECT_TRUE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    EXPECT_TRUE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    EXPECT_TRUE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0));
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnDestroy();
    vendorDriver.UnInit();
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0004, TestSize.Level2)
{
    MockVendorManager mock;
    VendorIppEveryWhere vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    std::vector<std::string> propertyKeys;
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES);
    vendorDriver.OnCreate();
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_CALL(mock, QueryPrinterStatusByUri(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, OnPrinterStatusChanged(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, QueryPrinterCapabilityByUri(_, _)).WillRepeatedly(Return(true));
    vendorDriver.MonitorPrinterStatus(PRINTER_TEST_IP, true);
    EXPECT_TRUE(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys));
    EXPECT_TRUE(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"));
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.MonitorPrinterStatus(PRINTER_TEST_IP, false);
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnDestroy();
    vendorDriver.UnInit();
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0005, TestSize.Level2)
{
    VendorIppEveryWhere vendorDriver;
    PrinterCapability cap;
    std::string uri;
    EXPECT_EQ(vendorDriver.ConvertCapabilityToInfo(cap, uri), nullptr);
    std::string option;
    cap.SetOption(option);
    EXPECT_EQ(vendorDriver.ConvertCapabilityToInfo(cap, uri), nullptr);
    option = "{\"make\":\"maker\"}";
    cap.SetOption(option);
    EXPECT_EQ(vendorDriver.ConvertCapabilityToInfo(cap, uri), nullptr);
    option = "{\"printerName\":\"name\"}";
    cap.SetOption(option);
    EXPECT_EQ(vendorDriver.ConvertCapabilityToInfo(cap, uri), nullptr);
    option = "{\"printerName\":\"name\",\"make\":\"maker\"}";
    cap.SetOption(option);
    EXPECT_NE(vendorDriver.ConvertCapabilityToInfo(cap, uri), nullptr);
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0006, TestSize.Level2)
{
    MockVendorManager mock;
    VendorIppEveryWhere vendorDriver;
    auto printerInfo = std::make_shared<PrinterInfo>();
    EXPECT_FALSE(vendorDriver.ConnectPrinter(printerInfo));
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_FALSE(vendorDriver.ConnectPrinter(nullptr));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).Times(3).WillOnce(Return(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).Times(2).WillOnce(Return(1)).WillRepeatedly(Return(0));
    EXPECT_FALSE(vendorDriver.ConnectPrinter(printerInfo));
    EXPECT_FALSE(vendorDriver.ConnectPrinter(printerInfo));
    EXPECT_TRUE(vendorDriver.ConnectPrinter(printerInfo));
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0007, TestSize.Level2)
{
    MockVendorManager mock;
    VendorIppEveryWhere vendorDriver;
    auto printerInfo = std::make_shared<PrinterInfo>();
    EXPECT_FALSE(vendorDriver.UpdateCapability(printerInfo));
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_FALSE(vendorDriver.UpdateCapability(nullptr));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).Times(2).WillOnce(Return(1)).WillRepeatedly(Return(0));
    EXPECT_FALSE(vendorDriver.UpdateCapability(printerInfo));
    EXPECT_TRUE(vendorDriver.UpdateCapability(printerInfo));
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0008, TestSize.Level2)
{
    VendorDriverBaseTest vendorDriver;
    std::string printerId = "test";
    Print_PrinterState state = Print_PrinterState::PRINTER_UNAVAILABLE;
    vendorDriver.OnPrinterStateQueried(printerId, state);
    vendorDriver.UpdateAllPrinterStatus();
    EXPECT_TRUE(vendorDriver.MonitorPrinterStatus(printerId, true));
    vendorDriver.UpdateAllPrinterStatus();
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, 0));
    EXPECT_FALSE(vendorDriver.OnQueryCapabilityByIp(printerId, ""));
    std::vector<std::string> propertyKeys;
    EXPECT_FALSE(vendorDriver.OnQueryProperties(printerId, propertyKeys));
}

HWTEST_F(VendorIppEverywhereTest, VendorIppEverywhereTest_0009, TestSize.Level2)
{
    MockVendorManager mock;
    VendorDriverBaseTest vendorDriver;
    std::string printerId = "test";
    EXPECT_TRUE(vendorDriver.MonitorPrinterStatus(printerId, true));
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, OnPrinterStatusChanged(_, _, _)).WillRepeatedly(Return(false));
    EXPECT_FALSE(vendorDriver.MonitorPrinterStatus(printerId, true));
    vendorDriver.UpdateAllPrinterStatus();
    EXPECT_TRUE(vendorDriver.MonitorPrinterStatus(printerId, false));
    EXPECT_FALSE(vendorDriver.MonitorPrinterStatus(printerId, false));
    vendorDriver.UnInit();
}
}  // namespace Print
}  // namespace OHOS