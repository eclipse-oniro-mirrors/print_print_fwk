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

#include <thread>
#include <gtest/gtest.h>
#define private public
#define protected public
#include "vendor_ppd_driver.h"
#undef private
#undef protected
#include "vendor_manager.h"
#include "print_constant.h"
#include "print_log.h"
#include "mock/mock_vendor_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class VendorPpdDriverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VendorPpdDriverTest::SetUpTestCase(void)
{}

void VendorPpdDriverTest::TearDownTestCase(void)
{}

void VendorPpdDriverTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorPpdDriverTest_%{public}d", ++testNo);
}

void VendorPpdDriverTest::TearDown(void)
{}

HWTEST_F(VendorPpdDriverTest, GetVendorName_ShouldReturnVendorName_WhenCalled, TestSize.Level0)
{
    VendorPpdDriver vendorDriver;
    EXPECT_EQ(vendorDriver.GetVendorName(), VENDOR_PPD_DRIVER);
}

HWTEST_F(
    VendorPpdDriverTest, OnPrinterDiscovered_ShouldSetConnectingVendorGroupAndPrinterInfo_WhenCalled, TestSize.Level0)
{
    VendorPpdDriver vendorDriver;
    std::string vendorName = "TestVendor";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("12345");
    vendorDriver.OnPrinterDiscovered(vendorName, printerInfo);
    EXPECT_EQ(vendorDriver.connectingVendorGroup, vendorName);
    EXPECT_EQ(vendorDriver.connectingPrinterInfo->GetPrinterId(), "12345");
}

HWTEST_F(VendorPpdDriverTest, QueryProperty_ShouldReturnFalse_WhenPrinterIdDoesNotMatch, TestSize.Level1)
{
    VendorPpdDriver vendorDriver;
    std::string vendorName = "TestVendor";
    std::string printerId = "12345";
    std::string key = "testKey";
    std::string value;
    EXPECT_FALSE(vendorDriver.QueryProperty(printerId, key, value));
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    vendorDriver.OnPrinterDiscovered(vendorName, printerInfo);
    EXPECT_FALSE(vendorDriver.QueryProperty("23", key, value));
}

HWTEST_F(VendorPpdDriverTest, QueryProperty_ShouldReturnTrue_WhenKeyIsCupsPpdNameAndQuerySucceeds, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryPPDInformation(_, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    std::string vendorName = "TestVendor";
    std::string printerId = "12345";
    std::string key = PRINTER_PROPERTY_KEY_CUPS_PPD_NAME;
    std::string value;
    PrinterInfo printerInfo;
    printerInfo.SetPrinterMake("TestMake");
    printerInfo.SetPrinterId(printerId);
    vendorDriver.OnPrinterDiscovered(vendorName, printerInfo);
    EXPECT_FALSE(vendorDriver.QueryProperty(printerId, key, value));
    value = "test";
    // success call to cupsd but response is empty string
    EXPECT_FALSE(vendorDriver.QueryProperty(printerId, key, value));
}

HWTEST_F(VendorPpdDriverTest, QueryPpdName_ShouldReturnFalse_WhenVendorManagerIsNull, TestSize.Level1)
{
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.QueryPpdName("TestMake").empty());
}

/**
 * @tc.name: DiscoverBackendPrinters_WhenDiscoverOne_ShouldAddIt
 * @tc.desc: when discover one device should add it.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VendorPpdDriverTest, DiscoverBackendPrinters_WhenDiscoverOne_ShouldAddIt, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    PrinterInfo info;
    info.SetPrinterId("test1");
    std::vector<PrinterInfo> infoVec = {info};
    EXPECT_CALL(mock, DiscoverBackendPrinters(_, _))
        .Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoVec), Return(E_PRINT_NONE)));
    EXPECT_CALL(mock, AddPrinterToDiscovery(_, _)).Times(1).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, RemovePrinterFromDiscovery(_, _)).Times(0);
    vendorDriver.DiscoverBackendPrinters();
}

/**
 * @tc.name: DiscoverBackendPrinters_WhenLoseOne_ShouldRemoveIt
 * @tc.desc: when lose one discovered device should remote it.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VendorPpdDriverTest, DiscoverBackendPrinters_WhenLoseOne_ShouldRemoveIt, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    vendorDriver.discoveredPrinters_["test1"] = true;
    EXPECT_CALL(mock, DiscoverBackendPrinters(_, _)).Times(1).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, AddPrinterToDiscovery(_, _)).Times(0);
    EXPECT_CALL(mock, RemovePrinterFromDiscovery(_, _)).Times(1).WillRepeatedly(Return(E_PRINT_NONE));
    vendorDriver.DiscoverBackendPrinters();
}

/**
 * @tc.name: DiscoverBackendPrinters_WhenLoseOne_ShouldRemoveIt
 * @tc.desc: when woke normolly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VendorPpdDriverTest, DiscoverBackendPrinters_ShouldWorkNormolly, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    PrinterInfo info;
    info.SetPrinterId("test1");
    std::vector<PrinterInfo> infoVec = {info};
    vendorDriver.discoveredPrinters_["test2"] = true;
    EXPECT_CALL(mock, DiscoverBackendPrinters(_, _))
        .Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoVec), Return(E_PRINT_NONE)));
    EXPECT_CALL(mock, AddPrinterToDiscovery(_, _)).Times(1).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, RemovePrinterFromDiscovery(_, _)).Times(1).WillRepeatedly(Return(E_PRINT_NONE));
    vendorDriver.DiscoverBackendPrinters();
}

/**
 * @tc.name: StartAndStopDiscovery_ShouldWorkNormolly
 * @tc.desc: Start and stop discovery when woke normolly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VendorPpdDriverTest, StartAndStopDiscovery_ShouldWorkNormolly, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    PrinterInfo info;
    info.SetPrinterId("test1");
    std::vector<PrinterInfo> infoVec = {info};
    EXPECT_CALL(mock, DiscoverBackendPrinters(_, _))
        .Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoVec), Return(E_PRINT_NONE)));
    vendorDriver.OnStartDiscovery();
    std::this_thread::sleep_for(std::chrono::seconds(10));
    vendorDriver.OnStopDiscovery();
}

/**
 * @tc.name: StartAndStopDiscovery_ShouldWorkNormolly
 * @tc.desc: Start and stop discovery when woke normolly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VendorPpdDriverTest, AllCallVendorMgrFunc_WhenAfterUninit_ShouldFail, TestSize.Level1)
{
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    vendorDriver.vendorManager = nullptr;
    PrinterInfo printerInfo;
    EXPECT_FALSE(vendorDriver.OnQueryCapability("", 0));
    EXPECT_TRUE(vendorDriver.QueryPpdName("").empty());
    vendorDriver.DiscoverBackendPrinters();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnStopDiscovery();
    EXPECT_FALSE(vendorDriver.TryConnectByPpdDriver(printerInfo));
}
}  // namespace Print
}  // namespace OHOS
