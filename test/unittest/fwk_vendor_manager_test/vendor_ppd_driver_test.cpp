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
#include "vendor_ppd_driver.h"
#undef private
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

void VendorPpdDriverTest::SetUpTestCase(void) {}

void VendorPpdDriverTest::TearDownTestCase(void) {}

void VendorPpdDriverTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorPpdDriverTest_%{public}d", ++testNo);
}

void VendorPpdDriverTest::TearDown(void) {}

HWTEST_F(VendorPpdDriverTest, GetVendorName_ShouldReturnVendorName_WhenCalled, TestSize.Level0)
{
    VendorPpdDriver vendorDriver;
    EXPECT_EQ(vendorDriver.GetVendorName(), VENDOR_PPD_DRIVER);
}

HWTEST_F(VendorPpdDriverTest, OnPrinterDiscovered_ShouldSetConnectingVendorGroupAndPrinterInfo_WhenCalled,
    TestSize.Level0)
{
    VendorPpdDriver vendorDriver;
    std::string vendorName = "TestVendor";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("12345");
    vendorDriver.OnPrinterDiscovered(vendorName, printerInfo);
    EXPECT_EQ(vendorDriver.connectingVendorGroup, vendorName);
    EXPECT_EQ(vendorDriver.connectingPrinterInfo->GetPrinterId(), "12345");
}

HWTEST_F(VendorPpdDriverTest, QueryProperty_ShouldReturnFalse_WhenPrinterIdDoesNotMatch,
    TestSize.Level1)
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

HWTEST_F(VendorPpdDriverTest, QueryProperty_ShouldReturnTrue_WhenKeyIsCupsPpdNameAndQuerySucceeds,
    TestSize.Level1)
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
    EXPECT_TRUE(vendorDriver.QueryProperty(printerId, key, value));
}

HWTEST_F(VendorPpdDriverTest, QueryPpdName_ShouldReturnFalse_WhenVendorManagerIsNull,
    TestSize.Level1)
{
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.QueryPpdName("TestMake").empty());
}

}  // namespace Print
}  // namespace OHOS
