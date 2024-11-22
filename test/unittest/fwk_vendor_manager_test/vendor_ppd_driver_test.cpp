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

namespace {
const int WAIT_TIME_MS = 100;
const std::string PRINTER_TEST_IP = "192.168.2.222";
}

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

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0001, TestSize.Level1)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    std::vector<std::string> propertyKeys(1, "test.property.key");
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryPPDInformation(_, _)).WillOnce(Return(false)).WillRepeatedly(
        DoAll(SetArgReferee<1>(std::vector<std::string>(1, defaultPpd)), Return(true)));
    EXPECT_FALSE(vendorDriver.OnQueryProperties(printerId, propertyKeys));
    EXPECT_TRUE(vendorDriver.OnQueryProperties(printerId, propertyKeys));
    std::vector<std::string> emptyPropertyKeys;
    EXPECT_FALSE(vendorDriver.OnQueryProperties(printerId, emptyPropertyKeys));
    vendorDriver.UnInit();
}

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0002, TestSize.Level1)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    int defaultTimeout = 0;
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryDiscoveredPrinterInfoById(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(std::make_shared<PrinterInfo>()));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_CALL(mock, QueryPrinterInfoByPrinterId(_, _, _)).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    vendorDriver.privatePrinterPpdMap.insert(std::make_pair(printerId, std::vector(1, defaultPpd)));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
    EXPECT_TRUE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
}

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0003, TestSize.Level1)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    int defaultTimeout = 0;
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryDiscoveredPrinterInfoById(_, _)).WillRepeatedly(Return(std::make_shared<PrinterInfo>()));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).WillOnce(Return(EXTENSION_ERROR_INVALID_PRINTER))
        .WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_CALL(mock, QueryPrinterInfoByPrinterId(_, _, _)).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    vendorDriver.privatePrinterPpdMap.insert(std::make_pair(printerId, std::vector(1, defaultPpd)));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
    EXPECT_TRUE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
}

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0004, TestSize.Level1)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    int defaultTimeout = 0;
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryDiscoveredPrinterInfoById(_, _)).WillRepeatedly(Return(std::make_shared<PrinterInfo>()));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_CALL(mock, QueryPrinterInfoByPrinterId(_, _, _)).WillOnce(Return(E_PRINT_UNKNOWN))
        .WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    vendorDriver.privatePrinterPpdMap.insert(std::make_pair(printerId, std::vector(1, defaultPpd)));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
    EXPECT_TRUE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
}

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0005, TestSize.Level1)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    int defaultTimeout = 0;
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryDiscoveredPrinterInfoById(_, _)).WillRepeatedly(Return(std::make_shared<PrinterInfo>()));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_CALL(mock, QueryPrinterInfoByPrinterId(_, _, _)).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).WillOnce(Return(EXTENSION_ERROR_INVALID_PRINTER))
        .WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    vendorDriver.privatePrinterPpdMap.insert(std::make_pair(printerId, std::vector(1, defaultPpd)));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
    EXPECT_TRUE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
}

HWTEST_F(VendorPpdDriverTest, VendorPpdDriverTest_0006, TestSize.Level2)
{
    std::string printerId = "test.printer.id";
    std::string defaultPpd = "test.ppd.name";
    std::vector<std::string> propertyKeys(1, "test.property.key");
    int defaultTimeout = 0;
    MockVendorManager mock;
    VendorPpdDriver vendorDriver;
    EXPECT_TRUE(vendorDriver.Init(&mock));
    EXPECT_CALL(mock, QueryPPDInformation(_, _)).WillRepeatedly(
        DoAll(SetArgReferee<1>(std::vector<std::string>(1, defaultPpd)), Return(true)));
    EXPECT_CALL(mock, QueryDiscoveredPrinterInfoById(_, _)).WillRepeatedly(Return(std::make_shared<PrinterInfo>()));
    EXPECT_CALL(mock, AddPrinterToCupsWithPpd(_, _, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_CALL(mock, QueryPrinterInfoByPrinterId(_, _, _)).WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(mock, UpdatePrinterToDiscovery(_, _)).WillRepeatedly(Return(EXTENSION_ERROR_NONE));
    EXPECT_FALSE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));

    EXPECT_TRUE(vendorDriver.OnQueryProperties(printerId, propertyKeys));
    EXPECT_TRUE(vendorDriver.OnQueryCapability(printerId, defaultTimeout));
}

}  // namespace Print
}  // namespace OHOS
