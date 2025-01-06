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
#define protected public
#include "vendor_bsuni_driver.h"
#undef private
#undef protected
#include "print_constant.h"
#include "print_log.h"
#include "mock/mock_bsuni_driver.h"
#include "mock/mock_vendor_manager.h"

using namespace testing;
using namespace testing::ext;

namespace {
const std::string PRINTER_TEST_IP = "192.168.2.222";
}

namespace OHOS {
namespace Print {
MockBsuniDriver *g_mockDriver = nullptr;
int32_t OnCreateTest(const Print_ServiceAbility *context)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnCreate(context);
    }
    return 0;
}
int32_t OnDestroyTest()
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnDestroy();
    }
    return 0;
}
int32_t OnStartDiscoveryTest()
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnStartDiscovery();
    }
    return 0;
}
int32_t OnStopDiscoveryTest()
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnStopDiscovery();
    }
    return 0;
}
int32_t OnConnectPrinterTest(const char *printerId)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnConnectPrinter(printerId);
    }
    return 0;
}
int32_t OnDisconnectPrinterTest(const char *printerId)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnDisconnectPrinter(printerId);
    }
    return 0;
}
int32_t OnQueryCapabilityTest(const char *printerId)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnQueryCapability(printerId);
    }
    return 0;
}
int32_t OnQueryCapabilityByIpTest(const char *printerIp, const char *protocol)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnQueryCapabilityByIp(printerIp, protocol);
    }
    return 0;
}
int32_t OnQueryPropertiesTest(const char *printerId, const Print_StringList *propertyKeyList)
{
    if (g_mockDriver != nullptr) {
        return g_mockDriver->OnQueryProperties(printerId, propertyKeyList);
    }
    return 0;
}
using MockTestFunc =
    std::function<void(VendorBsuniDriver &vendorDriver, MockBsuniDriver &mockDriver, MockVendorManager &mockManager)>;
class VendorBsuniDriverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void DoMockTest(MockTestFunc func);
};

void VendorBsuniDriverTest::SetUpTestCase(void) {}

void VendorBsuniDriverTest::TearDownTestCase(void) {}

void VendorBsuniDriverTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorBsuniDriverTest_%{public}d", ++testNo);
}

void VendorBsuniDriverTest::TearDown(void) {}

void VendorBsuniDriverTest::DoMockTest(MockTestFunc func)
{
    if (func == nullptr) {
        PRINT_HILOGE("test func is null");
        return;
    }
    MockBsuniDriver mockDriver;
    g_mockDriver = &mockDriver;
    MockVendorManager mockManager;
    VendorBsuniDriver vendorDriver;
    Print_VendorExtension vendorExtension = { .onCreate = OnCreateTest,
                                              .onDestroy = OnDestroyTest,
                                              .onStartDiscovery = OnStartDiscoveryTest,
                                              .onStopDiscovery = OnStopDiscoveryTest,
                                              .onConnectPrinter = OnConnectPrinterTest,
                                              .onDisconnectPrinter = OnDisconnectPrinterTest,
                                              .onQueryCapability = OnQueryCapabilityTest,
                                              .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
                                              .onQueryProperties = OnQueryPropertiesTest };
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.vendorManager = &mockManager;
    EXPECT_CALL(mockDriver, OnCreate(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(mockDriver, OnDestroy()).Times(1).WillOnce(Return(0));
    vendorDriver.OnCreate();
    func(vendorDriver, mockDriver, mockManager);
    vendorDriver.OnDestroy();
    vendorDriver.vendorExtension = nullptr;
    g_mockDriver = nullptr;
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0001, TestSize.Level1)
{
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(nullptr));
    g_mockDriver = nullptr;
    Print_VendorExtension vendorExtension = { .onCreate = OnCreateTest,
                                              .onDestroy = OnDestroyTest,
                                              .onStartDiscovery = OnStartDiscoveryTest,
                                              .onStopDiscovery = OnStopDiscoveryTest,
                                              .onConnectPrinter = OnConnectPrinterTest,
                                              .onDisconnectPrinter = OnDisconnectPrinterTest,
                                              .onQueryCapability = OnQueryCapabilityTest,
                                              .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
                                              .onQueryProperties = OnQueryPropertiesTest };
    EXPECT_TRUE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onQueryProperties = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onQueryCapabilityByIp = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onQueryCapability = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onDisconnectPrinter = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onConnectPrinter = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onStopDiscovery = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onStartDiscovery = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onDestroy = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
    vendorExtension.onCreate = nullptr;
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(&vendorExtension));
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0002, TestSize.Level2)
{
    MockVendorManager mockManager;
    VendorBsuniDriver vendorDriver;
    vendorDriver.Init(&mockManager);
    vendorDriver.UnInit();
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0003, TestSize.Level2)
{
    std::vector<std::string> propertyKeys;
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES);
    VendorBsuniDriver vendorDriver;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnStopDiscovery();
    EXPECT_EQ(vendorDriver.OnQueryCapability("", 0), false);
    EXPECT_EQ(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"), false);
    EXPECT_EQ(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys), false);
    Print_VendorExtension vendorExtension = { 0 };
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnStopDiscovery();
    EXPECT_EQ(vendorDriver.OnQueryCapability("", 0), false);
    EXPECT_EQ(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"), false);
    EXPECT_EQ(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys), false);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0004, TestSize.Level1)
{
    std::vector<std::string> propertyKeys;
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES);
    propertyKeys.push_back(PRINTER_PROPERTY_KEY_CUPS_PPD_FILE);
    std::string printerId = PRINTER_TEST_IP;
    VendorBsuniDriver vendorDriver;
    EXPECT_EQ(vendorDriver.OnPrinterPropertiesQueried(printerId, nullptr), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(vendorDriver.OnPrinterCapabilityQueried(nullptr, nullptr, nullptr), EXTENSION_ERROR_CALLBACK_NULL);
    MockVendorManager mockManager;
    vendorDriver.vendorManager = &mockManager;
    EXPECT_EQ(vendorDriver.OnPrinterPropertiesQueried(printerId, nullptr), EXTENSION_ERROR_NONE);
    EXPECT_EQ(vendorDriver.OnPrinterCapabilityQueried(nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0005, TestSize.Level2)
{
    VendorBsuniDriver::SetDriverWrapper(nullptr);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(nullptr, nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(nullptr, nullptr, nullptr), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), nullptr), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_NULL);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0006, TestSize.Level2)
{
    VendorBsuniDriver vendorDriver;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0);
    vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp");
    std::vector<std::string> propertyKeys;
    vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0007, TestSize.Level2)
{
    VendorBsuniDriver vendorDriver;
    g_mockDriver = nullptr;
    Print_VendorExtension vendorExtension = { .onCreate = OnCreateTest,
                                              .onDestroy = OnDestroyTest,
                                              .onStartDiscovery = OnStartDiscoveryTest,
                                              .onStopDiscovery = OnStopDiscoveryTest,
                                              .onConnectPrinter = OnConnectPrinterTest,
                                              .onDisconnectPrinter = OnDisconnectPrinterTest,
                                              .onQueryCapability = OnQueryCapabilityTest,
                                              .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
                                              .onQueryProperties = OnQueryPropertiesTest };
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0);
    vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp");
    std::vector<std::string> propertyKeys;
    vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys);
}

static void BuildDefaultValue(Print_DefaultValue &defaultValue)
{
    defaultValue.defaultColorMode = COLOR_MODE_MONOCHROME;
    defaultValue.defaultDuplexMode = DUPLEX_MODE_ONE_SIDED;
    defaultValue.defaultMediaType = "a";
    defaultValue.defaultPageSizeId = "ISO_A4";
    defaultValue.defaultMargin = {1, 1, 1, 1};
    defaultValue.defaultPaperSource = "a";
    defaultValue.defaultPrintQuality = Print_Quality::PRINT_QUALITY_HIGH;
    defaultValue.defaultCopies = 1;
    defaultValue.defaultResolution = {1, 1};
    defaultValue.defaultOrientation = ORIENTATION_MODE_PORTRAIT;
    defaultValue.otherDefaultValues = "default";
}

}  // namespace Print
}  // namespace OHOS