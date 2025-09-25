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
const uint32_t ISO_A3_WIDTH = 11690;
const uint32_t ISO_A3_HEIGHT = 16540;
const uint32_t ISO_A4_WIDTH = 8268;
const uint32_t ISO_A4_HEIGHT = 11692;
const uint32_t DPI_A = 300;
const uint32_t DPI_B = 600;
const uint32_t DEFAULT_COUNT = 2;
const uint32_t TEST_MAX_COPIES = 99;
const int WAIT_TIME_MS = 100;
static void BuildDiscoveryItem(Print_DiscoveryItem &discoveryItem)
{
    discoveryItem.printerId = "printerId";
    discoveryItem.printerName = "printerName";
    discoveryItem.description = "description";
    discoveryItem.location = "location";
    discoveryItem.makeAndModel = "makeAndModel";
    discoveryItem.printerUri = "printerUri";
    discoveryItem.printerUuid = "printerUuid";
}

static void BuildCapability(Print_PrinterCapability &capability)
{
    static Print_ColorMode colorModes[] = {COLOR_MODE_MONOCHROME, COLOR_MODE_COLOR};
    static Print_DuplexMode duplexModes[] = {DUPLEX_MODE_ONE_SIDED, DUPLEX_MODE_TWO_SIDED_SHORT_EDGE};
    static Print_PageSize pageSizes[] = {{"ISO_A4", "iso_a4_210x297mm", ISO_A4_WIDTH, ISO_A4_HEIGHT},
        {"ISO_A3", "iso_a3", ISO_A3_WIDTH, ISO_A3_HEIGHT},
        {"ISO_A4", "iso_a4", ISO_A4_WIDTH, ISO_A4_HEIGHT}};
    static Print_Quality qualities[] = {Print_Quality::PRINT_QUALITY_DRAFT, Print_Quality::PRINT_QUALITY_HIGH};
    static Print_Resolution resolutions[] = {{DPI_A, DPI_A}, {DPI_B, DPI_B}};
    static Print_OrientationMode orientations[] = {ORIENTATION_MODE_PORTRAIT, ORIENTATION_MODE_NONE};
    capability.supportedColorModesCount = DEFAULT_COUNT;
    capability.supportedColorModes = colorModes;
    capability.supportedDuplexModesCount = DEFAULT_COUNT;
    capability.supportedDuplexModes = duplexModes;
    capability.supportedPageSizesCount = DEFAULT_COUNT + 1;
    capability.supportedPageSizes = pageSizes;
    capability.supportedMediaTypes = "{\"a\",\"b\",\"c\"}";
    capability.supportedQualitiesCount = DEFAULT_COUNT;
    capability.supportedQualities = qualities;
    capability.supportedPaperSources = "{\"a\",\"b\",\"c\"}";
    capability.supportedCopies = TEST_MAX_COPIES;
    capability.supportedResolutionsCount = DEFAULT_COUNT;
    capability.supportedResolutions = resolutions;
    capability.supportedOrientationsCount = DEFAULT_COUNT;
    capability.supportedOrientations = orientations;
    capability.advancedCapability = "advance info";
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
    defaultValue.defaultResolution = {DPI_A, DPI_A};
    defaultValue.defaultOrientation = ORIENTATION_MODE_PORTRAIT;
    defaultValue.otherDefaultValues = "default";
}
}  // namespace

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

void VendorBsuniDriverTest::SetUpTestCase(void)
{}

void VendorBsuniDriverTest::TearDownTestCase(void)
{}

void VendorBsuniDriverTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorBsuniDriverTest_%{public}d", ++testNo);
}

void VendorBsuniDriverTest::TearDown(void)
{}

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
    Print_VendorExtension vendorExtension = {.onCreate = OnCreateTest,
        .onDestroy = OnDestroyTest,
        .onStartDiscovery = OnStartDiscoveryTest,
        .onStopDiscovery = OnStopDiscoveryTest,
        .onConnectPrinter = OnConnectPrinterTest,
        .onDisconnectPrinter = OnDisconnectPrinterTest,
        .onQueryCapability = OnQueryCapabilityTest,
        .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
        .onQueryProperties = OnQueryPropertiesTest};
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.vendorManager = &mockManager;
    EXPECT_CALL(mockDriver, OnCreate(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(mockDriver, OnDestroy()).Times(1).WillOnce(Return(0));
    vendorDriver.OnCreate();
    func(vendorDriver, mockDriver, mockManager);
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver.OnDestroy();
    vendorDriver.vendorExtension = nullptr;
    g_mockDriver = nullptr;
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0001, TestSize.Level1)
{
    EXPECT_FALSE(VendorBsuniDriver::CheckVendorExtension(nullptr));
    g_mockDriver = nullptr;
    Print_VendorExtension vendorExtension = {.onCreate = OnCreateTest,
        .onDestroy = OnDestroyTest,
        .onStartDiscovery = OnStartDiscoveryTest,
        .onStopDiscovery = OnStopDiscoveryTest,
        .onConnectPrinter = OnConnectPrinterTest,
        .onDisconnectPrinter = OnDisconnectPrinterTest,
        .onQueryCapability = OnQueryCapabilityTest,
        .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
        .onQueryProperties = OnQueryPropertiesTest};
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
    EXPECT_EQ(vendorDriver.Init(&mockManager), false);
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
    Print_VendorExtension vendorExtension = {0};
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    vendorDriver.OnStopDiscovery();
    EXPECT_EQ(vendorDriver.OnQueryCapability("", 0), false);
    EXPECT_EQ(vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp"), false);
    EXPECT_EQ(vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys), false);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0004, TestSize.Level2)
{
    VendorBsuniDriver vendorDriver;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    EXPECT_EQ(vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0), false);
    vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp");
    std::vector<std::string> propertyKeys;
    vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0005, TestSize.Level2)
{
    VendorBsuniDriver vendorDriver;
    g_mockDriver = nullptr;
    Print_VendorExtension vendorExtension = {.onCreate = OnCreateTest,
        .onDestroy = OnDestroyTest,
        .onStartDiscovery = OnStartDiscoveryTest,
        .onStopDiscovery = OnStopDiscoveryTest,
        .onConnectPrinter = OnConnectPrinterTest,
        .onDisconnectPrinter = OnDisconnectPrinterTest,
        .onQueryCapability = OnQueryCapabilityTest,
        .onQueryCapabilityByIp = OnQueryCapabilityByIpTest,
        .onQueryProperties = OnQueryPropertiesTest};
    vendorDriver.vendorExtension = &vendorExtension;
    vendorDriver.OnCreate();
    vendorDriver.OnDestroy();
    vendorDriver.OnStartDiscovery();
    EXPECT_EQ(vendorDriver.OnQueryCapability(PRINTER_TEST_IP, 0), true);
    vendorDriver.OnQueryCapabilityByIp(PRINTER_TEST_IP, "ipp");
    std::vector<std::string> propertyKeys;
    vendorDriver.OnQueryProperties(PRINTER_TEST_IP, propertyKeys);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0006, TestSize.Level2)
{
    MockTestFunc testFunc =
        [this](VendorBsuniDriver &vendorDriver, MockBsuniDriver &mockDriver, MockVendorManager &mockManager) {
            EXPECT_CALL(mockDriver, OnStartDiscovery()).Times(1).WillOnce(Return(0));
            EXPECT_CALL(mockDriver, OnStopDiscovery()).Times(1).WillOnce(Return(0));
            vendorDriver.OnStartDiscovery();
            vendorDriver.OnStopDiscovery();
        };
    DoMockTest(testFunc);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0007, TestSize.Level2)
{
    MockTestFunc testFunc =
        [this](VendorBsuniDriver &vendorDriver, MockBsuniDriver &mockDriver, MockVendorManager &mockManager) {
            EXPECT_CALL(mockDriver, OnQueryCapability(_)).Times(2).WillOnce(Return(1)).WillRepeatedly(Return(0));
            std::string printerId = PRINTER_TEST_IP;
            EXPECT_EQ(vendorDriver.OnQueryCapability(printerId, 0), false);
            EXPECT_EQ(vendorDriver.OnQueryCapability(printerId, 0), true);
        };
    DoMockTest(testFunc);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0008, TestSize.Level2)
{
    MockTestFunc testFunc =
        [this](VendorBsuniDriver &vendorDriver, MockBsuniDriver &mockDriver, MockVendorManager &mockManager) {
            EXPECT_CALL(mockDriver, OnQueryCapabilityByIp(_, _)).Times(2).WillOnce(Return(1)).WillRepeatedly(Return(0));
            std::string printerIp = PRINTER_TEST_IP;
            vendorDriver.OnQueryCapabilityByIp(printerIp, "ipp");
            vendorDriver.OnQueryCapabilityByIp(printerIp, "ipp");
        };
    DoMockTest(testFunc);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0009, TestSize.Level2)
{
    MockTestFunc testFunc =
        [this](VendorBsuniDriver &vendorDriver, MockBsuniDriver &mockDriver, MockVendorManager &mockManager) {
            EXPECT_CALL(mockManager, RemovePrinterFromCups(_, _)).WillRepeatedly(Return(0));
            EXPECT_CALL(mockManager, RemovePrinterFromDiscovery(_, _)).WillRepeatedly(Return(0));
            std::string printerIp = PRINTER_TEST_IP;
            EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
            EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
            EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(nullptr), EXTENSION_INVALID_PARAMETER);
            EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(printerIp.c_str(), nullptr), EXTENSION_INVALID_PARAMETER);
            EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(printerIp.c_str()), EXTENSION_ERROR_NONE);
            EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(nullptr), EXTENSION_INVALID_PARAMETER);
            EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(printerIp.c_str()), EXTENSION_ERROR_NONE);
        };
    DoMockTest(testFunc);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_00010, TestSize.Level2)
{
    VendorBsuniDriver::SetDriverWrapper(nullptr);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(nullptr, nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0011, TestSize.Level2)
{
    VendorBsuniDriver::SetDriverWrapper(nullptr);
    Print_DiscoveryItem discoveryItem = {0};
    Print_PrinterCapability capability = {0};
    Print_DefaultValue defaultValue;
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(&discoveryItem), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(
        VendorBsuniDriver::AddPrinterToCups(&discoveryItem, nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), nullptr), EXTENSION_INVALID_PARAMETER);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0012, TestSize.Level2)
{
    VendorBsuniDriver::SetDriverWrapper(nullptr);
    Print_DiscoveryItem discoveryItem = {0};
    BuildDiscoveryItem(discoveryItem);
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    Print_PropertyList propertyList = {0};
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(&discoveryItem), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(
        VendorBsuniDriver::AddPrinterToCups(&discoveryItem, nullptr, nullptr, nullptr), EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, nullptr, nullptr),
        EXTENSION_INVALID_PARAMETER);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr),
        EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(&discoveryItem, &capability, &defaultValue),
        EXTENSION_ERROR_CALLBACK_NULL);
    EXPECT_EQ(
        VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_CALLBACK_NULL);
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0013, TestSize.Level2)
{
    auto vendorDriver = std::make_shared<VendorBsuniDriver>();
    VendorBsuniDriver::SetDriverWrapper(vendorDriver);
    Print_DiscoveryItem discoveryItem = {0};
    BuildDiscoveryItem(discoveryItem);
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    Print_PropertyList propertyList = {0};
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(&discoveryItem), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr),
        EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr),
        EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(&discoveryItem, &capability, &defaultValue),
        EXTENSION_ERROR_CALLBACK_FAIL);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_NONE);
    propertyList.count = 1;
    propertyList.list = new Print_Property[1];
    propertyList.list[0].key = PRINTER_PROPERTY_KEY_CUPS_PPD_FILE;
    propertyList.list[0].value = "ppd";
    EXPECT_EQ(
        VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_CALLBACK_FAIL);
    delete[] propertyList.list;
    propertyList.list = nullptr;
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0014, TestSize.Level2)
{
    auto vendorDriver = std::make_shared<VendorBsuniDriver>();
    vendorDriver->opQueue.Run();
    VendorBsuniDriver::SetDriverWrapper(vendorDriver);
    Print_DiscoveryItem discoveryItem = {0};
    BuildDiscoveryItem(discoveryItem);
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    Print_PropertyList propertyList = {0};
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(&discoveryItem), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_NONE);
    EXPECT_EQ(
        VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, "test_ppd_data"),
        EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(&discoveryItem, &capability, &defaultValue), EXTENSION_ERROR_NONE);
    propertyList.count = DEFAULT_COUNT;
    propertyList.list = new Print_Property[DEFAULT_COUNT];
    propertyList.list[0].key = PRINTER_PROPERTY_KEY_CUPS_PPD_FILE;
    propertyList.list[0].value = "ppd";
    propertyList.list[1].key = PRINTER_PROPERTY_KEY_DEVICE_STATE;
    propertyList.list[1].value = "{\"state\":\"1\",\"reason\":\"none\"}";
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_NONE);
    delete[] propertyList.list;
    propertyList.list = nullptr;
    vendorDriver->opQueue.Stop();
}

HWTEST_F(VendorBsuniDriverTest, VendorBsuniDriverTest_0015, TestSize.Level2)
{
    auto vendorDriver = std::make_shared<VendorBsuniDriver>();
    MockVendorManager mockManager;
    vendorDriver->vendorManager = &mockManager;
    vendorDriver->opQueue.Run();
    VendorBsuniDriver::SetDriverWrapper(vendorDriver);
    Print_DiscoveryItem discoveryItem = {0};
    BuildDiscoveryItem(discoveryItem);
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    Print_PropertyList propertyList = {0};
    EXPECT_CALL(mockManager, AddPrinterToDiscovery(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockManager, RemovePrinterFromDiscovery(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockManager, UpdatePrinterToDiscovery(_, _)).WillOnce(Return(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockManager, AddPrinterToCupsWithPpd(_, _, _, _)).WillOnce(Return(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockManager, RemovePrinterFromCups(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockManager, OnPrinterPpdQueried(_, _, _, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToDiscovery(&discoveryItem), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromDiscovery(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_NONE);
    EXPECT_EQ(
        VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr), EXTENSION_ERROR_NONE);
    EXPECT_EQ(
        VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, nullptr), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::AddPrinterToCups(&discoveryItem, &capability, &defaultValue, "test_ppd_data"),
        EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::RemovePrinterFromCups(PRINTER_TEST_IP.c_str()), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(&discoveryItem, &capability, &defaultValue), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::OnCapabilityQueried(&discoveryItem, &capability, &defaultValue), EXTENSION_ERROR_NONE);
    propertyList.count = DEFAULT_COUNT;
    propertyList.list = new Print_Property[DEFAULT_COUNT];
    propertyList.list[0].key = PRINTER_PROPERTY_KEY_CUPS_PPD_FILE;
    propertyList.list[0].value = "ppd";
    propertyList.list[1].key = PRINTER_PROPERTY_KEY_DEVICE_STATE;
    propertyList.list[1].value = "{\"state\":\"1\",\"reason\":\"none\"}";
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_NONE);
    EXPECT_EQ(VendorBsuniDriver::OnPropertiesQueried(PRINTER_TEST_IP.c_str(), &propertyList), EXTENSION_ERROR_NONE);
    delete[] propertyList.list;
    propertyList.list = nullptr;
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    vendorDriver->opQueue.Stop();
}
}  // namespace Print
}  // namespace OHOS
