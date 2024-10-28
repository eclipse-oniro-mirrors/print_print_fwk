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
#include "vendor_helper.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing;
using namespace testing::ext;

namespace {
const int TEST_VALUE_SMALL = -1;
const int TEST_VALUE_LARGE = 10;
const uint32_t ISO_A3_WIDTH = 11690;
const uint32_t ISO_A3_HEIGHT = 16540;
const uint32_t ISO_A4_WIDTH = 8268;
const uint32_t ISO_A4_HEIGHT = 11692;
const uint32_t DPI_A = 300;
const uint32_t DPI_B = 600;
const uint32_t DEFAULT_COUNT = 2;
const uint32_t TEST_MAX_COPIES = 99;
}
namespace OHOS {
namespace Print {
class VendorHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VendorHelperTest::SetUpTestCase(void) {}

void VendorHelperTest::TearDownTestCase(void) {}

void VendorHelperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorHelperTest_%{public}d", ++testNo);
}

void VendorHelperTest::TearDown(void) {}

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

HWTEST_F(VendorHelperTest, VendorHelperTest_0001, TestSize.Level1)
{
    std::string test = "test ";
    char *result = CopyString("");
    EXPECT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    delete[] result;
    result = nullptr;
    result = CopyString(test);
    EXPECT_NE(result, nullptr);
    EXPECT_STREQ(result, test.c_str());
    delete[] result;
    result = nullptr;
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0002, TestSize.Level1)
{
    long value = 0;
    EXPECT_FALSE(ConvertStringToLong("", value));
    EXPECT_FALSE(ConvertStringToLong("999999999999999999999999999", value));
    EXPECT_FALSE(ConvertStringToLong("x", value));
    EXPECT_TRUE(ConvertStringToLong(std::to_string(TEST_VALUE_LARGE).c_str(), value));
    EXPECT_EQ(value, TEST_VALUE_LARGE);
    EXPECT_TRUE(ConvertStringToLong("0", value));
    EXPECT_EQ(value, 0);
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0003, TestSize.Level1)
{
    uint32_t value = 0;
    EXPECT_FALSE(ConvertColorMode(static_cast<Print_ColorMode>(TEST_VALUE_SMALL), value));
    EXPECT_FALSE(ConvertColorMode(static_cast<Print_ColorMode>(TEST_VALUE_LARGE), value));
    EXPECT_TRUE(ConvertColorMode(COLOR_MODE_AUTO, value));
    EXPECT_EQ(value, static_cast<uint32_t>(COLOR_MODE_AUTO));
    EXPECT_TRUE(ConvertColorMode(COLOR_MODE_MONOCHROME, value));
    EXPECT_EQ(value, static_cast<uint32_t>(COLOR_MODE_MONOCHROME));

    EXPECT_FALSE(ConvertDuplexMode(static_cast<Print_DuplexMode>(TEST_VALUE_SMALL), value));
    EXPECT_FALSE(ConvertDuplexMode(static_cast<Print_DuplexMode>(TEST_VALUE_LARGE), value));
    EXPECT_TRUE(ConvertDuplexMode(DUPLEX_MODE_ONE_SIDED, value));
    EXPECT_EQ(value, static_cast<uint32_t>(DUPLEX_MODE_ONE_SIDED));
    EXPECT_TRUE(ConvertDuplexMode(DUPLEX_MODE_TWO_SIDED_SHORT_EDGE, value));
    EXPECT_EQ(value, static_cast<uint32_t>(DUPLEX_MODE_TWO_SIDED_SHORT_EDGE));

    EXPECT_FALSE(ConvertQuality(static_cast<Print_Quality>(TEST_VALUE_SMALL), value));
    EXPECT_FALSE(ConvertQuality(static_cast<Print_Quality>(TEST_VALUE_LARGE), value));
    EXPECT_TRUE(ConvertQuality(Print_Quality::PRINT_QUALITY_DRAFT, value));
    EXPECT_EQ(value, static_cast<uint32_t>(Print_Quality::PRINT_QUALITY_DRAFT));
    EXPECT_TRUE(ConvertQuality(Print_Quality::PRINT_QUALITY_HIGH, value));
    EXPECT_EQ(value, static_cast<uint32_t>(Print_Quality::PRINT_QUALITY_HIGH));
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0004, TestSize.Level1)
{
    Print_PrinterState state = PRINTER_UNAVAILABLE;
    EXPECT_FALSE(ConvertStringToPrinterState("-1", state));
    EXPECT_FALSE(ConvertStringToPrinterState("12", state));
    EXPECT_FALSE(ConvertStringToPrinterState("", state));
    EXPECT_TRUE(ConvertStringToPrinterState("0", state));
    EXPECT_EQ(state, PRINTER_IDLE);
    EXPECT_TRUE(ConvertStringToPrinterState("2", state));
    EXPECT_EQ(state, PRINTER_IDLE);
    EXPECT_FALSE(ConvertStringToPrinterState("\"state\"", state));
    EXPECT_FALSE(ConvertStringToPrinterState("{\"state\":2}", state));
    EXPECT_TRUE(ConvertStringToPrinterState("{\"state\":\"2\"}", state));
    EXPECT_EQ(state, PRINTER_IDLE);
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0005, TestSize.Level1)
{
    Print_DiscoveryItem discoveryItem = {0};
    LogDiscoveryItem(nullptr);
    LogDiscoveryItem(&discoveryItem);
    EXPECT_EQ(discoveryItem.printerId, nullptr);
    EXPECT_EQ(discoveryItem.printerName, nullptr);
    EXPECT_EQ(discoveryItem.description, nullptr);
    EXPECT_EQ(discoveryItem.location, nullptr);
    EXPECT_EQ(discoveryItem.makeAndModel, nullptr);
    EXPECT_EQ(discoveryItem.printerUri, nullptr);
    EXPECT_EQ(discoveryItem.printerUuid, nullptr);
    BuildDiscoveryItem(discoveryItem);
    LogDiscoveryItem(&discoveryItem);
    LogDiscoveryItem(&discoveryItem);
    EXPECT_EQ(discoveryItem.printerId, "printerId");
    EXPECT_EQ(discoveryItem.printerName, "printerName");
    EXPECT_EQ(discoveryItem.description, "description");
    EXPECT_EQ(discoveryItem.location, "location");
    EXPECT_EQ(discoveryItem.makeAndModel, "makeAndModel");
    EXPECT_EQ(discoveryItem.printerUri, "printerUri");
    EXPECT_EQ(discoveryItem.printerUuid, "printerUuid");
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0006, TestSize.Level1)
{
    Print_PrinterCapability capability = {0};
    LogPageCapability(nullptr);
    LogOtherCapability(nullptr);
    LogPageCapability(&capability);
    LogOtherCapability(&capability);
    EXPECT_EQ(capability.supportedPageSizes, nullptr);
    EXPECT_EQ(capability.supportedMediaTypes, nullptr);
    EXPECT_EQ(capability.supportedPaperSources, nullptr);

    BuildCapability(capability);
    LogPageCapability(&capability);
    LogOtherCapability(&capability);
    EXPECT_NE(capability.supportedPageSizes, nullptr);
    EXPECT_EQ(capability.supportedMediaTypes, "{\"a\",\"b\",\"c\"}");
    EXPECT_EQ(capability.supportedPaperSources, "{\"a\",\"b\",\"c\"}");
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0007, TestSize.Level1)
{
    LogDefaultValue(nullptr);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    LogDefaultValue(&defaultValue);
    EXPECT_EQ(defaultValue.defaultMediaType, "a");
    EXPECT_EQ(defaultValue.defaultPageSizeId, "ISO_A4");
    EXPECT_EQ(defaultValue.defaultPaperSource, "a");
    EXPECT_EQ(defaultValue.otherDefaultValues, "default");
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0008, TestSize.Level1)
{
    Print_PropertyList propertyList = {0};
    LogProperties(nullptr);
    LogProperties(&propertyList);
    EXPECT_EQ(propertyList.list, nullptr);
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0009, TestSize.Level1)
{
    auto printerInfo = ConvertVendorCapabilityToPrinterInfo(nullptr, nullptr, nullptr);
    EXPECT_EQ(printerInfo, nullptr);
    Print_DiscoveryItem discoveryItem = {0};
    printerInfo = ConvertVendorCapabilityToPrinterInfo(&discoveryItem, nullptr, nullptr);
    EXPECT_EQ(printerInfo, nullptr);
    BuildDiscoveryItem(discoveryItem);
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    Print_DefaultValue defaultValue;
    BuildDefaultValue(defaultValue);
    printerInfo = ConvertVendorCapabilityToPrinterInfo(&discoveryItem, &capability, &defaultValue);
    EXPECT_NE(printerInfo, nullptr);
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0010, TestSize.Level1)
{
    std::vector<std::string> stringVector;
    Print_StringList list = {0};
    EXPECT_FALSE(ConvertStringVectorToStringList(stringVector, list));
    stringVector.push_back("test");
    EXPECT_TRUE(ConvertStringVectorToStringList(stringVector, list));
    EXPECT_EQ(list.count, stringVector.size());
    ReleaseStringList(list);
}

HWTEST_F(VendorHelperTest, VendorHelperTest_0011, TestSize.Level1)
{
    PrinterCapability printerCap;
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    EXPECT_FALSE(UpdateResolutionDefaultValue(printerCap, nullptr));
    EXPECT_FALSE(UpdateCopiesCapability(printerCap, nullptr, nullptr));
    EXPECT_FALSE(UpdateCopiesCapability(printerCap, &capability, nullptr));
    EXPECT_FALSE(UpdateOrientationCapability(printerCap, nullptr, nullptr));
    EXPECT_FALSE(UpdateOrientationCapability(printerCap, &capability, nullptr));
    EXPECT_FALSE(UpdateMediaCapability(printerCap, nullptr, nullptr));
    EXPECT_FALSE(UpdateMediaCapability(printerCap, &capability, nullptr));
    EXPECT_FALSE(UpdateMarginCapability(printerCap, nullptr));
}
} // namespace Print
} // namespace OHOS