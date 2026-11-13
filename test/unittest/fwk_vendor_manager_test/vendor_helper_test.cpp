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
#include "ohprint.h"
#include "print_json_util.h"

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
const uint32_t MAX_COLOR_MODE_COUNT = 200;
const uint32_t MAX_DUPLEX_MODE_COUNT = 1000;
const std::string PROTOCOL_JSON = "{\"printer_protocols\": {"
                "\"lpd\": \"lpd://192.168.1.1:515/\", "
                "\"socket\": \"socket://192.168.1.1:9100/\", "
                "\"ipp\": \"ipp://192.168.1.1:631/ipp/print\", "
                "\"ipps\": \"ipps://192.168.1.1:12345/ipps\"}}";
}  // namespace
namespace OHOS {
namespace Print {
class VendorHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VendorHelperTest::SetUpTestCase(void)
{}

void VendorHelperTest::TearDownTestCase(void)
{}

void VendorHelperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorHelperTest_%{public}d", ++testNo);
}

void VendorHelperTest::TearDown(void)
{}

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
    EXPECT_TRUE(ConvertStringToPrinterState("{\"state\":\"0\"}", state));
    EXPECT_EQ(state, PRINTER_IDLE);
    EXPECT_TRUE(ConvertStringToPrinterState("{\"state\":\"1\",\"reason\":\"none\"}", state));
    EXPECT_EQ(state, PRINTER_BUSY);
    EXPECT_TRUE(ConvertStringToPrinterState("{\"state\":\"2\",\"reason\":\"shutdown\"}", state));
    EXPECT_EQ(state, PRINTER_UNAVAILABLE);
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

HWTEST_F(VendorHelperTest, VendorHelperTest_0012, TestSize.Level1)
{
    PrinterInfo printerInfo;
    EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(printerInfo, nullptr));
    Print_DiscoveryItem discoveryItem;
    EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.printerId = "printerId";
    EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.printerName = "printerName";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.description = "description";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.printerUri = "printerUri";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.makeAndModel = "makeAndModel";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.detailInfo = "detailInfo";
    EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.detailInfo = "{\"key\":\"value\"}";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
    discoveryItem.detailInfo = "{\"bsunidriver_support\": \"false\"}";
    EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(printerInfo, &discoveryItem));
}

HWTEST_F(VendorHelperTest, UpdatePrinterDetailInfoToJsonTest, TestSize.Level1)
{
    Json::Value option;
    std::string detailInfo;
    EXPECT_FALSE(UpdatePrinterDetailInfoToJson(option, detailInfo));
    detailInfo = "{\"key\":\"value\"}";
    EXPECT_TRUE(UpdatePrinterDetailInfoToJson(option, detailInfo));
    detailInfo = "{\"bsunidriver_support\":\"false\"}";
    EXPECT_TRUE(UpdatePrinterDetailInfoToJson(option, detailInfo));
    detailInfo = "{\"printer_protocols\":\"ipp,ipps,socket\"}";
    EXPECT_TRUE(UpdatePrinterDetailInfoToJson(option, detailInfo));
    detailInfo = "{\"modelName\":\"testPrinterModel\"}";
    EXPECT_TRUE(UpdatePrinterDetailInfoToJson(option, detailInfo));
    detailInfo = PROTOCOL_JSON;
    EXPECT_TRUE(UpdatePrinterDetailInfoToJson(option, detailInfo));
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_Ipv4_Anonymized, TestSize.Level1)
{
    std::string input = "ipps://192.168.2.106:631/ipp/print, ipp://192.168.2.106:631/ipp/print";
    std::string expected = "ipps://*:631/ipp/print, ipp://*:631/ipp/print";
    EXPECT_EQ(AnonymizeIpInString(input), expected);
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_Ipv6Compressed_Anonymized, TestSize.Level1)
{
    std::string input = "uri ipps://[fe80::1]:631 v6=2001:db8::8a2e:370:7334 loop=::1 tail=fe80::";
    std::string expected = "uri ipps://[*]:631 v6=* loop=* tail=*";
    EXPECT_EQ(AnonymizeIpInString(input), expected);
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_Ipv6Full_Anonymized, TestSize.Level1)
{
    std::string input = "full=2001:0db8:85a3:08d3:1319:8a2e:0370:7334 mac=00:1a:2b:3c:4d:5e";
    std::string expected = "full=* mac=00:1a:2b:3c:4d:5e";
    EXPECT_EQ(AnonymizeIpInString(input), expected);
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_NoIp_Unchanged, TestSize.Level1)
{
    std::string input = "{\"printer-uuid\":\"urn:uuid:cfe92100-67c4-lld4-a45f-dccd2fbedl6e\","
        "\"uri-security-supported\":\"tls, node\",\"mac\":\"00:1a:2b:3c:4d:5e\"}";
    EXPECT_EQ(AnonymizeIpInString(input), input);
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_EmptyString_Unchanged, TestSize.Level1)
{
    std::string input = "";
    EXPECT_TRUE(AnonymizeIpInString(input).empty());
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_MultipleIp_Anonymized, TestSize.Level1)
{
    std::string input = "ips: 192.168.1.1 and 10.20.30.40 and fe80::1";
    std::string expected = "ips: * and * and *";
    EXPECT_EQ(AnonymizeIpInString(input), expected);
}

HWTEST_F(VendorHelperTest, AnonymizeIpInString_MaliciousHexPattern_NoCrash, TestSize.Level1)
{
    std::string input;
    for (int i = 0; i < 1000; ++i) {
        input += "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:0:";
    }
    input += "zzz";
    ASSERT_TRUE(input.size() < 65536);
    std::string result;
    EXPECT_NO_FATAL_FAILURE(result = AnonymizeIpInString(input));
    EXPECT_FALSE(result.empty());
}

bool UpdateColorCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability);

HWTEST_F(VendorHelperTest, UpdateColorCapability_NullCapability_ReturnsFalse, TestSize.Level1)
{
    PrinterCapability printerCap;
    EXPECT_FALSE(UpdateColorCapability(printerCap, nullptr));
}

HWTEST_F(VendorHelperTest, UpdateColorCapability_CountExceedsMax_ReturnsFalse, TestSize.Level1)
{
    PrinterCapability printerCap;
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    std::vector<Print_ColorMode> modes(MAX_COLOR_MODE_COUNT + 1, COLOR_MODE_MONOCHROME);
    capability.supportedColorModes = modes.data();
    capability.supportedColorModesCount = MAX_COLOR_MODE_COUNT + 1;
    EXPECT_FALSE(UpdateColorCapability(printerCap, &capability));
}

HWTEST_F(VendorHelperTest, UpdateColorCapability_NormalCount_ReturnsTrue, TestSize.Level1)
{
    PrinterCapability printerCap;
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    EXPECT_TRUE(UpdateColorCapability(printerCap, &capability));
}

bool UpdateDuplexCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability);

HWTEST_F(VendorHelperTest, UpdateDuplexCapability_CountExceedsMax_ReturnsFalse, TestSize.Level1)
{
    PrinterCapability printerCap;
    Print_PrinterCapability capability = {0};
    BuildCapability(capability);
    std::vector<Print_DuplexMode> modes(MAX_DUPLEX_MODE_COUNT + 1, DUPLEX_MODE_ONE_SIDED);
    capability.supportedDuplexModes = modes.data();
    capability.supportedDuplexModesCount = MAX_DUPLEX_MODE_COUNT + 1;
    EXPECT_FALSE(UpdateDuplexCapability(printerCap, &capability));
}

// ===== ParseCustomPageSizeRangeFromVendor Tests =====

void ParseCustomPageSizeRangeFromVendor(const Print_PrinterCapability *capability, Json::Value &options);

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_NullCapability_OptionsUnchanged, TestSize.Level1)
{
    Json::Value options;
    options["existing"] = "value";
    ParseCustomPageSizeRangeFromVendor(nullptr, options);
    EXPECT_FALSE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
    EXPECT_EQ(options["existing"].asString(), "value");
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_NullSupportedPageSizes_OptionsUnchanged, TestSize.Level1)
{
    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = nullptr;
    capability.supportedPageSizesCount = 0;
    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    EXPECT_FALSE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_HasMinAndMax_RangeSet, TestSize.Level1)
{
    Print_PageSize pageSizes[2];
    pageSizes[0].id = const_cast<char *>("CUSTOM_MIN");
    pageSizes[0].name = const_cast<char *>("Custom Min");
    pageSizes[0].width = 3000;
    pageSizes[0].height = 4000;
    pageSizes[1].id = const_cast<char *>("CUSTOM_MAX");
    pageSizes[1].name = const_cast<char *>("Custom Max");
    pageSizes[1].width = 8000;
    pageSizes[1].height = 12000;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 2;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    ASSERT_TRUE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
    const Json::Value &range = options[CUSTOM_PAGE_SIZE_RANGE_KEY];
    ASSERT_TRUE(range.isObject());
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MIN_WIDTH].asUInt(), 3000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MAX_WIDTH].asUInt(), 8000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MIN_HEIGHT].asUInt(), 4000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MAX_HEIGHT].asUInt(), 12000u);
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_OnlyMin_NoRange, TestSize.Level1)
{
    Print_PageSize pageSizes[1];
    pageSizes[0].id = const_cast<char *>("CUSTOM_MIN");
    pageSizes[0].name = const_cast<char *>("Custom Min");
    pageSizes[0].width = 3000;
    pageSizes[0].height = 4000;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 1;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    // only min present, no max → no range set
    EXPECT_FALSE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_OnlyMax_NoRange, TestSize.Level1)
{
    Print_PageSize pageSizes[1];
    pageSizes[0].id = const_cast<char *>("CUSTOM_MAX");
    pageSizes[0].name = const_cast<char *>("Custom Max");
    pageSizes[0].width = 8000;
    pageSizes[0].height = 12000;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 1;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    // only max present, no min → no range set
    EXPECT_FALSE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_NoCustomPageSizes_NoRange, TestSize.Level1)
{
    Print_PageSize pageSizes[2];
    pageSizes[0].id = const_cast<char *>("ISO_A4");
    pageSizes[0].name = const_cast<char *>("A4");
    pageSizes[0].width = 8268;
    pageSizes[0].height = 11692;
    pageSizes[1].id = const_cast<char *>("ISO_A3");
    pageSizes[1].name = const_cast<char *>("A3");
    pageSizes[1].width = 11690;
    pageSizes[1].height = 16540;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 2;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    EXPECT_FALSE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_NullIdInEntry_Skipped, TestSize.Level1)
{
    Print_PageSize pageSizes[3];
    pageSizes[0].id = nullptr;  // null id → skipped
    pageSizes[0].name = const_cast<char *>("Unknown");
    pageSizes[0].width = 0;
    pageSizes[0].height = 0;
    pageSizes[1].id = const_cast<char *>("CUSTOM_MIN");
    pageSizes[1].name = const_cast<char *>("Custom Min");
    pageSizes[1].width = 3000;
    pageSizes[1].height = 4000;
    pageSizes[2].id = const_cast<char *>("CUSTOM_MAX");
    pageSizes[2].name = const_cast<char *>("Custom Max");
    pageSizes[2].width = 8000;
    pageSizes[2].height = 12000;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 3;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    ASSERT_TRUE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
    const Json::Value &range = options[CUSTOM_PAGE_SIZE_RANGE_KEY];
    ASSERT_TRUE(range.isObject());
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MIN_WIDTH].asUInt(), 3000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MAX_WIDTH].asUInt(), 8000u);
}

HWTEST_F(VendorHelperTest, ParseCustomPageSizeRangeFromVendor_MixedWithRegularPageSizes_RangeSet, TestSize.Level1)
{
    Print_PageSize pageSizes[4];
    pageSizes[0].id = const_cast<char *>("ISO_A4");
    pageSizes[0].name = const_cast<char *>("A4");
    pageSizes[0].width = 8268;
    pageSizes[0].height = 11692;
    pageSizes[1].id = const_cast<char *>("CUSTOM_MIN");
    pageSizes[1].name = const_cast<char *>("Custom Min");
    pageSizes[1].width = 2000;
    pageSizes[1].height = 3000;
    pageSizes[2].id = const_cast<char *>("ISO_A3");
    pageSizes[2].name = const_cast<char *>("A3");
    pageSizes[2].width = 11690;
    pageSizes[2].height = 16540;
    pageSizes[3].id = const_cast<char *>("CUSTOM_MAX");
    pageSizes[3].name = const_cast<char *>("Custom Max");
    pageSizes[3].width = 10000;
    pageSizes[3].height = 15000;

    Print_PrinterCapability capability = {0};
    capability.supportedPageSizes = pageSizes;
    capability.supportedPageSizesCount = 4;

    Json::Value options;
    ParseCustomPageSizeRangeFromVendor(&capability, options);
    ASSERT_TRUE(options.isMember(CUSTOM_PAGE_SIZE_RANGE_KEY));
    const Json::Value &range = options[CUSTOM_PAGE_SIZE_RANGE_KEY];
    ASSERT_TRUE(range.isObject());
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MIN_WIDTH].asUInt(), 2000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MAX_WIDTH].asUInt(), 10000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MIN_HEIGHT].asUInt(), 3000u);
    EXPECT_EQ(range[CUSTOM_PAGE_SIZE_MAX_HEIGHT].asUInt(), 15000u);
}

}  // namespace Print
}  // namespace OHOS