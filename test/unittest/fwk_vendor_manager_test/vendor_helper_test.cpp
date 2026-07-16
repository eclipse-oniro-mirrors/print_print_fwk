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

static bool JsonContainsKey(const std::string &jsonStr, const std::string &key)
{
    Json::Value root;
    if (!PrintJsonUtil::Parse(jsonStr, root)) {
        return false;
    }
    return PrintJsonUtil::IsMember(root, key);
}

static bool JsonStringValueIs(const std::string &jsonStr, const std::string &key, const std::string &expected)
{
    Json::Value root;
    if (!PrintJsonUtil::Parse(jsonStr, root)) {
        return false;
    }
    std::string actual;
    if (!PrintJsonUtil::FindJsonStringMember(root, key, actual)) {
        return false;
    }
    return actual == expected;
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_InvalidJson_KeepOriginal, TestSize.Level1)
{
    std::string input = "";
    std::string original = input;
    RemoveIpFieldsFromRawData(input);
    EXPECT_EQ(input, original);

    input = "{invalid json";
    original = input;
    RemoveIpFieldsFromRawData(input);
    EXPECT_EQ(input, original);

    input = "plain text not json";
    original = input;
    RemoveIpFieldsFromRawData(input);
    EXPECT_EQ(input, original);
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_NonStringValue_KeepAllFields, TestSize.Level1)
{
    std::string input = "{\"port\":631,\"tls\":true,\"copies\":99,\"list\":[\"192.168.1.1\"],"
        "\"obj\":{\"host\":\"10.0.0.1\"}}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_TRUE(JsonContainsKey(input, "port"));
    EXPECT_TRUE(JsonContainsKey(input, "tls"));
    EXPECT_TRUE(JsonContainsKey(input, "copies"));
    EXPECT_TRUE(JsonContainsKey(input, "list"));
    EXPECT_TRUE(JsonContainsKey(input, "obj"));
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_StringWithoutIp_KeepAllFields, TestSize.Level1)
{
    std::string input = "{\"printer-uuid\":\"urn:uuid:cfe92100-67c4-lld4-a45f-dccd2fbedl6e\","
        "\"uri-security-supported\":\"tls, node\","
        "\"printer-name\":\"Office Printer\","
        "\"ipp-versions\":\"1.1, 2.0\","
        "\"mac\":\"00:1a:2b:3c:4d:5e\"}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_TRUE(JsonStringValueIs(input, "printer-uuid", "urn:uuid:cfe92100-67c4-lld4-a45f-dccd2fbedl6e"));
    EXPECT_TRUE(JsonStringValueIs(input, "uri-security-supported", "tls, node"));
    EXPECT_TRUE(JsonStringValueIs(input, "printer-name", "Office Printer"));
    EXPECT_TRUE(JsonStringValueIs(input, "ipp-versions", "1.1, 2.0"));
    EXPECT_TRUE(JsonStringValueIs(input, "mac", "00:1a:2b:3c:4d:5e"));
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_StringWithIpv4_RemoveFields, TestSize.Level1)
{
    std::string input = "{\"printer-uri-supported\":\"ipps://192.168.2.106:631/ipp/print, "
        "ipp://192.168.2.106:631/ipp/print\","
        "\"printer-uuid\":\"urn:uui:cfe92100-67c4-lld4-a45f-dccd2fbedl6e\","
        "\"printer=more-info\":\"http://192.168.2.106:80/PRESENTATION/BONJOUR\","
        "\"uri-security-supported\":\"tls, node\"}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_FALSE(JsonContainsKey(input, "printer-uri-supported"));
    EXPECT_FALSE(JsonContainsKey(input, "printer=more-info"));
    EXPECT_TRUE(JsonStringValueIs(input, "printer-uuid", "urn:uui:cfe92100-67c4-lld4-a45f-dccd2fbedl6e"));
    EXPECT_TRUE(JsonStringValueIs(input, "uri-security-supported", "tls, node"));
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_StringWithIpv6Compressed_RemoveFields, TestSize.Level1)
{
    std::string input = "{\"uri\":\"ipps://[fe80::1]:631/ipp/print\","
        "\"name\":\"printerA\","
        "\"v6\":\"2001:db8::8a2e:370:7334\","
        "\"loopback\":\"::1\","
        "\"trailing\":\"fe80::\","
        "\"dual\":\"::ffff:192.168.1.1\"}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_FALSE(JsonContainsKey(input, "uri"));
    EXPECT_FALSE(JsonContainsKey(input, "v6"));
    EXPECT_FALSE(JsonContainsKey(input, "loopback"));
    EXPECT_FALSE(JsonContainsKey(input, "trailing"));
    EXPECT_FALSE(JsonContainsKey(input, "dual"));
    EXPECT_TRUE(JsonStringValueIs(input, "name", "printerA"));
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_StringWithIpv6Full_RemoveFields, TestSize.Level1)
{
    std::string input = "{\"full\":\"2001:0db8:85a3:08d3:1319:8a2e:0370:7334\","
        "\"mac\":\"00:1a:2b:3c:4d:5e\","
        "\"name\":\"printerB\","
        "\"seven\":\"1:2:3:4:5:6:7\"}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_FALSE(JsonContainsKey(input, "full"));
    EXPECT_TRUE(JsonStringValueIs(input, "mac", "00:1a:2b:3c:4d:5e"));
    EXPECT_TRUE(JsonStringValueIs(input, "name", "printerB"));
    EXPECT_TRUE(JsonStringValueIs(input, "seven", "1:2:3:4:5:6:7"));
}

HWTEST_F(VendorHelperTest, RemoveIpFieldsFromRawData_AllFieldsMatchIp_BecomeEmptyObject, TestSize.Level1)
{
    std::string input = "{}";
    RemoveIpFieldsFromRawData(input);
    EXPECT_EQ(input, "{}");

    input = "{\"a\":\"1.2.3.4\",\"b\":\"::1\",\"c\":\"2001:db8::1\"}";
    RemoveIpFieldsFromRawData(input);
    Json::Value root;
    ASSERT_TRUE(PrintJsonUtil::Parse(input, root));
    EXPECT_TRUE(root.getMemberNames().empty());
}
}  // namespace Print
}  // namespace OHOS