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
#include "print_cups_attribute.h"
#include "print_json_util.h"

using namespace testing;
using namespace testing::ext;

namespace {
const char *const ATTR_TEST_ALL[] = {"all"};
const size_t ATTR_TEST_SIDES_COUNT = 3;
const char *const ATTR_TEST_SIDES_ARRAY[ATTR_TEST_SIDES_COUNT] = {
    "one-sided", "two-sided-long-edge", "two-sided-short-edge"};

const size_t ATTR_TEST_COLOR_MODE_COUNT = 2;
const char *const ATTR_TEST_COLOR_MODE_ARRAY[ATTR_TEST_COLOR_MODE_COUNT] = {"monochrome", "color"};

const size_t ATTR_TEST_PAGE_SIZE_COUNT = 4;
const char *const ATTR_TEST_PAGE_SIZE_ARRAY[ATTR_TEST_PAGE_SIZE_COUNT] = {
    "iso_b3_353x500mm", "iso_a4_210x297mm", "na_letter_8.5x11in", "om_card_54x86mm"};

const size_t ATTR_TEST_QUALITY_COUNT = 3;
const int ATTR_TEST_QUALITY_ARRAY[ATTR_TEST_QUALITY_COUNT] = {IPP_QUALITY_DRAFT, IPP_QUALITY_NORMAL, IPP_QUALITY_HIGH};
const int ATTR_TEST_MAX_COPIES = 99;
const int ATTR_TEST_RESOLUTION_SMALL = 250;  // need change
const int ATTR_TEST_RESOLUTION_DEFAULT = 600;
const int ATTR_TEST_RESULUTION_SMALL_DPCM = 100;

const int ATTR_TEST_PAPER_LEFT = 100;
const int ATTR_TEST_PAPER_RIGHT = 200;
const int ATTR_TEST_PAPER_TOP = 300;
const int ATTR_TEST_PAPER_BOTTOM = 400;

const int ATTR_TEST_ORIENTATION_COUNT = 3;
const int ATTR_TEST_ORIENTATION_ARRAY[ATTR_TEST_ORIENTATION_COUNT] = {
    IPP_ORIENT_PORTRAIT, IPP_ORIENT_LANDSCAPE, IPP_ORIENT_REVERSE_PORTRAIT};

const int ATTR_TEST_SOURCE_COUNT = 2;
const char *const ATTR_TEST_SOURCE_ARRAY[ATTR_TEST_SOURCE_COUNT] = {"main source", "front slot"};

const int ATTR_TEST_DOCUMENT_HANDLING_COUNT = 2;
const char *const ATTR_TEST_DOCUMENT_HANDLING_ARRAY[] = {"separate-uncollated", "multi-collated"};

const int ATTR_TEST_MEDIA_TYPE_COUNT = 3;
const char *const ATTR_TEST_MEDIA_TYPE_ARRAY[ATTR_TEST_MEDIA_TYPE_COUNT] = {"envelope", "stationery", "transparency"};

void TestAttrCount(const std::string &jsonString, int count)
{
    Json::Value jsonArrayObject;
    if (OHOS::Print::PrintJsonUtil::Parse(jsonString, jsonArrayObject)) {
        return;
    }
    if (jsonArrayObject.isArray()) {
        EXPECT_EQ(jsonArrayObject.size(), count);
    }
}
}  // namespace

namespace OHOS::Print {
using PreAttrTestFunc = std::function<void(ipp_t *)>;
using PostResponseTestFunc = std::function<void(ipp_t *)>;
using PostAttrTestFunc = std::function<void(PrinterCapability &)>;
class PrintCupsAttributeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void DoTestResponse(PreAttrTestFunc preFunc, PostResponseTestFunc postFunc);
    void DoTest(PreAttrTestFunc preFunc, PostAttrTestFunc postFunc);
};

void PrintCupsAttributeTest::SetUpTestCase(void)
{}

void PrintCupsAttributeTest::TearDownTestCase(void)
{}

void PrintCupsAttributeTest::SetUp(void)
{}

void PrintCupsAttributeTest::TearDown(void)
{}

void PrintCupsAttributeTest::DoTestResponse(PreAttrTestFunc preFunc, PostResponseTestFunc postFunc)
{
    if (preFunc == nullptr || postFunc == nullptr) {
        return;
    }
    ipp_t *request = ippNewRequest(IPP_OP_GET_PRINTER_ATTRIBUTES);
    if (request == nullptr) {
        return;
    }
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", nullptr, "printer-uri");
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", nullptr, "user");
    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", 1, nullptr, ATTR_TEST_ALL);
    ipp_t *response = ippNewResponse(request);
    ippDelete(request);
    if (response == nullptr) {
        return;
    }
    preFunc(response);
    postFunc(response);
    ippDelete(response);
}

void PrintCupsAttributeTest::DoTest(PreAttrTestFunc preFunc, PostAttrTestFunc postFunc)
{
    PostResponseTestFunc postResponseFunc = [this, postFunc](ipp_t *response) {
        PrinterCapability printerCaps;
        ParsePrinterAttributes(response, printerCaps);
        if (postFunc != nullptr) {
            postFunc(printerCaps);
        }
    };
    DoTestResponse(preFunc, postResponseFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0001
 * @tc.desc: printer idle state test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0001, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_IDLE);
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-info", nullptr, "Printer info test");
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-location", nullptr, "Printer location test");
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-state"), "idle");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-location"), "Printer location test");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0002
 * @tc.desc: printer processing state test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0002, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_PROCESSING);
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-info", nullptr, "");
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-location", nullptr, "");
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-state"), "processing");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-info"), "");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-location"), "");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0003
 * @tc.desc: printer stopped state test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0003, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_STOPPED);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-state"), "stopped");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-info"), "");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-location"), "");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0004
 * @tc.desc: printer empty state test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0004, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {};
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-state"), "");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-info"), "");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("printer-location"), "");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0005
 * @tc.desc: printer sides test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0005, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "sides-supported",
            ATTR_TEST_SIDES_COUNT,
            nullptr,
            ATTR_TEST_SIDES_ARRAY);
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "sides-default", nullptr, ATTR_TEST_SIDES_ARRAY[0]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string sideString = printerCaps.GetPrinterAttrValue("sides-supported");
        TestAttrCount(sideString, ATTR_TEST_SIDES_COUNT);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("sides-default"), "0");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0006
 * @tc.desc: printer sides test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0006, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "sides-default", nullptr, ATTR_TEST_SIDES_ARRAY[1]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string sideString = printerCaps.GetPrinterAttrValue("sides-supported");
        TestAttrCount(sideString, 0);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("sides-default"), "1");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0007
 * @tc.desc: printer color mode test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0007, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "print-color-mode-supported",
            ATTR_TEST_COLOR_MODE_COUNT,
            nullptr,
            ATTR_TEST_COLOR_MODE_ARRAY);
        ippAddString(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "print-color-mode-default",
            nullptr,
            ATTR_TEST_COLOR_MODE_ARRAY[0]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string colorModeString = printerCaps.GetPrinterAttrValue("print-color-mode-supported");
        TestAttrCount(colorModeString, ATTR_TEST_COLOR_MODE_COUNT);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("defaultColorMode"), "0");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0008
 * @tc.desc: printer color mode test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0008, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddString(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "print-color-mode-default",
            nullptr,
            ATTR_TEST_COLOR_MODE_ARRAY[1]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string colorModeString = printerCaps.GetPrinterAttrValue("print-color-mode-supported");
        TestAttrCount(colorModeString, 0);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("defaultColorMode"), "1");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0009
 * @tc.desc: printer page size test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0009, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "media-supported",
            ATTR_TEST_PAGE_SIZE_COUNT,
            nullptr,
            ATTR_TEST_PAGE_SIZE_ARRAY);
        ippAddString(
            response, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "media-default", nullptr, ATTR_TEST_PAGE_SIZE_ARRAY[0]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::vector<PrintPageSize> pageSizeList;
        printerCaps.GetSupportedPageSize(pageSizeList);
        EXPECT_EQ(pageSizeList.size(), ATTR_TEST_PAGE_SIZE_COUNT);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("defaultPageSizeId"), "ISO_B3");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0010
 * @tc.desc: printer page size test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0010, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddString(response,
            IPP_TAG_PRINTER,
            IPP_TAG_KEYWORD,
            "print-color-mode-default",
            nullptr,
            ATTR_TEST_COLOR_MODE_ARRAY[1]);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string pageSizeString = printerCaps.GetPrinterAttrValue("print-color-mode-supported");
        TestAttrCount(pageSizeString, 0);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("defaultPageSizeId"), "");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0011
 * @tc.desc: printer quality / copies test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0011, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddIntegers(response,
            IPP_TAG_PRINTER,
            IPP_TAG_ENUM,
            "print-quality-supported",
            ATTR_TEST_QUALITY_COUNT,
            ATTR_TEST_QUALITY_ARRAY);
        ippAddRange(response, IPP_TAG_PRINTER, "copies-supported", 1, ATTR_TEST_MAX_COPIES);
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "copies-default", 1);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string qualityString = printerCaps.GetPrinterAttrValue("print-quality-supported");
        TestAttrCount(qualityString, ATTR_TEST_QUALITY_COUNT);
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("copies-supported"), std::to_string(ATTR_TEST_MAX_COPIES).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("copies-default"), "1");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0012
 * @tc.desc: printer quality / copies test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0012, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {};
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string pageSizeString = printerCaps.GetPrinterAttrValue("print-quality-supported");
        EXPECT_TRUE(pageSizeString.empty());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("copies-supported"), "");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("copies-default"), "");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0013
 * @tc.desc: printer resolution test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0013, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddResolution(response,
            IPP_TAG_PRINTER,
            "printer-resolution-supported",
            IPP_RES_PER_INCH,
            ATTR_TEST_RESOLUTION_DEFAULT,
            ATTR_TEST_RESOLUTION_DEFAULT);
        ippAddResolution(response,
            IPP_TAG_PRINTER,
            "printer-resolution-default",
            IPP_RES_PER_INCH,
            ATTR_TEST_RESOLUTION_DEFAULT,
            ATTR_TEST_RESOLUTION_DEFAULT);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string supportedResolutionString = printerCaps.GetPrinterAttrValue("printer-resolution-supported");
        TestAttrCount(supportedResolutionString, 1);
        std::string defaultResolutionString = printerCaps.GetPrinterAttrValue("printer-resolution-default");
        std::istringstream iss(defaultResolutionString);
        Json::Value defaultResolutionJson;
        EXPECT_TRUE(OHOS::Print::PrintJsonUtil::ParseFromStream(iss, defaultResolutionJson));
        EXPECT_TRUE(PrintJsonUtil::IsMember(defaultResolutionJson, "horizontalDpi"));
        EXPECT_TRUE(PrintJsonUtil::IsMember(defaultResolutionJson, "verticalDpi"));
        EXPECT_TRUE(defaultResolutionJson["horizontalDpi"].isInt());
        EXPECT_TRUE(defaultResolutionJson["verticalDpi"].isInt());
        EXPECT_EQ(defaultResolutionJson["horizontalDpi"], ATTR_TEST_RESOLUTION_DEFAULT);
        EXPECT_EQ(defaultResolutionJson["verticalDpi"], ATTR_TEST_RESOLUTION_DEFAULT);
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0014
 * @tc.desc: printer resolution test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0014, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddResolution(response,
            IPP_TAG_PRINTER,
            "printer-resolution-default",
            IPP_RES_PER_CM,
            ATTR_TEST_RESULUTION_SMALL_DPCM,
            ATTR_TEST_RESULUTION_SMALL_DPCM);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string supportedResolutionString = printerCaps.GetPrinterAttrValue("printer-resolution-supported");
        EXPECT_TRUE(supportedResolutionString.empty());
        std::string defaultResolutionString = printerCaps.GetPrinterAttrValue("printer-resolution-default");
        std::istringstream iss(defaultResolutionString);
        Json::Value defaultResolutionJson;
        EXPECT_TRUE(OHOS::Print::PrintJsonUtil::ParseFromStream(iss, defaultResolutionJson));
        EXPECT_TRUE(defaultResolutionJson.isMember("horizontalDpi"));
        EXPECT_TRUE(defaultResolutionJson.isMember("verticalDpi"));
        EXPECT_TRUE(defaultResolutionJson["horizontalDpi"].isInt());
        EXPECT_TRUE(defaultResolutionJson["verticalDpi"].isInt());
        EXPECT_EQ(defaultResolutionJson["horizontalDpi"], ATTR_TEST_RESOLUTION_SMALL);
        EXPECT_EQ(defaultResolutionJson["verticalDpi"], ATTR_TEST_RESOLUTION_SMALL);
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0015
 * @tc.desc: printer media test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0015, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        auto mediaCol = ippNew();
        if (mediaCol == nullptr) {
            return;
        }
        ippAddInteger(mediaCol, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-bottom-margin", ATTR_TEST_PAPER_BOTTOM);
        ippAddInteger(mediaCol, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-left-margin", ATTR_TEST_PAPER_LEFT);
        ippAddInteger(mediaCol, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-right-margin", ATTR_TEST_PAPER_RIGHT);
        ippAddInteger(mediaCol, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-top-margin", ATTR_TEST_PAPER_TOP);
        ippAddBoolean(mediaCol, IPP_TAG_PRINTER, "duplex-supported", 1);
        ippAddString(mediaCol, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "media-source", nullptr, "Front Input Slot");
        ippAddString(mediaCol, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "media-type", nullptr, "stationery");
        ippAddCollection(response, IPP_TAG_PRINTER, "media-col-default", mediaCol);
        ippDelete(mediaCol);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(
            printerCaps.GetPrinterAttrValue("media-top-margin-default"), std::to_string(ATTR_TEST_PAPER_TOP).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-bottom-margin-default"),
            std::to_string(ATTR_TEST_PAPER_BOTTOM).c_str());
        EXPECT_STREQ(
            printerCaps.GetPrinterAttrValue("media-left-margin-default"), std::to_string(ATTR_TEST_PAPER_LEFT).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-right-margin-default"),
            std::to_string(ATTR_TEST_PAPER_RIGHT).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-source-default"), "Front Input Slot");
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-type-default"), "stationery");
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0016
 * @tc.desc: printer margin test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0016, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(
            response, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-bottom-margin-supported", ATTR_TEST_PAPER_BOTTOM);
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-left-margin-supported", ATTR_TEST_PAPER_LEFT);
        ippAddInteger(
            response, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-right-margin-supported", ATTR_TEST_PAPER_RIGHT);
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "media-top-margin-supported", ATTR_TEST_PAPER_TOP);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(
            printerCaps.GetPrinterAttrValue("media-top-margin-supported"), std::to_string(ATTR_TEST_PAPER_TOP).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-bottom-margin-supported"),
            std::to_string(ATTR_TEST_PAPER_BOTTOM).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-left-margin-supported"),
            std::to_string(ATTR_TEST_PAPER_LEFT).c_str());
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("media-right-margin-supported"),
            std::to_string(ATTR_TEST_PAPER_RIGHT).c_str());
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0017
 * @tc.desc: printer orientation test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0017, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "orientation-requested-default", IPP_ORIENT_PORTRAIT);
        ippAddIntegers(response,
            IPP_TAG_PRINTER,
            IPP_TAG_ENUM,
            "orientation-requested-supported",
            ATTR_TEST_ORIENTATION_COUNT,
            ATTR_TEST_ORIENTATION_ARRAY);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        EXPECT_STREQ(printerCaps.GetPrinterAttrValue("orientation-requested-default"), "3");
        std::string orientationString = printerCaps.GetPrinterAttrValue("orientation-requested-supported");
        TestAttrCount(orientationString, ATTR_TEST_ORIENTATION_COUNT);
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0018
 * @tc.desc: printer other attributes test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0018, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_CONST_TAG(IPP_TAG_KEYWORD),
            "media-source-supported",
            ATTR_TEST_SOURCE_COUNT,
            nullptr,
            ATTR_TEST_SOURCE_ARRAY);
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_CONST_TAG(IPP_TAG_KEYWORD),
            "multiple-document-handling-supported",
            ATTR_TEST_DOCUMENT_HANDLING_COUNT,
            nullptr,
            ATTR_TEST_DOCUMENT_HANDLING_ARRAY);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string sourceString = printerCaps.GetPrinterAttrValue("media-source-supported");
        TestAttrCount(sourceString, ATTR_TEST_SOURCE_COUNT);
        std::string documentHandlingString = printerCaps.GetPrinterAttrValue("multiple-document-handling-supported");
        TestAttrCount(documentHandlingString, ATTR_TEST_DOCUMENT_HANDLING_COUNT);
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0019
 * @tc.desc: printer option test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0019, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-make-and-model", nullptr, "Test make and model");
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_URI, "printer-uuid", nullptr, "Test printer uuid");
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_NAME, "printer-name", nullptr, "Test printer name");
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-location", nullptr, "Printer location test");
        ippAddStrings(response,
            IPP_TAG_PRINTER,
            IPP_CONST_TAG(IPP_TAG_KEYWORD),
            "media-type-supported",
            ATTR_TEST_MEDIA_TYPE_COUNT,
            nullptr,
            ATTR_TEST_MEDIA_TYPE_ARRAY);
    };
    PostAttrTestFunc postFunc = [this](PrinterCapability &printerCaps) {
        std::string mediaTypeString = printerCaps.GetPrinterAttrValue("media-type-supported");
        TestAttrCount(mediaTypeString, ATTR_TEST_MEDIA_TYPE_COUNT);
    };
    DoTest(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0020
 * @tc.desc: ParsePrinterStatusAttributes test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0020, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PSTATE_IDLE);
    };
    PostResponseTestFunc postFunc = [this](ipp_t *response) {
        PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
        EXPECT_TRUE(ParsePrinterStatusAttributes(response, status));
        EXPECT_EQ(status, PRINTER_STATUS_IDLE);
    };
    DoTestResponse(preFunc, postFunc);
}
/**
 * @tc.name: PrintCupsAttributeTest_0021
 * @tc.desc: ParsePrinterStatusAttributes test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0021, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_NAME, "printer-name", nullptr, "Test printer name");
    };
    PostResponseTestFunc postFunc = [this](ipp_t *response) {
        PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
        EXPECT_FALSE(ParsePrinterStatusAttributes(response, status));
    };
    DoTestResponse(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0022
 * @tc.desc: ParsePrinterStatusAttributes test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0022, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", 0);
    };
    PostResponseTestFunc postFunc = [this](ipp_t *response) {
        PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
        EXPECT_FALSE(ParsePrinterStatusAttributes(response, status));
    };
    DoTestResponse(preFunc, postFunc);
}

/**
 * @tc.name: PrintCupsAttributeTest_0023
 * @tc.desc: ParsePrinterStatusAttributes test
 */
HWTEST_F(PrintCupsAttributeTest, PrintCupsAttributeTest_0023, TestSize.Level1)
{
    PreAttrTestFunc preFunc = [this](ipp_t *response) {
        ippAddInteger(response, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PSTATE_STOPPED + 1);
    };
    PostResponseTestFunc postFunc = [this](ipp_t *response) {
        PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
        EXPECT_FALSE(ParsePrinterStatusAttributes(response, status));
    };
    DoTestResponse(preFunc, postFunc);
}
}  // namespace OHOS::Print