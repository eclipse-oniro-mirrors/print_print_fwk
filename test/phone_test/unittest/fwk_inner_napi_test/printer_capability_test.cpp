/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "printer_capability.h"
#include "print_margin.h"
#include "print_resolution.h"
#include "print_json_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrinterCapabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrinterCapabilityTest::SetUpTestCase(void)
{}

void PrinterCapabilityTest::TearDownTestCase(void)
{}

void PrinterCapabilityTest::SetUp(void)
{}

void PrinterCapabilityTest::TearDown(void)
{}

/**
 * @tc.name: PrinterCapabilityTest_0002
 * @tc.desc: Verify settings and obtain colorMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0002, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    capability.Reset();
    EXPECT_EQ((uint32_t)0, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0003
 * @tc.desc: Verify settings and obtain hasMargin function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0003, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin;
    capability.SetMinMargin(margin);
    EXPECT_EQ(true, capability.HasMargin());
}

/**
 * @tc.name: PrinterCapabilityTest_0004
 * @tc.desc: Verify settings and obtain hasMargin function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0004, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, copyMargin;
    capability.SetMinMargin(margin);
    capability.GetMinMargin(copyMargin);
    EXPECT_FALSE(copyMargin.HasRight());
}

/**
 * @tc.name: PrinterCapabilityTest_0005
 * @tc.desc: Verify settings and obtain pageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0005, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    PrintPageSize testPagesize;
    testPagesize.SetWidth(1);
    pagesize.emplace_back(testPagesize);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(pagesize.size(), getPagesize.size());
}

/**
 * @tc.name: PrinterCapabilityTest_0006
 * @tc.desc: Verify settings and obtain Resolution function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0006, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintResolution> resolution, getResolution;
    PrintResolution testResolution;
    testResolution.SetHorizontalDpi(1);
    resolution.emplace_back(testResolution);
    capability.SetResolution(resolution);
    capability.GetResolution(getResolution);
    EXPECT_EQ(resolution.size(), getResolution.size());
}

/**
 * @tc.name: PrinterCapabilityTest_0007
 * @tc.desc: Verify settings and obtain hasResolution function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0007, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintResolution> resolution;
    capability.SetResolution(resolution);
    EXPECT_EQ(true, capability.HasResolution());
}

/**
 * @tc.name: PrinterCapabilityTest_0008
 * @tc.desc: Verify settings and obtain colorMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0008, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0009
 * @tc.desc: Verify settings and obtain duplexMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0009, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetDuplexMode(6);
    EXPECT_EQ((uint32_t)6, capability.GetDuplexMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0010
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0010, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);

    capability.SetMinMargin(margin);
    capability.SetSupportedPageSize(pagesize);
    capability.SetResolution(resolutionList);
    Parcel parcel;
    EXPECT_EQ(capability.Marshalling(parcel), true);
}

/**
 * @tc.name: PrinterCapabilityTest_0011
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0011, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);
    capability.SetSupportedPageSize(pagesize);
    Parcel parcel;
    EXPECT_EQ(capability.Marshalling(parcel), true);
}

/**
 * @tc.name: PrinterCapabilityTest_0012
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0012, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);
    capability.SetMinMargin(margin);
    capability.SetSupportedPageSize(pagesize);
    capability.SetResolution(resolutionList);
    Parcel parcel;
    capability.Marshalling(parcel);
    auto result = OHOS::Print::PrinterCapability::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    capability.Dump();
}

/**
 * @tc.name: PrinterCapabilityTest_0013
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0013, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    PrinterCapability copyCapability(capability);
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0014
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0014, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    PrinterCapability copyCapability = capability;
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0015
 * @tc.desc: GetPrinterAttrValue.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0015, TestSize.Level2)
{
    PrinterCapability capability;
    capability.GetPrinterAttrGroupJson();
    capability.SetPrinterAttrNameAndValue("key1", "value1");
    capability.SetPrinterAttrNameAndValue("key2", "value2");
    EXPECT_STREQ(capability.GetPrinterAttrValue("key1"), "value1");
    EXPECT_STREQ(capability.GetPrinterAttrValue("key"), "");
    capability.ClearCurPrinterAttrGroup();
}

/**
 * @tc.name: PrinterCapabilityTest_00016
 * @tc.desc: Verify set duplicate pageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0016, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    pagesize.emplace_back("page1", "page1", 1, 1);
    pagesize.emplace_back("page2", "page2", 1, 1);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 1);
}

/**
 * @tc.name: PrinterCapabilityTest_0017
 * @tc.desc: Verify empty pageSize list returns empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0017, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 0);
}

/**
 * @tc.name: PrinterCapabilityTest_0018
 * @tc.desc: Verify single pageSize with no duplicate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0018, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    pagesize.emplace_back("page1", "A4", 210000, 297000);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 1);
}

/**
 * @tc.name: PrinterCapabilityTest_0019
 * @tc.desc: Verify all custom pageSize handled correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0019, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    pagesize.emplace_back("page1", "Custom.A4", 4000, 5000);
    pagesize.emplace_back("page2", "Custom.Letter", 5000, 4000);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 2);
}

/**
 * @tc.name: PrinterCapabilityTest_0020
 * @tc.desc: Verify mixed custom and standard pageSize with duplicate dimensions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0020, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    pagesize.emplace_back("page1", "A4", 1, 1);
    pagesize.emplace_back("page2", "Custom.A4", 1, 1);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 1);
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_HasOptionFalse_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_OptionEmpty_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetOption("");
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_InvalidJson_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetOption("invalid json string");
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_NotJsonObject_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetOption("\"just a string\"");
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_CupsOptionsNotObject_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    capJson["cupsOptions"] = "not an object";
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_AdvanceOptionsNotString_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    cupsOptions["advanceOptions"] = 123;
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_AdvanceOptionsParseFail_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    cupsOptions["advanceOptions"] = "invalid json";
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_AdvanceOptionsNotArray_ReturnFalse, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    cupsOptions["advanceOptions"] = "{\"key\":\"value\"}";
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    Json::Value advanceOptionsJson;
    EXPECT_EQ(false, capability.GetAdvanceOptionsJson(advanceOptionsJson));
}

HWTEST_F(PrinterCapabilityTest, GetAdvanceOptionsJson_ValidAdvanceOptions_ReturnTrue, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    Json::Value advanceOptions;
    Json::Value opt;
    opt["keyword"] = "CustomPin";
    opt["customParamType"] = 1;
    advanceOptions.append(opt);
    cupsOptions["advanceOptions"] = PrintJsonUtil::WriteString(advanceOptions);
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    Json::Value advanceOptionsJson;
    EXPECT_EQ(true, capability.GetAdvanceOptionsJson(advanceOptionsJson));
    EXPECT_EQ(true, advanceOptionsJson.isArray());
}

HWTEST_F(PrinterCapabilityTest, GetCustomOptionKeys_GetAdvanceOptionsFail_ReturnEmpty, TestSize.Level2)
{
    PrinterCapability capability;
    std::set<std::string> keys = capability.GetCustomOptionKeys();
    EXPECT_EQ(true, keys.empty());
}

HWTEST_F(PrinterCapabilityTest, GetCustomOptionKeys_NoCustomOptions_ReturnEmpty, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    Json::Value advanceOptions;
    Json::Value opt;
    opt["keyword"] = "CustomPin";
    advanceOptions.append(opt);
    cupsOptions["advanceOptions"] = PrintJsonUtil::WriteString(advanceOptions);
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    std::set<std::string> keys = capability.GetCustomOptionKeys();
    EXPECT_EQ(true, keys.empty());
}

HWTEST_F(PrinterCapabilityTest, GetCustomOptionKeys_HasCustomOptions_ReturnKeys, TestSize.Level2)
{
    PrinterCapability capability;
    Json::Value capJson;
    Json::Value cupsOptions;
    Json::Value advanceOptions;
    Json::Value opt1;
    opt1["keyword"] = "CustomPin";
    opt1["customParamType"] = 1;
    advanceOptions.append(opt1);
    Json::Value opt2;
    opt2["keyword"] = "CustomPassword";
    opt2["customParamType"] = 2;
    advanceOptions.append(opt2);
    cupsOptions["advanceOptions"] = PrintJsonUtil::WriteString(advanceOptions);
    capJson["cupsOptions"] = cupsOptions;
    capability.SetOption(PrintJsonUtil::WriteString(capJson));
    std::set<std::string> keys = capability.GetCustomOptionKeys();
    EXPECT_EQ(2, keys.size());
    EXPECT_EQ(true, keys.find("CustomPin") != keys.end());
    EXPECT_EQ(true, keys.find("CustomPassword") != keys.end());
}
}  // namespace Print
}  // namespace OHOS
