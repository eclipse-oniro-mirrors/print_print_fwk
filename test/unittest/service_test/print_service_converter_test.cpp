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
#include <string>
#include <vector>
#include <cmath>
#include <limits>
#include "print_service_converter.h"
#include "print_page_size.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
bool ConvertStrToDouble(const std::string& str, double& value);
bool ConvertCustomPageSizeFromWidthAndLength(const double& widthValue, const double& lengthValue,
    const std::string& unit, PrintPageSize &dst);

class PrintServiceConverterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceConverterTest::SetUpTestCase(void)
{}

void PrintServiceConverterTest::TearDownTestCase(void)
{}

void PrintServiceConverterTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintServiceConverterTest_%{public}d", ++testNo);
}

void PrintServiceConverterTest::TearDown(void)
{}

/**
 * @tc.name: PrintServiceConverterTest_0001
 * @tc.desc: reportPrintSuccess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0001_NeedRename, TestSize.Level1)
{
    int dpc = 120;
    EXPECT_EQ(DpcToDpi(dpc), 300);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0002_NeedRename, TestSize.Level1)
{
    std::vector<std::string> list;
    list.push_back("1111");
    list.push_back("2222");
    std::string value = "1111";
    AddToUniqueList(list, value);
    EXPECT_EQ(list.size(), 2);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0003_NeedRename, TestSize.Level1)
{
    std::vector<std::string> list;
    list.push_back("1111");
    list.push_back("2222");
    std::string value = "3333";
    AddToUniqueList(list, value);
    EXPECT_EQ(list.size(), 3);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0004_NeedRename, TestSize.Level1)
{
    int code = 3;
    EXPECT_EQ(GetQulityString(code), "3");
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0005_NeedRename, TestSize.Level1)
{
    const char *src = nullptr;
    ColorModeCode dst;
    EXPECT_EQ(ConvertColorModeCode(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0006_NeedRename, TestSize.Level1)
{
    PrintPageSize pageSize;
    Json::Value jsonObject;
    EXPECT_EQ(ConvertPageSizeToJson(pageSize, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0007_NeedRename, TestSize.Level1)
{
    const char *src = "color";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 1);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0008_NeedRename, TestSize.Level1)
{
    const char *src = "monochrome";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 0);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0009_NeedRename, TestSize.Level1)
{
    const char *src = "auto";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 2);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0010_NeedRename, TestSize.Level1)
{
    const char *src = "sss";
    ColorModeCode dst;
    EXPECT_EQ(ConvertColorModeCode(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0011_NeedRename, TestSize.Level1)
{
    ColorModeCode code = ColorModeCode::COLOR_MODE_COLOR;
    Json::Value jsonObject;
    EXPECT_EQ(ConvertColorModeToJson(code, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0012_NeedRename, TestSize.Level1)
{
    DuplexModeCode code = DuplexModeCode::DUPLEX_MODE_ONE_SIDED;
    Json::Value jsonObject;
    EXPECT_EQ(ConvertDuplexModeToJson(code, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0013_NeedRename, TestSize.Level1)
{
    const char *src = nullptr;
    std::string id = "";
    EXPECT_EQ(ConvertPageSizeId(src, id), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0014_NeedRename, TestSize.Level1)
{
    const char *src = "iso_a4_210x297mm";
    std::string id = "";
    EXPECT_EQ(ConvertPageSizeId(src, id), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0015_NeedRename, TestSize.Level1)
{
    const char *src = nullptr;
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0016_NeedRename, TestSize.Level1)
{
    const char *src = "iso_a4_210x297mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0017_NeedRename, TestSize.Level1)
{
    const char *src = "na_number-10_4.125x9.5in";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0018_NeedRename, TestSize.Level1)
{
    const char *src = "custom_390.03x540.03mm_390.03x540.03mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0019_NeedRename, TestSize.Level1)
{
    const char *src = "nanumber";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0020_NeedRename, TestSize.Level1)
{
    const char *src = "custom_min_50.8x85.94mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0021_NeedRename, TestSize.Level1)
{
    const char *src = "custom_390.03x540.03mm_390.03540.03mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0022_NeedRename, TestSize.Level1)
{
    const char *src = "custom_390.03x540.03mm_390.03x540.03cm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0023
 * @tc.desc: ConvertStrToDouble with a valid finite number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0023_ConvertStrToDouble_ValidNumber_ReturnsTrue, TestSize.Level1)
{
    double value = 0.0;
    EXPECT_EQ(ConvertStrToDouble(std::string("100.0"), value), true);
    EXPECT_EQ(value, 100.0);
}

/**
 * @tc.name: PrintServiceConverterTest_0024
 * @tc.desc: ConvertStrToDouble with inf (non-finite) value should be rejected by isfinite check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0024_ConvertStrToDouble_InfValue_ReturnsFalse, TestSize.Level1)
{
    double value = 0.0;
    EXPECT_EQ(ConvertStrToDouble(std::string("inf"), value), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0025
 * @tc.desc: ConvertStrToDouble with nan (non-finite) value should be rejected by isfinite check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0025_ConvertStrToDouble_NanValue_ReturnsFalse, TestSize.Level1)
{
    double value = 0.0;
    EXPECT_EQ(ConvertStrToDouble(std::string("nan"), value), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0026
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with negative width
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0026_ConvertCustomPageSizeFromWidthAndLength_NegativeWidth_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(-1.0, 200.0, std::string("mm"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0027
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with negative length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0027_ConvertCustomPageSizeFromWidthAndLength_NegativeLength_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, -1.0, std::string("mm"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0028
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with infinite width
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0028_ConvertCustomPageSizeFromWidthAndLength_InfWidth_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(
        std::numeric_limits<double>::infinity(), 200.0, std::string("mm"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0029
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with nan length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0029_ConvertCustomPageSizeFromWidthAndLength_NanLength_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, NAN, std::string("mm"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0030
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with mm unit overflow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0030_ConvertCustomPageSizeFromWidthAndLength_MmOverflow_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(1e30, 200.0, std::string("mm"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0031
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with in unit overflow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0031_ConvertCustomPageSizeFromWidthAndLength_InOverflow_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(1e30, 200.0, std::string("in"), dst), false);
}

/**
 * @tc.name: PrintServiceConverterTest_0032
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with valid mm values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0032_ConvertCustomPageSizeFromWidthAndLength_ValidMm_ReturnsTrue, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, 200.0, std::string("mm"), dst), true);
    EXPECT_EQ(dst.GetWidth(), 3937u);
    EXPECT_EQ(dst.GetHeight(), 7874u);
    EXPECT_EQ(dst.GetId(), std::string("Custom.100x200mm"));
}

/**
 * @tc.name: PrintServiceConverterTest_0033
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with valid in values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0033_ConvertCustomPageSizeFromWidthAndLength_ValidIn_ReturnsTrue, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(8.5, 11.0, std::string("in"), dst), true);
    EXPECT_EQ(dst.GetWidth(), 8500u);
    EXPECT_EQ(dst.GetHeight(), 11000u);
    EXPECT_EQ(dst.GetId(), std::string("Custom.216x279mm"));
}

/**
 * @tc.name: PrintServiceConverterTest_0034
 * @tc.desc: ConvertCustomPageSizeFromWidthAndLength with unsupported unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0034_ConvertCustomPageSizeFromWidthAndLength_InvalidUnit_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, 200.0, std::string("cm"), dst), false);
}

}  // namespace Print
}  // namespace OHOS
