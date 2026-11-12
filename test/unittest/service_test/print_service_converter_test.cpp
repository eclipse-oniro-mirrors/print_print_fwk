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
#include <cstdint>
#include <limits>
#include "print_service_converter.h"
#include "print_page_size.h"
#include "print_constant.h"
#include "print_util.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
bool ConvertPwgSizeField(const std::string &sizeName, PrintPageSize &dst);
bool SplitPwgKeyword(const std::string &pwgNameStr, std::string &middleName, std::string &sizeName);

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

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0023_StrToDouble_Valid, TestSize.Level1)
{
    double value = 0.0;
    EXPECT_EQ(ConvertStrToDouble(std::string("100.0"), value), true);
    EXPECT_EQ(value, 100.0);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0024_StrToDouble_Inf, TestSize.Level1)
{
    double value = 0.0;
    EXPECT_EQ(ConvertStrToDouble(std::string("inf"), value), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0026_CustomPageSize_NegWidth, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(-1.0, 200.0, std::string("mm"), dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0028_CustomPageSize_InfWidth, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(
        std::numeric_limits<double>::infinity(), 200.0, std::string("mm"), dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0030_CustomPageSize_MmOverflow, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(1e30, 200.0, std::string("mm"), dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0032_CustomPageSize_ValidMm, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, 200.0, std::string("mm"), dst), true);
    EXPECT_EQ(dst.GetWidth(), 3937u);
    EXPECT_EQ(dst.GetHeight(), 7874u);
    EXPECT_EQ(dst.GetId(), std::string("Custom.100x200mm"));
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0034_CustomPageSize_InvalidUnit, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_EQ(ConvertCustomPageSizeFromWidthAndLength(100.0, 200.0, std::string("cm"), dst), false);
}

/**
 * @tc.name: NormalizeCustomPageSizeList_ValidFormat_ParsesWidthHeight
 * @tc.desc: Verify NormalizeCustomPageSizeList parses width/height from <user-input>(<w>x<h>mm).
 * @tc.type: FUNC
 */
HWTEST_F(PrintServiceConverterTest, NormalizeCustomPageSizeList_ValidFormat_ParsesWidthHeight, TestSize.Level1)
{
    std::vector<PrintPageSize> entryList;
    PrintPageSize item;
    item.SetName("MyForm(210x297mm)");
    entryList.push_back(item);
    NormalizeCustomPageSizeList(entryList);
    EXPECT_EQ(entryList.size(), 1u);
    EXPECT_EQ(entryList[0].GetWidth(), 8268u);
    EXPECT_EQ(entryList[0].GetHeight(), 11693u);
}

/**
 * @tc.name: NormalizeCustomPageSizeList_NoParen_Removed
 * @tc.desc: Verify NormalizeCustomPageSizeList removes entries without parenthesized suffix.
 * @tc.type: FUNC
 */
HWTEST_F(PrintServiceConverterTest, NormalizeCustomPageSizeList_NoParen_Removed, TestSize.Level1)
{
    std::vector<PrintPageSize> entryList;
    PrintPageSize item;
    item.SetName("MyForm");
    entryList.push_back(item);
    NormalizeCustomPageSizeList(entryList);
    EXPECT_TRUE(entryList.empty());
}

/**
 * @tc.name: NormalizeCustomPageSizeList_NoXInParen_Removed
 * @tc.desc: Verify NormalizeCustomPageSizeList removes entries without 'x' inside parens.
 * @tc.type: FUNC
 */
HWTEST_F(PrintServiceConverterTest, NormalizeCustomPageSizeList_NoXInParen_Removed, TestSize.Level1)
{
    std::vector<PrintPageSize> entryList;
    PrintPageSize item;
    item.SetName("MyForm(210mm)");
    entryList.push_back(item);
    NormalizeCustomPageSizeList(entryList);
    EXPECT_TRUE(entryList.empty());
}

/**
 * @tc.name: NormalizeCustomPageSizeList_NonNumeric_Removed
 * @tc.desc: Verify NormalizeCustomPageSizeList removes entries with non-numeric dimensions.
 * @tc.type: FUNC
 */
HWTEST_F(PrintServiceConverterTest, NormalizeCustomPageSizeList_NonNumeric_Removed, TestSize.Level1)
{
    std::vector<PrintPageSize> entryList;
    PrintPageSize item;
    item.SetName("MyForm(axbxmm)");
    entryList.push_back(item);
    NormalizeCustomPageSizeList(entryList);
    EXPECT_TRUE(entryList.empty());
}

/**
 * @tc.name: NormalizeCustomPageSizeList_MissingMmSuffix_Removed
 * @tc.desc: Verify NormalizeCustomPageSizeList removes entries missing mm suffix inside parens.
 * @tc.type: FUNC
 */
HWTEST_F(PrintServiceConverterTest, NormalizeCustomPageSizeList_MissingMmSuffix_Removed, TestSize.Level1)
{
    std::vector<PrintPageSize> entryList;
    PrintPageSize item;
    item.SetName("MyForm(210x297)");
    entryList.push_back(item);
    NormalizeCustomPageSizeList(entryList);
    EXPECT_TRUE(entryList.empty());
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0035_DpcToDpi_OverflowAndBoundary, TestSize.Level1)
{
    // 边界值
    EXPECT_EQ(DpcToDpi(7158278), 17895695);
    // 正向溢出
    EXPECT_EQ(DpcToDpi(7158279), 0);
    // 负向溢出
    EXPECT_EQ(DpcToDpi(-7158279), 0);
    // 负值正常
    EXPECT_EQ(DpcToDpi(-120), -300);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0039_CustomPageSize_MultiScenario, TestSize.Level1)
{
    PrintPageSize dst;
    // 有效 mm
    EXPECT_TRUE(ConvertCustomPageSizeFromWidthAndLength(100.0, 200.0, "mm", dst));
    // 负宽度
    EXPECT_FALSE(ConvertCustomPageSizeFromWidthAndLength(-100.0, 200.0, "mm", dst));
    // 溢出
    EXPECT_FALSE(ConvertCustomPageSizeFromWidthAndLength(200000000.0, 200000000.0, "mm", dst));
    // 有效 inch
    EXPECT_TRUE(ConvertCustomPageSizeFromWidthAndLength(1.0, 1.0, "in", dst));
}

// ===== SplitPwgKeyword Tests =====

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_ValidKeyword_PartsSplit, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    EXPECT_TRUE(SplitPwgKeyword("custom_min_210x297mm", middleName, sizeName));
    EXPECT_EQ(middleName, "min");
    EXPECT_EQ(sizeName, "210x297mm");
}

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_NoUnderscore_ReturnsFalse, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    EXPECT_FALSE(SplitPwgKeyword("210x297mm", middleName, sizeName));
}

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_OnlyOneUnderscore_ReturnsFalse, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    EXPECT_FALSE(SplitPwgKeyword("custom_210x297mm", middleName, sizeName));
}

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_TrailingUnderscoreEmptySize_ReturnsFalse, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    // lastPart + 1 >= size: "custom_min_" has empty size after last underscore
    EXPECT_FALSE(SplitPwgKeyword("custom_min_", middleName, sizeName));
}

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_AdjacentUnderscoresEmptyMiddle_ReturnsFalse, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    // lastPart <= firstPart + 1 means empty middle
    EXPECT_FALSE(SplitPwgKeyword("custom__210x297mm", middleName, sizeName));
}

HWTEST_F(PrintServiceConverterTest, SplitPwgKeyword_EmptyString_ReturnsFalse, TestSize.Level1)
{
    std::string middleName;
    std::string sizeName;
    EXPECT_FALSE(SplitPwgKeyword("", middleName, sizeName));
}

// ===== ConvertPwgSizeField Tests =====

HWTEST_F(PrintServiceConverterTest, ConvertPwgSizeField_ValidMm_Succeeds, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_TRUE(ConvertPwgSizeField("210x297mm", dst));
    EXPECT_EQ(dst.GetWidth(), 8268u);
    EXPECT_EQ(dst.GetHeight(), 11693u);
}

HWTEST_F(PrintServiceConverterTest, ConvertPwgSizeField_ValidInch_Succeeds, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_TRUE(ConvertPwgSizeField("8.5x11in", dst));
    EXPECT_GT(dst.GetWidth(), 0u);
    EXPECT_GT(dst.GetHeight(), 0u);
}

HWTEST_F(PrintServiceConverterTest, ConvertPwgSizeField_InvalidFormats_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    // :179 no 'x' separator (empty string also hits this branch via find==npos)
    EXPECT_FALSE(ConvertPwgSizeField("210297mm", dst));
    EXPECT_FALSE(ConvertPwgSizeField("", dst));
    // :180 'x' at end, no length value
    EXPECT_FALSE(ConvertPwgSizeField("210x", dst));
    // :181 too short to hold the 2-char unit suffix after 'x'
    EXPECT_FALSE(ConvertPwgSizeField("210x2", dst));
    // :190 non-numeric width / length fails ConvertStrToDouble
    EXPECT_FALSE(ConvertPwgSizeField("abcx297mm", dst));
    // :194 unsupported unit "cm" rejected by ConvertCustomPageSizeFromWidthAndLength
    EXPECT_FALSE(ConvertPwgSizeField("210x297cm", dst));
}

// ===== ConvertCustomPageSizeBound Tests =====

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_MinBound_Succeeds, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    EXPECT_TRUE(ConvertCustomPageSizeBound("custom_min_100x200mm", isMinBound, widthMils, heightMils));
    EXPECT_TRUE(isMinBound);
    EXPECT_EQ(widthMils, 3937u);
    EXPECT_EQ(heightMils, 7874u);
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_MaxBound_Succeeds, TestSize.Level1)
{
    bool isMinBound = true;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    EXPECT_TRUE(ConvertCustomPageSizeBound("custom_max_210x297mm", isMinBound, widthMils, heightMils));
    EXPECT_FALSE(isMinBound);
    EXPECT_EQ(widthMils, 8268u);
    EXPECT_EQ(heightMils, 11693u);
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_NullSrc_ReturnsFalse, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    EXPECT_FALSE(ConvertCustomPageSizeBound(nullptr, isMinBound, widthMils, heightMils));
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_NoBoundKeyword_ReturnsFalse, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    // middle name is neither "min" nor "max"
    EXPECT_FALSE(ConvertCustomPageSizeBound("custom_other_210x297mm", isMinBound, widthMils, heightMils));
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_InvalidSizeField_ReturnsFalse, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    // middle name is "min" but size field is malformed (no 'x')
    EXPECT_FALSE(ConvertCustomPageSizeBound("custom_min_invalid", isMinBound, widthMils, heightMils));
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_NoUnderscore_ReturnsFalse, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    EXPECT_FALSE(ConvertCustomPageSizeBound("min210x297mm", isMinBound, widthMils, heightMils));
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeBound_InchBound_Succeeds, TestSize.Level1)
{
    bool isMinBound = false;
    uint32_t widthMils = 0;
    uint32_t heightMils = 0;
    EXPECT_TRUE(ConvertCustomPageSizeBound("custom_min_3x5in", isMinBound, widthMils, heightMils));
    EXPECT_TRUE(isMinBound);
    EXPECT_EQ(widthMils, 3000u);
    EXPECT_EQ(heightMils, 5000u);
}

// ===== ConvertCustomPageSizeFromPwgName edge cases (refactored path) =====

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeFromPwgName_InvalidInput_ReturnsFalse, TestSize.Level1)
{
    PrintPageSize dst;
    // :139 null src
    EXPECT_FALSE(ConvertCustomPageSizeFromPwgName(nullptr, dst));
    // :146 no underscore → SplitPwgKeyword boundary fails
    EXPECT_FALSE(ConvertCustomPageSizeFromPwgName("210x297mm", dst));
    // :152 middle name == "min" rejected
    EXPECT_FALSE(ConvertCustomPageSizeFromPwgName("custom_min_210x297mm", dst));
    // :152 middle name == "max" rejected
    EXPECT_FALSE(ConvertCustomPageSizeFromPwgName("custom_max_210x297mm", dst));
}

HWTEST_F(PrintServiceConverterTest, ConvertCustomPageSizeFromPwgName_ValidKeyword_Succeeds, TestSize.Level1)
{
    PrintPageSize dst;
    EXPECT_TRUE(ConvertCustomPageSizeFromPwgName("custom_a4_210x297mm", dst));
    EXPECT_EQ(dst.GetWidth(), 8268u);
    EXPECT_EQ(dst.GetHeight(), 11693u);
}

// ===== GetUtf8CharCount Tests =====

HWTEST_F(PrintServiceConverterTest, GetUtf8CharCount_AsciiAndEmpty_ReturnsCharCount, TestSize.Level1)
{
    // Empty string is the boundary: loop body never executes, count stays 0
    EXPECT_EQ(GetUtf8CharCount(""), 0u);
    // Pure ASCII single-byte chars (B1: c < 0x80, i += 1)
    EXPECT_EQ(GetUtf8CharCount("abc"), 3u);
    // Real-world style media-size keyword, all ASCII
    EXPECT_EQ(GetUtf8CharCount("custom:myA4"), 11u);
    // Long ASCII string stresses the B1 path repeatedly
    std::string s(100, 'x');
    EXPECT_EQ(GetUtf8CharCount(s), 100u);
}

HWTEST_F(PrintServiceConverterTest, GetUtf8CharCount_TwoAndFourByteChars_ReturnsCharCount, TestSize.Level1)
{
    // 2-byte path (B2: (c & 0xE0) == 0xC0, i += 2)
    // Latin accented char é (U+00E9) = "\xc3\xa9"
    std::string s = "caf\xc3\xa9";
    EXPECT_EQ(GetUtf8CharCount(s), 4u);
    // 4-byte path (B4: (c & 0xF8) == 0xF0, i += 4)
    // Emoji 😀 (U+1F600)
    std::string s2 = "😀";
    EXPECT_EQ(GetUtf8CharCount(s2), 1u);
    // Multiple 4-byte emoji: 😀😂 (2 chars, 8 bytes)
    std::string s3 = "😀😂";
    EXPECT_EQ(GetUtf8CharCount(s3), 2u);
}

HWTEST_F(PrintServiceConverterTest, GetUtf8CharCount_ThreeByteChars_ReturnsCharCount, TestSize.Level1)
{
    // Chinese char "中" (U+4E2D) = 3 bytes
    std::string s = "\xe4\xb8\xad";
    EXPECT_EQ(GetUtf8CharCount(s), 1u);
    // 3 Chinese chars
    std::string s2 = "\xe4\xb8\xad\xe6\x96\x87\xe5\xad\x97";
    EXPECT_EQ(GetUtf8CharCount(s2), 3u);
}

HWTEST_F(PrintServiceConverterTest, GetUtf8CharCount_MixedAndInvalid_ReturnsCharCount, TestSize.Level1)
{
    // Mixed ASCII + 3-byte: "a中b" = 1 + 3 + 1 = 5 bytes, 3 chars
    // Use separate string literals to avoid "\xadb" being parsed as a single hex escape
    std::string s = "a\xe4\xb8\xad" "b";
    EXPECT_EQ(GetUtf8CharCount(s), 3u);
    // Invalid leading byte path (B5: else branch, i += 1, count++)
    // 0xFF is not a valid UTF-8 leading byte
    std::string s2 = "\xff";
    EXPECT_EQ(GetUtf8CharCount(s2), 1u);
    // Invalid byte surrounded by ASCII: B1 + B5 + B1 = 3 chars, 3 bytes
    std::string s3 = "a\xff" "b";
    EXPECT_EQ(GetUtf8CharCount(s3), 3u);
}

}  // namespace Print
}  // namespace OHOS
