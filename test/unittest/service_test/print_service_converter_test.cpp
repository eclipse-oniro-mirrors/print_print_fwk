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
#include <nlohmann/json.hpp>
#include "print_service_converter.h"
#include "print_page_size.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintServiceConverterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceConverterTest::SetUpTestCase(void) {}

void PrintServiceConverterTest::TearDownTestCase(void) {}

void PrintServiceConverterTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintServiceConverterTest_%{public}d", ++testNo);
}

void PrintServiceConverterTest::TearDown(void) {}

/**
* @tc.name: PrintServiceConverterTest_0001
* @tc.desc: reportPrintSuccess
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0001, TestSize.Level1)
{
    int dpc = 120;
    EXPECT_EQ(DpcToDpi(dpc), 300);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0002, TestSize.Level1)
{
    std::vector<std::string> list;
    list.push_back("1111");
    list.push_back("2222");
    std::string value = "1111";
    AddToUniqueList(list, value);
    EXPECT_EQ(list.size(), 2);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0003, TestSize.Level1)
{
    std::vector<std::string> list;
    list.push_back("1111");
    list.push_back("2222");
    std::string value = "3333";
    AddToUniqueList(list, value);
    EXPECT_EQ(list.size(), 3);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0004, TestSize.Level1)
{
    int code = 3;
    EXPECT_EQ(GetQulityString(code), "3");
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0005, TestSize.Level1)
{
    const char* src = nullptr;
    ColorModeCode dst;
    EXPECT_EQ(ConvertColorModeCode(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_006, TestSize.Level1)
{
    PrintPageSize pageSize;
    nlohmann::json jsonObject;
    EXPECT_EQ(ConvertPageSizeToJson(pageSize, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0007, TestSize.Level1)
{
    const char* src = "color";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 1);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0008, TestSize.Level1)
{
    const char* src = "monochrome";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 0);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0009, TestSize.Level1)
{
    const char* src = "auto";
    ColorModeCode dst;
    bool re = ConvertColorModeCode(src, dst);
    EXPECT_EQ(dst, 2);
    EXPECT_EQ(re, true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0010, TestSize.Level1)
{
    const char* src = "sss";
    ColorModeCode dst;
    EXPECT_EQ(ConvertColorModeCode(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0011, TestSize.Level1)
{
    ColorModeCode code = ColorModeCode::COLOR_MODE_COLOR;
    nlohmann::json jsonObject;
    EXPECT_EQ(ConvertColorModeToJson(code, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0012, TestSize.Level1)
{
    DuplexModeCode code = DuplexModeCode::DUPLEX_MODE_ONE_SIDED;
    nlohmann::json jsonObject;
    EXPECT_EQ(ConvertDuplexModeToJson(code, jsonObject), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0013, TestSize.Level1)
{
    const char* src = nullptr;
    std::string id = "";
    EXPECT_EQ(ConvertPageSizeId(src, id), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0014, TestSize.Level1)
{
    const char* src = "iso_a4_210x297mm";
    std::string id = "";
    EXPECT_EQ(ConvertPageSizeId(src, id), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0015, TestSize.Level1)
{
    const char* src = nullptr;
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0016, TestSize.Level1)
{
    const char* src = "iso_a4_210x297mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0017, TestSize.Level1)
{
    const char* src = "na_number-10_4.125x9.5in";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0018, TestSize.Level1)
{
    const char* src = "custom_390.03x540.03mm_390.03x540.03mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), true);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0019, TestSize.Level1)
{
    const char* src = "nanumber";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0020, TestSize.Level1)
{
    const char* src = "custom_min_50.8x85.94mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0021, TestSize.Level1)
{
    const char* src = "custom_390.03x540.03mm_390.03540.03mm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

HWTEST_F(PrintServiceConverterTest, PrintServiceConverterTest_0022, TestSize.Level1)
{
    const char* src = "custom_390.03x540.03mm_390.03x540.03cm";
    PrintPageSize dst;
    EXPECT_EQ(ConvertPrintPageSize(src, dst), false);
}

}
}
