/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <json/json.h>
#include <memory>
#include <string>
#include "print_shell_command.h"
#include "command_output.h"

using namespace testing::ext;
using namespace OHOS::Print;

static Json::Value ParseJson(const std::string& str)
{
    Json::Value val;
    Json::CharReaderBuilder rBuilder;
    std::unique_ptr<Json::CharReader> reader(rBuilder.newCharReader());
    JSONCPP_STRING err;
    reader->parse(str.c_str(), str.c_str() + str.length(), &val, &err);
    return val;
}

class OhosPrintCliUtilsTest : public ::testing::Test {};

/**
 * @tc.number: Ohos_Print_Cli_ParseCopies_0100
 * @tc.name: ParseCopies
 * @tc.desc: Verify parsing pure numeric copies input.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ParseCopies_0100, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_TRUE(PrintShellCommand::ParseCopies("3", result));
    EXPECT_EQ(result, 3u);
    EXPECT_TRUE(PrintShellCommand::ParseCopies("1", result));
    EXPECT_EQ(result, 1u);
    EXPECT_TRUE(PrintShellCommand::ParseCopies("10", result));
    EXPECT_EQ(result, 10u);
}

/**
 * @tc.number: Ohos_Print_Cli_ParseCopies_0200
 * @tc.name: ParseCopies
 * @tc.desc: Verify parsing copies with non-digit characters is rejected.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ParseCopies_0200, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_FALSE(PrintShellCommand::ParseCopies("3份", result));
    EXPECT_FALSE(PrintShellCommand::ParseCopies("5份", result));
}

/**
 * @tc.number: Ohos_Print_Cli_ParseCopies_0300
 * @tc.name: ParseCopies
 * @tc.desc: Verify parsing empty or invalid copies input returns false.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ParseCopies_0300, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_FALSE(PrintShellCommand::ParseCopies("", result));
    EXPECT_FALSE(PrintShellCommand::ParseCopies("abc", result));
}

/**
 * @tc.number: Ohos_Print_Cli_ParseCopies_0400
 * @tc.name: ParseCopies
 * @tc.desc: Verify parsing copies with overflow and mixed characters is rejected.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ParseCopies_0400, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_FALSE(PrintShellCommand::ParseCopies("3abc", result));
    EXPECT_FALSE(PrintShellCommand::ParseCopies("abc5", result));
    EXPECT_TRUE(PrintShellCommand::ParseCopies("007", result));
    EXPECT_EQ(result, 7u);
    EXPECT_FALSE(PrintShellCommand::ParseCopies("4294967296", result));
    EXPECT_FALSE(PrintShellCommand::ParseCopies("9999999999", result));
}

/**
 * @tc.number: Ohos_Print_Cli_MapPageSizeToId_0100
 * @tc.name: MapPageSizeToId
 * @tc.desc: Verify all supported page sizes map to correct IDs.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapPageSizeToId_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("A4"), "ISO_A4");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("A3"), "ISO_A3");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("A5"), "ISO_A5");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("B5"), "ISO_B5");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("Letter"), "NA_LETTER");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("Legal"), "NA_LEGAL");
}

/**
 * @tc.number: Ohos_Print_Cli_MapPageSizeToId_0200
 * @tc.name: MapPageSizeToId
 * @tc.desc: Verify unknown page size defaults to ISO_A4.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapPageSizeToId_0200, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId("unknown"), "ISO_A4");
    EXPECT_EQ(PrintShellCommand::MapPageSizeToId(""), "ISO_A4");
}

/**
 * @tc.number: Ohos_Print_Cli_MapDirection_0100
 * @tc.name: MapDirection
 * @tc.desc: Verify direction mapping for landscape and portrait.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapDirection_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapDirection("横向"), DIRECTION_MODE_LANDSCAPE);
    EXPECT_EQ(PrintShellCommand::MapDirection("landscape"), DIRECTION_MODE_LANDSCAPE);
    EXPECT_EQ(PrintShellCommand::MapDirection("纵向"), DIRECTION_MODE_PORTRAIT);
    EXPECT_EQ(PrintShellCommand::MapDirection("portrait"), DIRECTION_MODE_PORTRAIT);
    EXPECT_EQ(PrintShellCommand::MapDirection("自动"), DIRECTION_MODE_AUTO);
    EXPECT_EQ(PrintShellCommand::MapDirection("auto"), DIRECTION_MODE_AUTO);
    EXPECT_EQ(PrintShellCommand::MapDirection(""), DIRECTION_MODE_PORTRAIT);
}

/**
 * @tc.number: Ohos_Print_Cli_MapDirectionToOption_0100
 * @tc.name: MapDirectionToOption
 * @tc.desc: Verify direction-to-option mapping.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapDirectionToOption_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("横向"), "landscape");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("landscape"), "landscape");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("自动"), "auto");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("auto"), "auto");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("纵向"), "portrait");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption("portrait"), "portrait");
    EXPECT_EQ(PrintShellCommand::MapDirectionToOption(""), "portrait");
}

/**
 * @tc.number: Ohos_Print_Cli_MapColorMode_0100
 * @tc.name: MapColorMode
 * @tc.desc: Verify color mode mapping.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapColorMode_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapColorMode("彩色"), 1u);
    EXPECT_EQ(PrintShellCommand::MapColorMode("彩印"), 1u);
    EXPECT_EQ(PrintShellCommand::MapColorMode("color"), 1u);
    EXPECT_EQ(PrintShellCommand::MapColorMode("黑白"), 0u);
    EXPECT_EQ(PrintShellCommand::MapColorMode("单色"), 0u);
    EXPECT_EQ(PrintShellCommand::MapColorMode("mono"), 0u);
    EXPECT_EQ(PrintShellCommand::MapColorMode(""), 0u);
}

/**
 * @tc.number: Ohos_Print_Cli_MapColorModeToOption_0100
 * @tc.name: MapColorModeToOption
 * @tc.desc: Verify color mode to option mapping for all supported inputs.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapColorModeToOption_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("彩色"), "color");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("彩印"), "color");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("color"), "color");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("黑白"), "mono");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("单色"), "mono");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption("mono"), "mono");
    EXPECT_EQ(PrintShellCommand::MapColorModeToOption(""), "mono");
}

/**
 * @tc.number: Ohos_Print_Cli_MapDuplex_0100
 * @tc.name: MapDuplex
 * @tc.desc: Verify duplex mode mapping.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapDuplex_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapDuplex("单面"), 0u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("none"), 0u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("双面"), 1u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("双面长边"), 1u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("long"), 1u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("双面短边"), 2u);
    EXPECT_EQ(PrintShellCommand::MapDuplex("short"), 2u);
    EXPECT_EQ(PrintShellCommand::MapDuplex(""), 0u);
}

/**
 * @tc.number: Ohos_Print_Cli_MapDuplexToOption_0100
 * @tc.name: MapDuplexToOption
 * @tc.desc: Verify duplex-to-option mapping.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_MapDuplexToOption_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("单面"), "none");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("none"), "none");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("双面"), "long");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("双面长边"), "long");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("long"), "long");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("双面短边"), "short");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption("short"), "short");
    EXPECT_EQ(PrintShellCommand::MapDuplexToOption(""), "none");
}

/**
 * @tc.number: Ohos_Print_Cli_OutputSuccess_0100
 * @tc.name: OutputSuccess
 * @tc.desc: Verify OutputSuccess writes valid JSON with status=success.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_OutputSuccess_0100, Function | MediumTest | Level1)
{
    Json::Value data;
    data["key"] = "value";
    std::string output;
    OutputSuccess(data, output);
    Json::Value response = ParseJson(output);
    EXPECT_EQ(response["type"].asString(), "result");
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_EQ(response["data"]["key"].asString(), "value");
}

/**
 * @tc.number: Ohos_Print_Cli_OutputError_0100
 * @tc.name: OutputError
 * @tc.desc: Verify OutputError writes valid JSON with status=failed.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_OutputError_0100, Function | MediumTest | Level1)
{
    std::string output;
    OutputError("ERR_TEST", "test error", "test suggestion", output);
    Json::Value response = ParseJson(output);
    EXPECT_EQ(response["type"].asString(), "result");
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_TEST");
    EXPECT_EQ(response["errMsg"].asString(), "test error");
    EXPECT_EQ(response["suggestion"].asString(), "test suggestion");
}

/**
 * @tc.number: Ohos_Print_Cli_OutputError_0200
 * @tc.name: OutputError
 * @tc.desc: Verify OutputError with empty suggestion.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_OutputError_0200, Function | MediumTest | Level1)
{
    std::string output;
    OutputError("ERR_NO_SUGGESTION", "error without suggestion", "", output);
    Json::Value response = ParseJson(output);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_NO_SUGGESTION");
    EXPECT_EQ(response["suggestion"].asString(), "");
}

/**
 * @tc.number: Ohos_Print_Cli_OutputSuccess_0200
 * @tc.name: OutputSuccess
 * @tc.desc: Verify OutputSuccess with empty data object.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_OutputSuccess_0200, Function | MediumTest | Level1)
{
    Json::Value data;
    std::string output;
    OutputSuccess(data, output);
    Json::Value response = ParseJson(output);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isObject());
    EXPECT_TRUE(response["data"].empty());
}

/**
 * @tc.number: Ohos_Print_Cli_SafeParseUint32_0100
 * @tc.name: SafeParseUint32
 * @tc.desc: Verify SafeParseUint32 with valid numeric inputs.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_SafeParseUint32_0100, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_TRUE(PrintShellCommand::SafeParseUint32("0", result));
    EXPECT_EQ(result, 0u);
    EXPECT_TRUE(PrintShellCommand::SafeParseUint32("42", result));
    EXPECT_EQ(result, 42u);
    EXPECT_TRUE(PrintShellCommand::SafeParseUint32("4294967295", result));
    EXPECT_EQ(result, 4294967295u);
}

/**
 * @tc.number: Ohos_Print_Cli_SafeParseUint32_0200
 * @tc.name: SafeParseUint32
 * @tc.desc: Verify SafeParseUint32 rejects invalid inputs.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_SafeParseUint32_0200, Function | MediumTest | Level1)
{
    uint32_t result = 0;
    EXPECT_FALSE(PrintShellCommand::SafeParseUint32("", result));
    EXPECT_FALSE(PrintShellCommand::SafeParseUint32("abc", result));
    EXPECT_FALSE(PrintShellCommand::SafeParseUint32("12abc", result));
    EXPECT_FALSE(PrintShellCommand::SafeParseUint32("4294967296", result));
    EXPECT_FALSE(PrintShellCommand::SafeParseUint32("-1", result));
}

/**
 * @tc.number: Ohos_Print_Cli_ExtractJobName_0100
 * @tc.name: ExtractJobName
 * @tc.desc: Verify extracting job name from file paths.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ExtractJobName_0100, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::ExtractJobName("/data/test.pdf"), "test.pdf");
    EXPECT_EQ(PrintShellCommand::ExtractJobName("/home/user/doc/report.docx"), "report.docx");
    EXPECT_EQ(PrintShellCommand::ExtractJobName("simple.txt"), "simple.txt");
}

/**
 * @tc.number: Ohos_Print_Cli_ExtractJobName_0200
 * @tc.name: ExtractJobName
 * @tc.desc: Verify ExtractJobName with edge cases.
 */
HWTEST_F(OhosPrintCliUtilsTest, Ohos_Print_Cli_ExtractJobName_0200, Function | MediumTest | Level1)
{
    EXPECT_EQ(PrintShellCommand::ExtractJobName("/"), "/");
    EXPECT_EQ(PrintShellCommand::ExtractJobName("/data/"), "/data/");
    EXPECT_EQ(PrintShellCommand::ExtractJobName(""), "");
}
