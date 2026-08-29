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
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "print_shell_command.h"

using json = nlohmann::json;
using namespace testing::ext;
using namespace OHOS::Print;

class PrintShellCommandHelpTest : public ::testing::Test {
protected:
    static std::vector<char*> BuildArgv(const std::vector<std::string>& args,
        std::vector<std::string>& holder)
    {
        holder = args;
        std::vector<char*> argv;
        for (auto& s : holder) {
            argv.push_back(s.data());
        }
        return argv;
    }

    static void ParseJsonResponse(const std::string& result, json& out)
    {
        ASSERT_FALSE(result.empty()) << "resultReceiver_ is empty";
        ASSERT_TRUE(json::accept(result)) << "resultReceiver_ is not valid JSON: " << result;
        out = json::parse(result);
    }
};

/**
 * @tc.number: HelpCommand_NoArgs_0100
 * @tc.name: Help command with no arguments
 * @tc.desc: help without arguments should return general help JSON with helpText and subcommands.
 */
HWTEST_F(PrintShellCommandHelpTest, HelpCommand_NoArgs_0100, Function | MediumTest | Level1)
{
    // Given: "help" with no additional arguments
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result contains general help with helpText and subcommands
    json response;
    ParseJsonResponse(result, response);
    EXPECT_EQ(response["status"], "success");
    EXPECT_TRUE(response["data"].contains("helpText"));
    EXPECT_TRUE(response["data"].contains("subcommands"));
    EXPECT_TRUE(response["data"]["subcommands"].is_array());
    EXPECT_GE(response["data"]["subcommands"].size(), 2u);
}

/**
 * @tc.number: HelpCommand_ListAddedPrinters_0100
 * @tc.name: Help for list-added-printers
 * @tc.desc: help list-added-printers should return help text containing list-added-printers usage.
 */
HWTEST_F(PrintShellCommandHelpTest, HelpCommand_ListAddedPrinters_0100, Function | MediumTest | Level1)
{
    // Given: "help list-added-printers"
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help", "list-added-printers"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result contains list-added-printers help text
    json response;
    ParseJsonResponse(result, response);
    EXPECT_EQ(response["status"], "success");
    EXPECT_TRUE(response["data"].contains("helpText"));
    std::string helpText = response["data"]["helpText"].get<std::string>();
    EXPECT_NE(helpText.find("list-added-printers"), std::string::npos);
}

/**
 * @tc.number: HelpCommand_StartPrintJob_0100
 * @tc.name: Help for start-print-job
 * @tc.desc: help start-print-job should return help text containing start-print-job usage.
 */
HWTEST_F(PrintShellCommandHelpTest, HelpCommand_StartPrintJob_0100, Function | MediumTest | Level1)
{
    // Given: "help start-print-job"
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help", "start-print-job"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result contains start-print-job help text
    json response;
    ParseJsonResponse(result, response);
    EXPECT_EQ(response["status"], "success");
    EXPECT_TRUE(response["data"].contains("helpText"));
    std::string helpText = response["data"]["helpText"].get<std::string>();
    EXPECT_NE(helpText.find("start-print-job"), std::string::npos);
}

/**
 * @tc.number: HelpCommand_UnknownCmd_0100
 * @tc.name: Help for unknown command
 * @tc.desc: help unknown_cmd should return INVALID_COMMAND error.
 */
HWTEST_F(PrintShellCommandHelpTest, HelpCommand_UnknownCmd_0100, Function | MediumTest | Level1)
{
    // Given: "help unknown_cmd"
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help", "unknown_cmd"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result contains INVALID_COMMAND error
    json response;
    ParseJsonResponse(result, response);
    EXPECT_EQ(response["status"], "failed");
    EXPECT_EQ(response["errCode"], "INVALID_COMMAND");
}

/**
 * @tc.number: ShowGeneralHelp_VerifyStructure_0100
 * @tc.name: General help JSON structure verification
 * @tc.desc: General help should contain subcommands array with list-added-printers and start-print-job entries.
 */
HWTEST_F(PrintShellCommandHelpTest, ShowGeneralHelp_VerifyStructure_0100, Function | MediumTest | Level1)
{
    // Given: "help" with no arguments
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: verify the structure of general help JSON
    json response;
    ParseJsonResponse(result, response);
    EXPECT_EQ(response["status"], "success");

    json subcommands = response["data"]["subcommands"];
    EXPECT_TRUE(subcommands.is_array());

    bool hasListAddedPrinters = false;
    bool hasStartPrintJob = false;
    for (const auto& cmd : subcommands) {
        EXPECT_TRUE(cmd.contains("name"));
        EXPECT_TRUE(cmd.contains("description"));
        std::string name = cmd["name"].get<std::string>();
        if (name == "list-added-printers") {
            hasListAddedPrinters = true;
            EXPECT_FALSE(cmd["description"].get<std::string>().empty());
        }
        if (name == "start-print-job") {
            hasStartPrintJob = true;
            EXPECT_FALSE(cmd["description"].get<std::string>().empty());
        }
    }
    EXPECT_TRUE(hasListAddedPrinters);
    EXPECT_TRUE(hasStartPrintJob);
}
