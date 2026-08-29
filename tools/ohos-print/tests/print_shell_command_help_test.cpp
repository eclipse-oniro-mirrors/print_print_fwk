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
#include <json/json.h>
#include <memory>

#include "print_shell_command.h"

using json = nlohmann::json;
using namespace testing::ext;
using namespace OHOS::Print;

class PrintShellCommandHelpTest : public ::testing::Test {
protected:
    static std::vector<const char*> BuildArgv(const std::vector<std::string>& args,
        std::vector<std::string>& holder)
    {
        holder = args;
        std::vector<const char*> argv;
        for (auto& s : holder) {
            argv.push_back(s.data());
        }
        return argv;
    }

    static Json::Value ParseJsonResponse(const std::string& result)
    {
        Json::Value response;
        if (result.empty()) {
            EXPECT_FALSE(result.empty()) << "ExecCommand returned empty result";
            return response;
        }
        Json::CharReaderBuilder rBuilder;
        std::unique_ptr<Json::CharReader> reader(rBuilder.newCharReader());
        JSONCPP_STRING err;
        if (!reader->parse(result.c_str(), result.c_str() + result.length(), &response, &err)) {
            EXPECT_TRUE(false) << "ExecCommand result is not valid JSON: " << result;
            return Json::Value();
        }
        return response;
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
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    EXPECT_TRUE(response["data"].isMember("subcommands"));
    EXPECT_TRUE(response["data"]["subcommands"].isArray());
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
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    std::string helpText = response["data"]["helpText"].asString();
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
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    std::string helpText = response["data"]["helpText"].asString();
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
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "INVALID_COMMAND");
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
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");

    Json::Value subcommands = response["data"]["subcommands"];
    EXPECT_TRUE(subcommands.isArray());

    bool hasListAddedPrinters = false;
    bool hasStartPrintJob = false;
    for (const auto& cmd : subcommands) {
        EXPECT_TRUE(cmd.isMember("name"));
        EXPECT_TRUE(cmd.isMember("description"));
        std::string name = cmd["name"].asString();
        if (name == "list-added-printers") {
            hasListAddedPrinters = true;
            EXPECT_FALSE(cmd["description"].asString().empty());
        }
        if (name == "start-print-job") {
            hasStartPrintJob = true;
            EXPECT_FALSE(cmd["description"].asString().empty());
        }
    }
    EXPECT_TRUE(hasListAddedPrinters);
    EXPECT_TRUE(hasStartPrintJob);
}
