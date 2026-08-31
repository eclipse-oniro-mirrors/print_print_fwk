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

using namespace testing::ext;
using namespace OHOS::Print;

class ShellCommandTest : public ::testing::Test {
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
            EXPECT_TRUE(false) << "ExecCommand result is not valid : " << result;
            return Json::Value();
        }
        return response;
    }
};

/**
 * @tc.number: ShellCommand_Construct_MinArgs_0100
 * @tc.name: Construct with argc < 2
 * @tc.desc: When argc is less than MIN_ARGUMENT_NUMBER, cmd_ should be "help" and argList_ should be empty.
 */
HWTEST_F(ShellCommandTest, ShellCommand_Construct_MinArgs_0100, Function | MediumTest | Level1)
{
    // Given: argc = 1 (only program name)
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result should contain help text (general help)
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
}

/**
 * @tc.number: ShellCommand_Construct_MaxArgs_0100
 * @tc.name: Construct with argc > 256
 * @tc.desc: When argc exceeds MAX_ARGUMENT_NUMBER, cmd_ should be "help".
 */
HWTEST_F(ShellCommandTest, ShellCommand_Construct_MaxArgs_0100, Function | MediumTest | Level1)
{
    // Given: argc > 256 (create 257 arguments)
    std::vector<std::string> args;
    args.push_back("ohos-print");
    for (int i = 0; i < 257; i++) {
        args.push_back("arg" + std::to_string(i));
    }
    std::vector<std::string> holder;
    auto argv = BuildArgv(args, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result should contain help text since cmd_ = "help"
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
}

/**
 * @tc.number: ShellCommand_Construct_HelpFlag_0100
 * @tc.name: Construct with --help flag
 * @tc.desc: When argv[1] is "--help", cmd_ should be "help".
 */
HWTEST_F(ShellCommandTest, ShellCommand_Construct_HelpFlag_0100, Function | MediumTest | Level1)
{
    // Given: argv[1] = "--help"
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "--help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    EXPECT_TRUE(response["data"].isMember("subcommands"));
}

/**
 * @tc.number: ShellCommand_Construct_ShortHelpFlag_0100
 * @tc.name: Construct with -h flag
 * @tc.desc: When argv[1] is "-h", cmd_ should be "help".
 */
HWTEST_F(ShellCommandTest, ShellCommand_Construct_ShortHelpFlag_0100, Function | MediumTest | Level1)
{
    // Given: argv[1] = "-h"
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "-h"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
}

/**
 * @tc.number: ShellCommand_Construct_NormalCommand_0100
 * @tc.name: Construct with normal command
 * @tc.desc: When argv has normal command, cmd_ should be argv[1] and argList_ should contain argv[2..].
 */
HWTEST_F(ShellCommandTest, ShellCommand_Construct_NormalCommand_0100, Function | MediumTest | Level1)
{
    // Given: normal command with arguments
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job", "--file-path", "/data/test.pdf"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: command is recognized and processed (not treated as help)
    // start-print-job without --document-format should fail with ERR_ARG_MISSING
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_ARG_MISSING");
}

/**
 * @tc.number: ShellCommand_ExecCommand_UnknownCmd_0100
 * @tc.name: ExecCommand with unknown command
 * @tc.desc: Unknown command should produce INVALID_COMMAND error in result.
 */
HWTEST_F(ShellCommandTest, ShellCommand_ExecCommand_UnknownCmd_0100, Function | MediumTest | Level1)
{
    // Given: an unknown subcommand
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "unknown-cmd"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: result should contain INVALID_COMMAND error
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "INVALID_COMMAND");
}

/**
 * @tc.number: ShellCommand_ExecCommand_HelpCmd_0100
 * @tc.name: ExecCommand with help command
 * @tc.desc: Help command should return general help with helpText and subcommands.
 */
HWTEST_F(ShellCommandTest, ShellCommand_ExecCommand_HelpCmd_0100, Function | MediumTest | Level1)
{
    // Given: "help" command
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    EXPECT_TRUE(response["data"].isMember("subcommands"));
    EXPECT_TRUE(response["data"]["subcommands"].isArray());
}

/**
 * @tc.number: ShellCommand_GetCommandErrorMsg_0100
 * @tc.name: GetCommandErrorMsg returns INVALID_COMMAND
 * @tc.desc: GetCommandErrorMsg should return  string containing INVALID_COMMAND error code.
 */
HWTEST_F(ShellCommandTest, ShellCommand_GetCommandErrorMsg_0100, Function | MediumTest | Level1)
{
    // Given: unknown command triggers GetCommandErrorMsg
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "bogus-command"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();

    // Then: output should contain INVALID_COMMAND and the unknown command name
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["errCode"].asString(), "INVALID_COMMAND");
    EXPECT_NE(response["errMsg"].asString().find("bogus-command"), std::string::npos);
}
