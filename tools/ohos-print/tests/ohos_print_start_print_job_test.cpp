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
#include <vector>

#include "print_shell_command.h"

using namespace testing::ext;
using namespace OHOS::Print;

class OhosPrintStartPrintJobTest : public ::testing::Test {
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
 * @tc.number: Ohos_Print_Cli_StartPrintJob_Help_0100
 * @tc.name: CmdStartPrintJob --help
 * @tc.desc: Verify --help option returns 0 and outputs help text JSON.
 */
HWTEST_F(OhosPrintStartPrintJobTest, Ohos_Print_Cli_StartPrintJob_Help_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job", "--help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "success");
    EXPECT_TRUE(response["data"].isMember("helpText"));
    EXPECT_NE(response["data"]["helpText"].asString().find("start-print-job"), std::string::npos);
}

/**
 * @tc.number: Ohos_Print_Cli_StartPrintJob_InvalidOption_0100
 * @tc.name: CmdStartPrintJob invalid option
 * @tc.desc: Verify invalid option returns 1 with ERR_INVALID_INPUT.
 */
HWTEST_F(OhosPrintStartPrintJobTest, Ohos_Print_Cli_StartPrintJob_InvalidOption_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job", "--nonexistent"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_INVALID_INPUT");
}

/**
 * @tc.number: Ohos_Print_Cli_StartPrintJob_MissingFilePath_0100
 * @tc.name: CmdStartPrintJob missing --file-path
 * @tc.desc: Verify missing --file-path returns 1 with ERR_ARG_MISSING.
 */
HWTEST_F(OhosPrintStartPrintJobTest, Ohos_Print_Cli_StartPrintJob_MissingFilePath_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job", "--document-format", "application/pdf"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_ARG_MISSING");
    EXPECT_NE(response["errMsg"].asString().find("file-path"), std::string::npos);
}

/**
 * @tc.number: Ohos_Print_Cli_StartPrintJob_MissingDocFormat_0100
 * @tc.name: CmdStartPrintJob missing --document-format
 * @tc.desc: Verify missing --document-format returns 1 with ERR_ARG_MISSING.
 */
HWTEST_F(OhosPrintStartPrintJobTest, Ohos_Print_Cli_StartPrintJob_MissingDocFormat_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job", "--file-path", "/data/test.pdf"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_ARG_MISSING");
    EXPECT_NE(response["errMsg"].asString().find("document-format"), std::string::npos);
}

/**
 * @tc.number: Ohos_Print_Cli_StartPrintJob_FileNotExist_0100
 * @tc.name: CmdStartPrintJob file not exist
 * @tc.desc: Verify non-existent file path returns 1 with ERR_FILE_OPEN_FAILED.
 */
HWTEST_F(OhosPrintStartPrintJobTest, Ohos_Print_Cli_StartPrintJob_FileNotExist_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "start-print-job",
        "--file-path", "/data/nonexistent_file_for_test.pdf",
        "--document-format", "application/pdf"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    Json::Value response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"].asString(), "failed");
    EXPECT_EQ(response["errCode"].asString(), "ERR_FILE_OPEN_FAILED");
}

