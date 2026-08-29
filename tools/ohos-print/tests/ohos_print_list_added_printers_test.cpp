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

class OhosPrintListAddedPrintersTest : public ::testing::Test {
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

    static json ParseJsonResponse(const std::string& result)
    {
        ASSERT_FALSE(result.empty()) << "ExecCommand returned empty result";
        ASSERT_TRUE(json::accept(result)) << "ExecCommand result is not valid JSON: " << result;
        return json::parse(result);
    }
};

/**
 * @tc.number: Ohos_Print_Cli_ListAddedPrinters_Help_0100
 * @tc.name: CmdListAddedPrinters --help
 * @tc.desc: Verify --help option returns 0 and outputs help text JSON.
 */
HWTEST_F(OhosPrintListAddedPrintersTest, Ohos_Print_Cli_ListAddedPrinters_Help_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "list-added-printers", "--help"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    json response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"], "success");
    EXPECT_TRUE(response["data"].contains("helpText"));
    EXPECT_NE(response["data"]["helpText"].get<std::string>().find("list-added-printers"), std::string::npos);
}

/**
 * @tc.number: Ohos_Print_Cli_ListAddedPrinters_InvalidOption_0100
 * @tc.name: CmdListAddedPrinters invalid option
 * @tc.desc: Verify invalid option returns 1 with ERR_INVALID_INPUT.
 */
HWTEST_F(OhosPrintListAddedPrintersTest, Ohos_Print_Cli_ListAddedPrinters_InvalidOption_0100,
    Function | MediumTest | Level1)
{
    std::vector<std::string> holder;
    auto argv = BuildArgv({"ohos-print", "list-added-printers", "--nonexistent"}, holder);
    PrintShellCommand cmd(argv.size(), argv.data());
    std::string result = cmd.ExecCommand();
    json response = ParseJsonResponse(result);
    EXPECT_EQ(response["status"], "failed");
    EXPECT_EQ(response["errCode"], "ERR_INVALID_INPUT");
}
