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

#include "shell_command.h"

#include <getopt.h>
#include "print_log.h"
#include "command_output.h"

namespace OHOS {
namespace Print {
ShellCommand::ShellCommand(int argc, char* argv[], std::string name)
{
    opterr = 0;
    argc_ = argc;
    argv_ = argv;
    name_ = name;
    if (argc < MIN_ARGUMENT_NUMBER || argc > MAX_ARGUMENT_NUMBER) {
        cmd_ = "help";
        return;
    }
    cmd_ = argv[1];
    if (cmd_ == "--help" || cmd_ == "-h") {
        cmd_ = "help";
    }
    for (int i = 2; i < argc; i++) {
        argList_.push_back(argv[i]);
    }
}

ShellCommand::~ShellCommand()
{}

ErrCode ShellCommand::OnCommand()
{
    int32_t result = OHOS::ERR_OK;
    auto respond = commandMap_[cmd_];
    if (respond == nullptr) {
        std::string errorMsg = GetCommandErrorMsg();
        resultReceiver_ = errorMsg;
        return OHOS::ERR_INVALID_VALUE;
    }
    if (Init() == OHOS::ERR_OK) {
        PRINT_HILOGD("Init is ERR_OK.");
        respond();
    } else {
        OutputError("ERR_INIT_FAILED", "Initialization failed: unable to connect to print service",
            "Check if the print service is running", resultReceiver_);
        result = OHOS::ERR_INVALID_VALUE;
    }
    return result;
}

std::string ShellCommand::ExecCommand()
{
    int32_t result = CreateCommandMap();
    if (result != OHOS::ERR_OK) {
        PRINT_HILOGE("failed to create command map.");
    }
    result = OnCommand();
    if (result != OHOS::ERR_OK) {
        PRINT_HILOGE("failed to execute your command.");
    }
    return resultReceiver_;
}

std::string ShellCommand::GetCommandErrorMsg() const
{
    std::string output;
    OutputError("INVALID_COMMAND", "Unknown command: " + cmd_,
        "Run '" + name_ + " help' for available commands", output);
    return output;
}

}  // namespace Print
}  // namespace OHOS
