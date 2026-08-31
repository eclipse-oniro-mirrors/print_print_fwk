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

#include <csignal>
#include <unistd.h>

#include <iostream>
#include <string>

#include "print_shell_command.h"

using namespace OHOS::Print;

namespace {
void CommandTimeoutHandler(int sig)
{
    const char msg[] =
        "{\"type\":\"result\",\"status\":\"failed\","
        "\"errCode\":\"ERR_COMMAND_TIMEOUT\","
        "\"errMsg\":\"Command execution timed out\","
        "\"suggestion\":\"Check if the print service is responding.\"}\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}
} // namespace

int main(int argc, char** argv)
{
    struct sigaction sa;
    sa.sa_handler = CommandTimeoutHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, nullptr);
    alarm(COMMAND_TIME_OUT);

    PrintShellCommand cmd(argc, argv);
    std::string result = cmd.ExecCommand();

    alarm(0);
    std::cout << result << std::endl;
    fflush(stdout);
    _exit(0);
}
