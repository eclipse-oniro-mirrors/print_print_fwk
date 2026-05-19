/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "print_security_guard_info.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSecurityGuardInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintSecurityGuardInfoTest::SetUpTestCase(void)
{}

void PrintSecurityGuardInfoTest::TearDownTestCase(void)
{}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0001_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0002_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("EPRINT_printer");
    PrintJob printJob;
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0003_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("EPRINT_printer");
    std::string option = R"({"ePrintUrl":"testUrl"})";
    printerInfo.SetOption(option);
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0004_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("EPRINT_printer");
    std::string option = R"({"ePrintUrl":0})";
    printerInfo.SetOption(option);
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_CANCELLED);
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0005_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("EPRINT_printer");
    std::string option = R"({"":"testUrl"})";
    printerInfo.SetOption(option);
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_FAILED);
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0006_NeedRename, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("EPRINT_printer");
    std::string option = R"({"":""})";
    printerInfo.SetOption(option);
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_FILE_CORRUPT);
    printSecurityGuardInfo.SetPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}
}  // namespace Print
}  // namespace OHOS