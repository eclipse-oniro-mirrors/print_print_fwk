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

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0007, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("TestPrinter");
    PrintJob printJob;
    std::vector<FileAuditInfo> fileInfos;
    FileAuditInfo info;
    info.fileName = "/data/test/file.pdf";
    info.md5 = "d41d8cd98f00b204e9800998ecf8427e";
    info.size = 1024;
    fileInfos.push_back(info);
    printSecurityGuardInfo.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    std::string jsonStr = printSecurityGuardInfo.ToJsonStr();
    EXPECT_NE("", jsonStr);
    EXPECT_TRUE(jsonStr.find("file.pdf") != std::string::npos);
}

HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0008_MultiFile, TestSize.Level1)
{
    std::vector<std::string> fileList = {"a.pdf", "b.pdf"};
    PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP Printer");
    PrintJob printJob;
    printJob.SetDuplexMode(1);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    std::vector<FileAuditInfo> fileInfos;
    FileAuditInfo fa;
    fa.fileName = "a.pdf"; fa.md5 = "aaa"; fa.size = 100;
    FileAuditInfo fb;
    fb.fileName = "b.pdf"; fb.md5 = "bbb"; fb.size = 200;
    fileInfos.push_back(fa);
    fileInfos.push_back(fb);
    printSecurityGuardInfo.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    std::string jsonStr = printSecurityGuardInfo.ToJsonStr();
    EXPECT_NE("", jsonStr);
    EXPECT_TRUE(jsonStr.find("a.pdf") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("b.pdf") != std::string::npos);
}
}  // namespace Print
}  // namespace OHOS