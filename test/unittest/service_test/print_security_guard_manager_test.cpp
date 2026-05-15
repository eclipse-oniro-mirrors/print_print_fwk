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
#define private public
#include "print_security_guard_manager.h"
#undef private
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSecurityGuardManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintSecurityGuardManagerTest::SetUpTestCase(void)
{}

void PrintSecurityGuardManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PrintSecurityGuardManagerTest_0001
 * @tc.desc: receiveBaseInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_0001_NeedRename, TestSize.Level1)
{
    PrintSecurityGuardManager printSerPrintSecurityGuardManager;
    std::vector<std::string> fileList;
    PrinterInfo printerInfo;
    PrintJob printJob;
    int num = printSerPrintSecurityGuardManager.securityMap_.size();
    printSerPrintSecurityGuardManager.receiveBaseInfo("jobId-1", "callerPkg-1", fileList);
    EXPECT_EQ(printSerPrintSecurityGuardManager.securityMap_.size(), num + 1);
    printSerPrintSecurityGuardManager.receiveJobStateUpdate("jobId-2", printerInfo, printJob);
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_0002
 * @tc.desc: receiveBaseInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_0002_NeedRename, TestSize.Level1)
{
    PrintSecurityGuardManager printSerPrintSecurityGuardManager;
    std::vector<std::string> fileList;
    PrinterInfo printerInfo;
    PrintJob printJob;
    int num = printSerPrintSecurityGuardManager.securityMap_.size();
    printSerPrintSecurityGuardManager.receiveBaseInfo("jobId-1", "callerPkg-1", fileList);
    EXPECT_EQ(printSerPrintSecurityGuardManager.securityMap_.size(), num + 1);
    printSerPrintSecurityGuardManager.receiveJobStateUpdate("jobId-1", printerInfo, printJob);
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_0003
 * @tc.desc: ReceiveAuditInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_0003, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList;
    PrinterInfo printerInfo;
    PrintJob printJob;
    std::vector<FileAuditInfo> fileInfos;
    FileAuditInfo info;
    info.fileName = "test.pdf";
    info.md5 = "d41d8cd98f00b204e9800998ecf8427e";
    info.size = 1024;
    fileInfos.push_back(info);
    manager.receiveBaseInfo("jobId-1", "callerPkg-1", fileList);
    int num = manager.securityMap_.size();
    manager.receiveAuditInfo("jobId-1", printerInfo, printJob, fileInfos);
    EXPECT_EQ(manager.securityMap_.size(), num);
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_0004
 * @tc.desc: ReceiveAuditInfo not found in map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_0004, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    PrinterInfo printerInfo;
    PrintJob printJob;
    std::vector<FileAuditInfo> fileInfos;
    int num = manager.securityMap_.size();
    manager.receiveAuditInfo("jobId-notexist", printerInfo, printJob, fileInfos);
    EXPECT_EQ(manager.securityMap_.size(), num + 1);
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_0005
 * @tc.desc: ReceiveAuditInfo with file data, then ReceiveJobStateUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_0005, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("TestPrinter");
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    std::vector<FileAuditInfo> fileInfos;
    FileAuditInfo info;
    info.fileName = "test.pdf";
    info.md5 = "d41d8cd98f00b204e9800998ecf8427e";
    info.size = 1024;
    fileInfos.push_back(info);
    manager.receiveBaseInfo("jobId-1", "callerPkg-1", std::vector<std::string>{});
    manager.receiveAuditInfo("jobId-1", printerInfo, printJob, fileInfos);
    manager.receiveJobStateUpdate("jobId-1", printerInfo, printJob);
    EXPECT_EQ(manager.securityMap_.size(), 0);
}
}  // namespace Print
}  // namespace OHOS
