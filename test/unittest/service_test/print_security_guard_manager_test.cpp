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
 * @tc.name: PrintSecurityGuardManagerTest_receiveAuditInfo_001
 * @tc.desc: Verify receiveAuditInfo with existing jobId in securityMap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_receiveAuditInfo_001, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList = {"/data/doc1.pdf"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet");
    PrintJob printJob;
    printJob.SetDuplexMode(1);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    manager.receiveBaseInfo("jobId-1", "callerPkg-1", fileList);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    manager.receiveAuditInfo("jobId-1", printerInfo, printJob, fileInfos);

    auto it = manager.securityMap_.find("jobId-1");
    ASSERT_NE(it, manager.securityMap_.end());
    ASSERT_NE(it->second, nullptr);
    EXPECT_EQ(it->second->files_.size(), 1U);
    EXPECT_EQ(it->second->files_[0].fileName, "doc1.pdf");
    EXPECT_EQ(it->second->duplexMode_, 1U);
    EXPECT_EQ(it->second->printerName_, "HP LaserJet");
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_receiveAuditInfo_002
 * @tc.desc: Verify receiveAuditInfo with non-existing jobId creates new entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_receiveAuditInfo_002, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    PrinterInfo printerInfo;
    PrintJob printJob;

    std::vector<FileAuditInfo> fileInfos;
    manager.receiveAuditInfo("jobId-unknown", printerInfo, printJob, fileInfos);

    auto it = manager.securityMap_.find("jobId-unknown");
    ASSERT_NE(it, manager.securityMap_.end());
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_receiveAuditInfo_003
 * @tc.desc: Verify receiveAuditInfo with empty fileInfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_receiveAuditInfo_003, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList;
    manager.receiveBaseInfo("jobId-1", "callerPkg-1", fileList);

    PrinterInfo printerInfo;
    PrintJob printJob;
    std::vector<FileAuditInfo> fileInfos;
    manager.receiveAuditInfo("jobId-1", printerInfo, printJob, fileInfos);

    auto it = manager.securityMap_.find("jobId-1");
    ASSERT_NE(it, manager.securityMap_.end());
    EXPECT_TRUE(it->second->files_.empty());
}

// ===== Full flow Tests =====

/**
 * @tc.name: PrintSecurityGuardManagerTest_FullFlow_001
 * @tc.desc: Verify full audit flow: receiveBaseInfo → receiveAuditInfo → receiveJobStateUpdate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_FullFlow_001, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList = {"/data/doc1.pdf"};

    // Step 1: receiveBaseInfo
    manager.receiveBaseInfo("jobId-flow1", "callerPkg", fileList);
    EXPECT_EQ(manager.securityMap_.size(), 1U);

    // Step 2: receiveAuditInfo
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet");
    PrintJob printJob;
    printJob.SetDuplexMode(1);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    manager.receiveAuditInfo("jobId-flow1", printerInfo, printJob, fileInfos);

    // Step 3: receiveJobStateUpdate (should clear the map entry)
我说呢    printJob.SetJobState(PRINT_JOB_COMPLETED);
    manager.receiveJobStateUpdate("jobId-flow1", printerInfo, printJob);
    EXPECT_EQ(manager.securityMap_.find("jobId-flow1"), manager.securityMap_.end());
}

/**
 * @tc.name: PrintSecurityGuardManagerTest_FullFlow_002
 * @tc.desc: Verify full audit flow with BLOCKED state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_FullFlow_002, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList = {"/data/doc1.pdf"};

    manager.receiveBaseInfo("jobId-blocked", "callerPkg", fileList);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Canon PIXMA");
    PrintJob printJob;
    printJob.SetDuplexMode(0);
    printJob.SetSubState(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    manager.AddBlockedSubState("jobId-blocked", PRINT_JOB_BLOCKED_OUT_OF_PAPER);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    manager.receiveAuditInfo("jobId-blocked", printerInfo, printJob, fileInfos);
    printJob.SetJobState(PRINT_JOB_COMPLETED);
    manager.receiveJobStateUpdate("jobId-blocked", printerInfo, printJob);

    EXPECT_EQ(manager.securityMap_.find("jobId-blocked"), manager.securityMap_.end());
}

// ===== clearAll Tests =====

/**
 * @tc.name: PrintSecurityGuardManagerTest_clearAll_001
 * @tc.desc: Verify clearAll clears all entries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_clearAll_001, TestSize.Level1)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList;

    manager.receiveBaseInfo("jobId-1", "caller1", fileList);
    manager.receiveBaseInfo("jobId-2", "caller2", fileList);
    manager.receiveBaseInfo("jobId-3", "caller3", fileList);
    EXPECT_EQ(manager.securityMap_.size(), 3U);

    manager.clearAll();
    EXPECT_EQ(manager.securityMap_.size(), 0U);
}

// ===== Multiple jobs Tests =====

/**
 * @tc.name: PrintSecurityGuardManagerTest_MultipleJobs_001
 * @tc.desc: Verify multiple concurrent jobs with separate audit info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardManagerTest, PrintSecurityGuardManagerTest_MultipleJobs_001, TestSize.Level1)
{
    PrintSecurityGuardManager manager;

    std::vector<std::string> fileList1 = {"/data/doc1.pdf"};
    std::vector<std::string> fileList2 = {"/data/doc2.pdf"};
    manager.receiveBaseInfo("jobId-1", "caller1", fileList1);
    manager.receiveBaseInfo("jobId-2", "caller2", fileList2);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("TestPrinter");
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos1 = {{"doc1.pdf", "md5_1", 100}};
    std::vector<FileAuditInfo> fileInfos2 = {{"doc2.pdf", "md5_2", 200}};

    manager.receiveAuditInfo("jobId-1", printerInfo, printJob, fileInfos1);
    manager.receiveAuditInfo("jobId-2", printerInfo, printJob, fileInfos2);

    auto it1 = manager.securityMap_.find("jobId-1");
    auto it2 = manager.securityMap_.find("jobId-2");
    ASSERT_NE(it1, manager.securityMap_.end());
    ASSERT_NE(it2, manager.securityMap_.end());
    EXPECT_EQ(it1->second->files_[0].fileName, "doc1.pdf");
    EXPECT_EQ(it2->second->files_[0].fileName, "doc2.pdf");
}
}  // namespace Print
}  // namespace OHOS
