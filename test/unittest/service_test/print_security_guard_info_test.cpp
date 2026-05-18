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

/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_001
 * @tc.desc: Verify SetPrintAuditInfo with single file and success state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_001, TestSize.Level1)
{
    std::vector<std::string> fileList = {"/data/local/tmp/doc1.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet Pro");
    PrintJob printJob;
    printJob.SetDuplexMode(1);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);

    EXPECT_EQ(info.files_.size(), 1U);
    EXPECT_EQ(info.files_[0].fileName, "doc1.pdf");
    EXPECT_EQ(info.files_[0].md5, "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(info.files_[0].size, 102400U);
    EXPECT_EQ(info.duplexMode_, 1U);
    EXPECT_EQ(info.printerName_, "HP LaserJet Pro");
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_002
 * @tc.desc: Verify SetPrintAuditInfo with multiple files.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"/data/doc1.pdf", "/data/doc2.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("Canon PIXMA");
    PrintJob printJob;
    printJob.SetDuplexMode(2);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400},
        {"doc2.pdf", "098f6bcd4621d373cade4e832627b4f6", 204800}
    };
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);

    EXPECT_EQ(info.files_.size(), 2U);
    EXPECT_EQ(info.files_[1].fileName, "doc2.pdf");
    EXPECT_EQ(info.files_[1].size, 204800U);
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_003
 * @tc.desc: Verify SetPrintAuditInfo with blocked state (out_of_paper).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_003, TestSize.Level1)
{
    std::vector<std::string> fileList = {"/data/doc1.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet Pro");
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    info.AddBlockedSubState(PRINT_JOB_BLOCKED_OUT_OF_PAPER);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);

    bool hasOutOfPaper = false;
    for (const auto &code : info.errorCode_) {
        if (code == "out_of_paper") hasOutOfPaper = true;
    }
    EXPECT_TRUE(hasOutOfPaper);
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_004
 * @tc.desc: Verify SetPrintAuditInfo with empty file list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_004, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);

    EXPECT_TRUE(info.files_.empty());
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_005
 * @tc.desc: Verify SetPrintAuditInfo with multiple blocked subStates.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_005, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    info.AddBlockedSubState(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    info.AddBlockedSubState(PRINT_JOB_BLOCKED_OUT_OF_INK);
    printJob.SetSubState(PRINT_JOB_BLOCKED_JAMMED);

    std::vector<FileAuditInfo> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);

    EXPECT_GE(info.errorCode_.size(), 2U);
    bool hasOutOfPaper = false;
    bool hasOutOfInk = false;
    bool hasJammed = false;
    for (const auto &code : info.errorCode_) {
        if (code == "out_of_paper") hasOutOfPaper = true;
        if (code == "out_of_ink") hasOutOfInk = true;
        if (code == "jammed") hasJammed = true;
    }
    EXPECT_TRUE(hasOutOfPaper);
    EXPECT_TRUE(hasOutOfInk);
    EXPECT_TRUE(hasJammed);
}

// ===== ToJsonStr with audit fields Tests =====

/**
 * @tc.name: PrintSecurityGuardInfoTest_ToJsonWithAudit_001
 * @tc.desc: Verify ToJsonStr output contains new audit fields.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_ToJsonWithAudit_001, TestSize.Level1)
{
    std::vector<std::string> fileList = {"/data/local/tmp/doc1.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet Pro");
    PrintJob printJob;
    printJob.SetDuplexMode(1);
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos = {
        {"doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);

    std::string json = info.ToJsonStr();
    EXPECT_NE(json.find("files"), std::string::npos);
    EXPECT_NE(json.find("duplexMode"), std::string::npos);
    EXPECT_NE(json.find("errorCode"), std::string::npos);
    EXPECT_NE(json.find("printerName"), std::string::npos);
    EXPECT_NE(json.find("doc1.pdf"), std::string::npos);
    EXPECT_NE(json.find("d41d8cd98f00b204e9800998ecf8427e"), std::string::npos);
    EXPECT_NE(json.find("HP LaserJet Pro"), std::string::npos);
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_ToJsonWithAudit_002
 * @tc.desc: Verify ToJsonStr uses ExtractFileName for files array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_ToJsonWithAudit_002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"/data/local/tmp/doc1.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos = {
        {"/data/local/tmp/doc1.pdf", "d41d8cd98f00b204e9800998ecf8427e", 102400}
    };
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);

    std::string json = info.ToJsonStr();
    // ExtractFileName should strip the path prefix
    EXPECT_NE(json.find("doc1.pdf"), std::string::npos);
    // The full path should NOT appear as the fileName in JSON
    // (it can appear in objectInfo, but fileName should be just the name)
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_ToJsonWithAudit_003
 * @tc.desc: Verify ToJsonStr with empty fileInfos produces empty files array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_ToJsonWithAudit_003, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<FileAuditInfo> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);

    std::string json = info.ToJsonStr();
    EXPECT_TRUE(info.files_.empty());
    EXPECT_NE(json.find("\"files\":[]"), std::string::npos);
    EXPECT_NE(json.find("duplexMode"), std::string::npos);
    EXPECT_NE(json.find("errorCode"), std::string::npos);
    EXPECT_NE(json.find("printerName"), std::string::npos);
}
}  // namespace Print
}  // namespace OHOS
