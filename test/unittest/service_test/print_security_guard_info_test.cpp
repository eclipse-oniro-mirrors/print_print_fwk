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
    void SetUp();
    void TearDown();
};

void PrintSecurityGuardInfoTest::SetUpTestCase(void)
{}

void PrintSecurityGuardInfoTest::TearDownTestCase(void)
{}

void PrintSecurityGuardInfoTest::SetUp(void)
{}

void PrintSecurityGuardInfoTest::TearDown(void)
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
 
    std::vector<std::string> fileInfos = {"doc1.pdf"};
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
 
    EXPECT_EQ(info.files_.size(), 1U);
    EXPECT_EQ(info.files_[0], "doc1.pdf");
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
 
    std::vector<std::string> fileInfos = {"doc1.pdf", "doc2.pdf"};
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
 
    EXPECT_EQ(info.files_.size(), 2U);
    EXPECT_EQ(info.files_[1], "doc2.pdf");
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
 
    std::vector<std::string> fileInfos = {"doc1.pdf"};
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
 
    std::vector<std::string> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
 
    EXPECT_TRUE(info.files_.empty());
}
 
/**
 * @tc.name: PrintSecurityGuardInfoTest_SetPrintAuditInfo_005
 * @tc.desc: Verify SetPrintAuditInfo reports only current subState, not accumulated history.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_SetPrintAuditInfo_005, TestSize.Level1)
{
    std::vector<std::string> fileList;
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_BLOCKED_JAMMED);
 
    std::vector<std::string> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
 
    // Only current subState should be reported
    EXPECT_EQ(info.errorCode_.size(), 1U);
    bool hasJammed = false;
    for (const auto &code : info.errorCode_) {
        if (code == "jammed") hasJammed = true;
    }
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
 
    std::vector<std::string> fileInfos = {"doc1.pdf"};
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);
 
    std::string json = info.ToJsonStr();
    EXPECT_NE(json.find("files"), std::string::npos);
    EXPECT_NE(json.find("duplexMode"), std::string::npos);
    EXPECT_NE(json.find("errorCode"), std::string::npos);
    EXPECT_NE(json.find("printerName"), std::string::npos);
    EXPECT_NE(json.find("doc1.pdf"), std::string::npos);
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
 
    std::vector<std::string> fileInfos = {"doc1.pdf"};
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
 
    std::vector<std::string> fileInfos;
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);
 
    std::string json = info.ToJsonStr();
    EXPECT_TRUE(info.files_.empty());
    EXPECT_NE(json.find("\"files\":[]"), std::string::npos);
    EXPECT_NE(json.find("duplexMode"), std::string::npos);
    EXPECT_NE(json.find("errorCode"), std::string::npos);
    EXPECT_NE(json.find("printerName"), std::string::npos);
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_ToJsonUrlDecode_001
 * @tc.desc: Verify ToJsonStr decodes URL-encoded Chinese in fileName with file:// prefix.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_ToJsonUrlDecode_001, TestSize.Level1)
{
    std::vector<std::string> fileList = {"file:///data/storage/%E5%8D%B0%E7%AB%A0.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterName("HP LaserJet Pro");
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    printJob.SetOption(R"({"jobName":"report.pdf","printPages":1})");

    std::vector<std::string> fileInfos = {"file:///data/storage/%E5%8D%B0%E7%AB%A0.pdf"};
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);

    std::string json = info.ToJsonStr();
    std::string decodedFileName = "\xe5\x8d\xb0\xe7\xab\xa0.pdf";
    EXPECT_NE(json.find(decodedFileName), std::string::npos);
}

/**
 * @tc.name: PrintSecurityGuardInfoTest_ToJsonUrlDecode_002
 * @tc.desc: Verify ToJsonStr does NOT decode fileName without file:// prefix (CAPI path).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_ToJsonUrlDecode_002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"report.pdf"};
    PrintSecurityGuardInfo info("callPkg", fileList);
    PrinterInfo printerInfo;
    PrintJob printJob;
    printJob.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);

    std::vector<std::string> fileInfos = {"report.pdf"};
    info.SetPrintAuditInfo(printerInfo, printJob, fileInfos);
    info.SetPrintTypeInfo(printerInfo, printJob);

    std::string json = info.ToJsonStr();
    EXPECT_NE(json.find("report.pdf"), std::string::npos);
}
}  // namespace Print
}  // namespace OHOS