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
#include "print_security_guard_util.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSecurityGuardUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintSecurityGuardUtilTest::SetUpTestCase(void)
{}

void PrintSecurityGuardUtilTest::TearDownTestCase(void)
{}

// ===== GenerateErrorCodes Tests =====

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_001
 * @tc.desc: Verify GenerateErrorCodes with single COMPLETED subState.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_001, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_COMPLETED_SUCCESS};
    auto result = GenerateErrorCodes(subStates);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_002
 * @tc.desc: Verify GenerateErrorCodes with single BLOCKED subState (out_of_paper).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_002, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_BLOCKED_OUT_OF_PAPER};
    auto result = GenerateErrorCodes(subStates);
    ASSERT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], "out_of_paper");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_003
 * @tc.desc: Verify GenerateErrorCodes with single BLOCKED subState (jammed).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_003, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_BLOCKED_JAMMED};
    auto result = GenerateErrorCodes(subStates);
    ASSERT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], "jammed");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_004
 * @tc.desc: Verify GenerateErrorCodes with multiple BLOCKED subStates.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_004, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_BLOCKED_OUT_OF_PAPER, PRINT_JOB_BLOCKED_OUT_OF_INK};
    auto result = GenerateErrorCodes(subStates);
    EXPECT_EQ(result.size(), 2U);
    // Results are sorted by string since we use std::set
    bool hasOutOfPaper = false;
    bool hasOutOfInk = false;
    for (const auto &code : result) {
        if (code == "out_of_paper") hasOutOfPaper = true;
        if (code == "out_of_ink") hasOutOfInk = true;
    }
    EXPECT_TRUE(hasOutOfPaper);
    EXPECT_TRUE(hasOutOfInk);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_005
 * @tc.desc: Verify GenerateErrorCodes with unknown subState.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_005, TestSize.Level1)
{
    std::set<uint32_t> subStates = {50};
    auto result = GenerateErrorCodes(subStates);
    ASSERT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], "unknown");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_006
 * @tc.desc: Verify GenerateErrorCodes with empty set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_006, TestSize.Level1)
{
    std::set<uint32_t> subStates;
    auto result = GenerateErrorCodes(subStates);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_007
 * @tc.desc: Verify GenerateErrorCodes with PRINT_JOB_BLOCKED_UNKNOWN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_007, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_BLOCKED_UNKNOWN};
    auto result = GenerateErrorCodes(subStates);
    ASSERT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], "unknown");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_008
 * @tc.desc: Verify GenerateErrorCodes with combined subState code (>99, e.g. 708 = 07,08).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_008, TestSize.Level1)
{
    // 708 => "0708" => 07(out_of_paper) + 08(out_of_ink)
    std::set<uint32_t> subStates = {708};
    auto result = GenerateErrorCodes(subStates);
    ASSERT_EQ(result.size(), 2U);
    bool hasOutOfPaper = false;
    bool hasOutOfInk = false;
    for (const auto &code : result) {
        if (code == "out_of_paper") hasOutOfPaper = true;
        if (code == "out_of_ink") hasOutOfInk = true;
    }
    EXPECT_TRUE(hasOutOfPaper);
    EXPECT_TRUE(hasOutOfInk);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_009
 * @tc.desc: Verify GenerateErrorCodes filters out SUCCESS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_009, TestSize.Level1)
{
    std::set<uint32_t> subStates = {
        PRINT_JOB_COMPLETED_SUCCESS,
        PRINT_JOB_COMPLETED_FAILED,
        PRINT_JOB_COMPLETED_CANCELLED,
        PRINT_JOB_COMPLETED_FILE_CORRUPT
    };
    auto result = GenerateErrorCodes(subStates);
    EXPECT_EQ(result.size(), 3U);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GenerateErrorCodes_010
 * @tc.desc: Verify GenerateErrorCodes with duplicate subStates (deduplication via set).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GenerateErrorCodes_010, TestSize.Level1)
{
    std::set<uint32_t> subStates = {PRINT_JOB_BLOCKED_OUT_OF_PAPER};
    auto result1 = GenerateErrorCodes(subStates);
    auto result2 = GenerateErrorCodes(subStates);
    EXPECT_EQ(result1, result2);
}

// ===== ExtractFileName Tests =====

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileName_001
 * @tc.desc: Verify ExtractFileName with full path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileName_001, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/data/local/tmp/doc1.pdf"), "doc1.pdf");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileName_002
 * @tc.desc: Verify ExtractFileName with only file name (no path).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileName_002, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("doc1.pdf"), "doc1.pdf");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileName_003
 * @tc.desc: Verify ExtractFileName with empty string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileName_003, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName(""), "");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileName_004
 * @tc.desc: Verify ExtractFileName with trailing slash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileName_004, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/data/local/tmp/"), "");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileName_005
 * @tc.desc: Verify ExtractFileName with multiple slashes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileName_005, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/a/b/c/d/file.txt"), "file.txt");
}

// ===== ExtractFileListFromOption Tests =====

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileListFromOption_001
 * @tc.desc: Verify ExtractFileListFromOption with valid jobName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileListFromOption_001, TestSize.Level1)
{
    std::string option = R"({"jobName":"test_doc.pdf"})";
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    ASSERT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], "test_doc.pdf");
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileListFromOption_002
 * @tc.desc: Verify ExtractFileListFromOption with no jobName field.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileListFromOption_002, TestSize.Level1)
{
    std::string option = R"({"otherField":"value"})";
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileListFromOption_003
 * @tc.desc: Verify ExtractFileListFromOption with invalid JSON.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileListFromOption_003, TestSize.Level1)
{
    std::string option = "not a json";
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileListFromOption_004
 * @tc.desc: Verify ExtractFileListFromOption with empty string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileListFromOption_004, TestSize.Level1)
{
    std::string option;
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ExtractFileListFromOption_005
 * @tc.desc: Verify ExtractFileListFromOption with jobName as non-string type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ExtractFileListFromOption_005, TestSize.Level1)
{
    std::string option = R"({"jobName":123})";
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    EXPECT_TRUE(result.empty());
}

// ===== GetPrinterType Tests =====

/**
 * @tc.name: PrintSecurityGuardUtilTest_GetPrinterType_001
 * @tc.desc: Verify GetPrinterType with P2P printer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GetPrinterType_001, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::GetPrinterType("P2P_printer"), FROM_P2P);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GetPrinterType_002
 * @tc.desc: Verify GetPrinterType with EPRINT printer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GetPrinterType_002, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::GetPrinterType("EPRINT_printer"), FROM_EPRINT);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GetPrinterType_003
 * @tc.desc: Verify GetPrinterType with USB printer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GetPrinterType_003, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::GetPrinterType("USB_printer"), FROM_USB);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GetPrinterType_004
 * @tc.desc: Verify GetPrinterType with local network printer (default).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GetPrinterType_004, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::GetPrinterType("ipp://192.168.1.1"), FROM_LOCAL_NET);
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_GetPrinterType_005
 * @tc.desc: Verify GetPrinterType with empty string (default).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_GetPrinterType_005, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::GetPrinterType(""), FROM_LOCAL_NET);
}

// ===== Data Table: All errorCode mappings =====

/**
 * @tc.name: PrintSecurityGuardUtilTest_ErrorCodeMapping_001
 * @tc.desc: Verify all COMPLETED subState to errorCode mappings.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ErrorCodeMapping_001, TestSize.Level1)
{
    struct TestCase {
        uint32_t subState;
        std::string expected;
    };
    std::vector<TestCase> testCases = {
        {PRINT_JOB_COMPLETED_FAILED, "failed"},
        {PRINT_JOB_COMPLETED_CANCELLED, "cancelled"},
        {PRINT_JOB_COMPLETED_FILE_CORRUPT, "file_corrupt"},
    };
    for (const auto &tc : testCases) {
        std::set<uint32_t> subStates = {tc.subState};
        auto result = GenerateErrorCodes(subStates);
        ASSERT_EQ(result.size(), 1U) << "Failed for subState " << tc.subState;
        EXPECT_EQ(result[0], tc.expected) << "Failed for subState " << tc.subState;
    }
    // SUCCESS should be filtered out
    EXPECT_TRUE(GenerateErrorCodes({PRINT_JOB_COMPLETED_SUCCESS}).empty());
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_ErrorCodeMapping_002
 * @tc.desc: Verify all BLOCKED subState to errorCode mappings.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_ErrorCodeMapping_002, TestSize.Level1)
{
    struct TestCase {
        uint32_t subState;
        std::string expected;
    };
    std::vector<TestCase> testCases = {
        {PRINT_JOB_BLOCKED_OFFLINE, "offline"},
        {PRINT_JOB_BLOCKED_BUSY, "busy"},
        {PRINT_JOB_BLOCKED_CANCELLED, "cancelled"},
        {PRINT_JOB_BLOCKED_OUT_OF_PAPER, "out_of_paper"},
        {PRINT_JOB_BLOCKED_OUT_OF_INK, "out_of_ink"},
        {PRINT_JOB_BLOCKED_OUT_OF_TONER, "out_of_toner"},
        {PRINT_JOB_BLOCKED_JAMMED, "jammed"},
        {PRINT_JOB_BLOCKED_DOOR_OPEN, "door_open"},
        {PRINT_JOB_BLOCKED_SERVICE_REQUEST, "service_request"},
        {PRINT_JOB_BLOCKED_LOW_ON_INK, "low_on_ink"},
        {PRINT_JOB_BLOCKED_LOW_ON_TONER, "low_on_toner"},
        {PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK, "really_low_on_ink"},
        {PRINT_JOB_BLOCKED_BAD_CERTIFICATE, "bad_certificate"},
        {PRINT_JOB_BLOCKED_DRIVER_EXCEPTION, "driver_exception"},
        {PRINT_JOB_BLOCKED_ACCOUNT_ERROR, "account_error"},
        {PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR, "print_permission_error"},
        {PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR, "color_permission_error"},
        {PRINT_JOB_BLOCKED_NETWORK_ERROR, "network_error"},
        {PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR, "server_connection_error"},
        {PRINT_JOB_BLOCKED_LARGE_FILE_ERROR, "large_file_error"},
        {PRINT_JOB_BLOCKED_FILE_PARSING_ERROR, "file_parsing_error"},
        {PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION, "slow_file_conversion"},
        {PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR, "file_uploading_error"},
        {PRINT_JOB_BLOCKED_DRIVER_MISSING, "driver_missing"},
        {PRINT_JOB_BLOCKED_INTERRUPT, "interrupt"},
        {PRINT_JOB_BLOCKED_AUTHENTICATION, "authentication_required"},
        {PRINT_JOB_BLOCKED_BANNED, "banned"},
        {PRINT_JOB_BLOCKED_SMB_PRINTER, "smb_printer_error"},
        {PRINT_JOB_BLOCKED_INPUT_TRAY_MISSING, "input_tray_missing"},
        {PRINT_JOB_BLOCKED_SECURITY_POLICY_RESTRICTED, "security_policy_restricted"},
        {PRINT_JOB_BLOCKED_INVALID_NUMBER_UP, "invalid_number_up"},
        {PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE, "printer_unavailable"},
        {PRINT_JOB_BLOCKED_UNKNOWN, "unknown"},
    };
    for (const auto &tc : testCases) {
        std::set<uint32_t> subStates = {tc.subState};
        auto result = GenerateErrorCodes(subStates);
        ASSERT_EQ(result.size(), 1U) << "Failed for subState " << tc.subState;
        EXPECT_EQ(result[0], tc.expected) << "Failed for subState " << tc.subState;
    }
}
/**
 * @tc.name: PrintSecurityGuardUtilTest_IsPrintableFile_001
 * @tc.desc: Verify IsPrintableFile with known printable extensions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_IsPrintableFile_001, TestSize.Level1)
{
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("doc.pdf"));
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("doc.docx"));
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("doc.jpg"));
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("doc.PDF"));
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_IsPrintableFile_002
 * @tc.desc: Verify IsPrintableFile with non-printable extensions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_IsPrintableFile_002, TestSize.Level1)
{
    EXPECT_FALSE(PrintSecurityGuardUtil::IsPrintableFile("lib.a"));
    EXPECT_FALSE(PrintSecurityGuardUtil::IsPrintableFile("app.exe"));
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_IsPrintableFile_003
 * @tc.desc: Verify IsPrintableFile with no extension or empty string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_IsPrintableFile_003, TestSize.Level1)
{
    EXPECT_FALSE(PrintSecurityGuardUtil::IsPrintableFile("noextension"));
    EXPECT_FALSE(PrintSecurityGuardUtil::IsPrintableFile(""));
}

/**
 * @tc.name: PrintSecurityGuardUtilTest_IsPrintableFile_004
 * @tc.desc: Verify IsPrintableFile with full path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSecurityGuardUtilTest, PrintSecurityGuardUtilTest_IsPrintableFile_004, TestSize.Level1)
{
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("/data/storage/doc.pdf"));
    EXPECT_TRUE(PrintSecurityGuardUtil::IsPrintableFile("/a/b/c/report.docx"));
    EXPECT_FALSE(PrintSecurityGuardUtil::IsPrintableFile("/usr/lib/libstdc++.so"));
}

}  // namespace Print
}  // namespace OHOS
