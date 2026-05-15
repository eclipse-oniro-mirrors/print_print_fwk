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
#include "print_security_guard_util.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintSecurityGuardUtilTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(PrintSecurityGuardUtilTest, SubStateToErrorCodeStr_001, TestSize.Level1)
{
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_COMPLETED_SUCCESS), "success");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_COMPLETED_FAILED), "failed");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_COMPLETED_CANCELLED), "cancelled");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_COMPLETED_FILE_CORRUPT), "file_corrupt");
}

HWTEST_F(PrintSecurityGuardUtilTest, SubStateToErrorCodeStr_002, TestSize.Level1)
{
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_OUT_OF_PAPER), "out_of_paper");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_JAMMED), "jammed");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_OUT_OF_INK), "out_of_ink");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_OFFLINE), "offline");
}

HWTEST_F(PrintSecurityGuardUtilTest, SubStateToErrorCodeStr_003, TestSize.Level1)
{
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_BANNED), "banned");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_DRIVER_EXCEPTION), "driver_exception");
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_NETWORK_ERROR), "network_error");
}

HWTEST_F(PrintSecurityGuardUtilTest, SubStateToErrorCodeStr_004, TestSize.Level1)
{
    EXPECT_EQ(SubStateToErrorCodeStr(PRINT_JOB_BLOCKED_UNKNOWN), "unknown");
    EXPECT_EQ(SubStateToErrorCodeStr(999), "other_error");
    EXPECT_EQ(SubStateToErrorCodeStr(0xFFFFFFFF), "other_error");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_001, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    auto result = GenerateErrorCodes(blockedSubStates);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_002, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_COMPLETED_SUCCESS);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "success");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_003, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    blockedSubStates.insert(PRINT_JOB_BLOCKED_JAMMED);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 2);
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_004, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_UNKNOWN);
    blockedSubStates.insert(9999);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "unknown");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_005, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "out_of_paper");
}

HWTEST_F(PrintSecurityGuardUtilTest, ExtractFileName_001, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/data/test/file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName(""), "");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/a/b/c/d.doc"), "d.doc");
}

HWTEST_F(PrintSecurityGuardUtilTest, CalculateFileMd5_001, TestSize.Level1)
{
    std::string md5 = PrintSecurityGuardUtil::CalculateFileMd5(static_cast<uint32_t>(-1));
    EXPECT_TRUE(md5.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, CalculateFileMd5_002, TestSize.Level1)
{
    std::string md5 = PrintSecurityGuardUtil::CalculateFileMd5(99999);
    EXPECT_TRUE(md5.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, GetFileSize_001, TestSize.Level1)
{
    uint64_t size = PrintSecurityGuardUtil::GetFileSize(static_cast<uint32_t>(-1));
    EXPECT_EQ(size, 0);
}

HWTEST_F(PrintSecurityGuardUtilTest, GetFileSize_002, TestSize.Level1)
{
    uint64_t size = PrintSecurityGuardUtil::GetFileSize(99999);
    EXPECT_EQ(size, 0);
}

HWTEST_F(PrintSecurityGuardUtilTest, Md5HashBuffer_001, TestSize.Level1)
{
    std::string md5 = PrintSecurityGuardUtil::Md5HashBuffer(nullptr, 0);
    EXPECT_TRUE(md5.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, Md5HashBuffer_002, TestSize.Level1)
{
    const char* data = "test";
    std::string md5 = PrintSecurityGuardUtil::Md5HashBuffer(data, 0);
    EXPECT_TRUE(md5.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, Md5HashBuffer_003, TestSize.Level1)
{
    const char* data = nullptr;
    std::string md5 = PrintSecurityGuardUtil::Md5HashBuffer(data, 10);
    EXPECT_TRUE(md5.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, CalculateFileAuditInfo_001, TestSize.Level1)
{
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;
    auto result = PrintSecurityGuardUtil::CalculateFileAuditInfo(fileList, fdList);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintSecurityGuardUtilTest, CalculateFileAuditInfo_002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"test.pdf"};
    std::vector<uint32_t> fdList = {static_cast<uint32_t>(-1)};
    auto result = PrintSecurityGuardUtil::CalculateFileAuditInfo(fileList, fdList);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].fileName, "test.pdf");
    EXPECT_TRUE(result[0].md5.empty());
    EXPECT_EQ(result[0].size, 0);
}

} // namespace Print
} // namespace OHOS
