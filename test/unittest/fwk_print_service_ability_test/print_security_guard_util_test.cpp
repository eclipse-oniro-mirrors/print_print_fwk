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
    blockedSubStates.insert(PRINT_JOB_COMPLETED_FAILED);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "failed");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_004, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_COMPLETED_CANCELLED);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "cancelled");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_005, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    blockedSubStates.insert(PRINT_JOB_BLOCKED_JAMMED);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 2);
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_006, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_INK);
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OFFLINE);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 2);
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_007, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_BANNED);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "banned");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_008, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_DRIVER_EXCEPTION);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "driver_exception");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_009, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_NETWORK_ERROR);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "network_error");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_010, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_UNKNOWN);
    blockedSubStates.insert(9999);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "unknown");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_011, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    blockedSubStates.insert(PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "out_of_paper");
}

HWTEST_F(PrintSecurityGuardUtilTest, GenerateErrorCodes_012, TestSize.Level1)
{
    std::set<uint32_t> blockedSubStates;
    blockedSubStates.insert(9999);
    auto result = GenerateErrorCodes(blockedSubStates);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "unknown");
}

HWTEST_F(PrintSecurityGuardUtilTest, ExtractFileName_001, TestSize.Level1)
{
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/data/test/file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/file.pdf"), "file.pdf");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName(""), "");
    EXPECT_EQ(PrintSecurityGuardUtil::ExtractFileName("/a/b/c/d.doc"), "d.doc");
}

} // namespace Print
} // namespace OHOS
