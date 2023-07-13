/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applipcable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "iservice_registry.h"
#include "print_utils.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintUtilsTest::SetUpTestCase(void) {}

void PrintUtilsTest::TearDownTestCase(void) {}

void PrintUtilsTest::SetUp(void) {}

void PrintUtilsTest::TearDown(void) {}

/**
 * @tc.name: PrintUtilsTest_0001
 * @tc.desc: Verify the toLower function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0001, TestSize.Level1)
{
    std::string testResult = "test";
    std::string result = PrintUtils::ToLower("TEST");
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0002
 * @tc.desc: Verify the getExtensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0002, TestSize.Level1)
{
    std::string gid = "com.sample.ext";
    std::string testResult = "";
    std::string result = PrintUtils::GetExtensionId(gid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0003
 * @tc.desc: Verify the getExtensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0003, TestSize.Level1)
{
    std::string gid = "com.sample.ext:1234";
    std::string testResult = "com.sample.ext";
    std::string result = PrintUtils::GetExtensionId(gid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0004
 * @tc.desc: Verify the getGlobalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0004, TestSize.Level1)
{
    std::string id = "com.sample.ext";
    std::string localId = "1234";
    std::string testResult = "com.sample.ext:1234";
    std::string result = PrintUtils::GetGlobalId(id, localId);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0005
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0005, TestSize.Level1)
{
    std::string gid = "com.sample.ext";
    std::string id = "com.sample.ext";
    std::string testResult = "";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0006
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0006, TestSize.Level1)
{
    std::string gid = "com.sample.ext:1234";
    std::string id = "com.sample.extt";
    std::string testResult = "";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0007
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0007, TestSize.Level1)
{
    std::string gid = "com.sample.ext:1234";
    std::string id = "com.sample.ext4";
    std::string testResult = "1234";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_NE(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0008
 * @tc.desc: Verify the encodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0008, TestSize.Level1)
{
    std::string gid = "com.sample.ext";
    uint32_t cid = 1;
    std::string testResult = "com.sample.ext:1";
    std::string result = PrintUtils::EncodeExtensionCid(gid, cid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0009
 * @tc.desc: Verify the decodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0009, TestSize.Level1)
{
    std::string gid = "com.sample.ext";
    std::string extensionId = "com.sample.ext";
    uint32_t callbackId;
    EXPECT_FALSE(PrintUtils::DecodeExtensionCid(gid, extensionId, callbackId));
}

/**
 * @tc.name: PrintUtilsTest_0010
 * @tc.desc: Verify the decodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0010, TestSize.Level1)
{
    std::string gid = "com.sample.ext:1";
    std::string extensionId = "com.sample.ext";
    uint32_t testCid = 1;
    uint32_t callbackId = 0;
    EXPECT_TRUE(PrintUtils::DecodeExtensionCid(gid, extensionId, callbackId));
    EXPECT_EQ(testCid, callbackId);
}

/**
 * @tc.name: PrintUtilsTest_0011
 * @tc.desc: Verify the getTaskEventId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0011, TestSize.Level1)
{
    std::string taskId = "1234";
    std::string type = "block";
    std::string testResult = "block-1234";
    std::string result = PrintUtils::GetTaskEventId(taskId, type);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0012
 * @tc.desc: Verify the openFile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0012, TestSize.Level1)
{
    int32_t result = PrintUtils::OpenFile("/error");
    EXPECT_EQ(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0013
 * @tc.desc: Verify the openFile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0013, TestSize.Level1)
{
    int32_t result = PrintUtils::OpenFile("/data/e11");
    EXPECT_EQ(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0014
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0014, TestSize.Level1)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11/data/service/ \
    e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11/data/service/ \
    e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0015
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0015, TestSize.Level1)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11//data/service/e11");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0016
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0016, TestSize.Level1)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11");
    EXPECT_NE(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0017
 * @tc.desc: Verify the getIdFromFdPath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0017, TestSize.Level1)
{
    int32_t result = PrintUtils::GetIdFromFdPath("/data/service");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0018
 * @tc.desc: Verify the getIdFromFdPath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0018, TestSize.Level1)
{
    int32_t result = PrintUtils::GetIdFromFdPath("/data/service/e11");
    EXPECT_NE(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0019
 * @tc.desc: Verify the getJobStateChar function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0019, TestSize.Level1)
{
    std::string testResult = "PRINT_JOB_PREPARED";
    std::string result = PrintUtils::GetJobStateChar(PRINT_JOB_PREPARED);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0020
 * @tc.desc: Verify the getJobStateChar function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0020, TestSize.Level1)
{
    std::string testResult = "PRINT_JOB_UNKNOWN";
    std::string result = PrintUtils::GetJobStateChar(PRINT_JOB_PREPARED + 100);
    EXPECT_EQ(testResult, result);
}
}  // namespace Print
}  // namespace OHOS
