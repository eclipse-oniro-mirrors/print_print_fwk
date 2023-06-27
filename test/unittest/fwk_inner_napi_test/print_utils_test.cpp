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
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0001, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::ToLower("TEST");
//     EXPECT_EQ("test", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0002
//  * @tc.desc: Verify the getExtensionId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0002, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetExtensionId("TEST");
//     EXPECT_EQ("", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0003
//  * @tc.desc: Verify the getExtensionId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0003, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetExtensionId("TEST:ExtensionId");
//     EXPECT_EQ("TEST", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0004
//  * @tc.desc: Verify the getGlobalId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0004, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetGlobalId("TEST", "ExtensionId");
//     EXPECT_EQ("TEST:ExtensionId", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0005
//  * @tc.desc: Verify the getLocalId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0005, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetLocalId("TEST", "ExtensionId");
//     EXPECT_EQ("", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0006
//  * @tc.desc: Verify the getLocalId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtilsTest_0006, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetLocalId("TEST:test", "ExtensionId");
//     EXPECT_EQ("", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0007
//  * @tc.desc: Verify the getLocalId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0007, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetLocalId("TEST:test", "TEST");
//     EXPECT_EQ("TEST:", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0008
//  * @tc.desc: Verify the encodeExtensionCid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0008, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::EncodeExtensionCid("TEST", "test");
//     EXPECT_EQ("TEST:test", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0009
//  * @tc.desc: Verify the decodeExtensionCid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0009, TestSize.Level1)
// {
//     std::string extensionId = "";
//     uint32_t callbackId;
//     std::string result = OHOS::Print::PrintUtils::DecodeExtensionCid("TEST", extensionId, callbackId);
//     EXPECT_FALSE(result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0010
//  * @tc.desc: Verify the decodeExtensionCid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0010, TestSize.Level1)
// {
//     std::string extensionId = "";
//     uint32_t callbackId;
//     std::string result = OHOS::Print::PrintUtils::DecodeExtensionCid("TEST:test", extensionId, callbackId);
//     EXPECT_TRUE(result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0011
//  * @tc.desc: Verify the getTaskEventId function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0011, TestSize.Level1)
// {
//     std::string extensionId = "";
//     uint32_t callbackId;
//     std::string result = OHOS::Print::PrintUtils::GetTaskEventId("TEST", "test");
//     EXPECT_EQ("TEST:test", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0012
//  * @tc.desc: Verify the openFile function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0012, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::OpenFile("/error");
//     EXPECT_EQ(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0013
//  * @tc.desc: Verify the openFile function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0013, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::OpenFile("/data/e11");
//     EXPECT_EQ(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0014
//  * @tc.desc: Verify the openFile function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0014, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::OpenFile("/data/service/e11");
//     EXPECT_NE(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0015
//  * @tc.desc: Verify the isPathValid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0015, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::IsPathValid("/data/service/e11/data/service/
//     e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11/data/service/
//     e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11");
//     EXPECT_EQ(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0016
//  * @tc.desc: Verify the isPathValid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0016, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::IsPathValid("/data/service/e11//data/service/e11");
//     EXPECT_EQ(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0017
//  * @tc.desc: Verify the isPathValid function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0017, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::IsPathValid("/data/service/e11");
//     EXPECT_NE(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0018
//  * @tc.desc: Verify the getIdFromFdPath function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0018, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::GetIdFromFdPath("/data/service");
//     EXPECT_EQ(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0019
//  * @tc.desc: Verify the getIdFromFdPath function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0019, TestSize.Level1)
// {
//     int32_t result = OHOS::Print::PrintUtils::GetIdFromFdPath("/data/service/e11");
//     EXPECT_NE(PRINT_INVALID_ID, result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0020
//  * @tc.desc: Verify the getJobStateChar function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0020, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetJobStateChar(0);
//     EXPECT_EQ("PRINT_JOB_PREPARED", result);
// }

// /**
//  * @tc.name: PrintUtilsTest_0021
//  * @tc.desc: Verify the getJobStateChar function.
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(PrintUtilsTest, PrintUtsilsTest_0021, TestSize.Level1)
// {
//     std::string result = OHOS::Print::PrintUtils::GetJobStateChar(6);
//     EXPECT_EQ("PRINT_JOB_UNKNOWN", result);
// }
}  // namespace Print
}  // namespace OHOS
