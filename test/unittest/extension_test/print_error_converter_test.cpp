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

#include "print_error_converter.h"
#include "ability_manager_errors.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
using namespace AAFwk;

class PrintErrorConverterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintErrorConverterTest::SetUpTestCase(void)
{}

void PrintErrorConverterTest::TearDownTestCase(void)
{}

void PrintErrorConverterTest::SetUp(void)
{}

void PrintErrorConverterTest::TearDown(void)
{}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_0001, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_OK), E_PRINT_NONE);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_NoPermission, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(CHECK_PERMISSION_FAILED), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_STATIC_CFG_PERMISSION), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_NO_PERMISSION_CALLER), E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_NotSystemApp, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_NOT_SYSTEM_APP), E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_InvalidParameter, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(RESOLVE_ABILITY_ERR), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(RESOLVE_APP_ERR), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(RESOLVE_CALL_ABILITY_TYPE_ERR), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(RESOLVE_CALL_ABILITY_INNER_ERR), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_INVALID_CALLER), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(INVALID_CALLER_TOKEN), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_NATIVE_ABILITY_NOT_FOUND), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_TARGET_BUNDLE_NOT_EXIST), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_BUNDLE_NOT_EXIST), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_ABILITY_TYPE_INVALID), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_InvalidExtension, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_INVALID_EXTENSION_TYPE), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(EXTENSION_ABILITY_NOT_EXIST), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(EXTENSION_ABILITY_INFO_NOT_QUERY_BY_URI), E_PRINT_INVALID_EXTENSION);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_RpcFailure, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(CONNECTION_NOT_EXIST), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(INVALID_CONNECTION_STATE), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(CONNECTION_TIMEOUT), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(TARGET_ABILITY_NOT_SERVICE), E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_ServerFailure, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ABILITY_SERVICE_NOT_CONNECTED), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(GET_ABILITY_SERVICE_FAILED), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_APP_MGR_SERVICE_NOT_READY), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_ABILITY_NOT_FOREGROUND), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_InvalidUserid, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(INVALID_USERID_VALUE), E_PRINT_INVALID_USERID);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(ERR_CROSS_USER), E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_Terminate, TestSize.Level0)
{
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(TERMINATE_LAUNCHER_DENIED), E_PRINT_GENERIC_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(TERMINATE_SERVICE_IS_CONNECTED), E_PRINT_GENERIC_FAILURE);
    EXPECT_EQ(PrintErrorConverter::FromAafwkError(TERMINATE_ABILITY_RESULT_FAILED), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintErrorConverterTest, PrintErrorConverterTest_Default, TestSize.Level0)
{
    const ErrCode unmappedCodes[] = { 1, 100, 9999, 4000000 };
    for (auto code : unmappedCodes) {
        EXPECT_EQ(PrintErrorConverter::FromAafwkError(code), E_PRINT_GENERIC_FAILURE) <<
            "unmapped code " << code << " should fall back to E_PRINT_GENERIC_FAILURE";
    }
}
}  // namespace Print
}  // namespace OHOS
