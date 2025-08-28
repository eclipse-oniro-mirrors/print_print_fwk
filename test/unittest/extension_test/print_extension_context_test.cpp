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
#include "print_extension_context.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class PrintExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionContextTest::SetUpTestCase(void)
{}

void PrintExtensionContextTest::TearDownTestCase(void)
{}

void PrintExtensionContextTest::SetUp(void)
{}

void PrintExtensionContextTest::TearDown(void)
{}

/**
 * @tc.name: PrintExtensionContextTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0001, TestSize.Level0)
{
    AAFwk::Want want;
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.StartAbility(want), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0002, TestSize.Level0)
{
    AAFwk::Want want;
    AAFwk::StartOptions startOptions;
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.StartAbility(want, startOptions), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0003, TestSize.Level0)
{
    AAFwk::Want want;
    int accountId = 0;
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.StartAbilityWithAccount(want, accountId), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0004, TestSize.Level0)
{
    AAFwk::Want want;
    int accountId = 0;
    AAFwk::StartOptions startOptions;
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.StartAbilityWithAccount(want, accountId, startOptions), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0005, TestSize.Level0)
{
    AAFwk::Want want;
    sptr<AbilityConnectCallback> connectCallback;
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.DisconnectAbility(want, connectCallback), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0006, TestSize.Level0)
{
    PrintExtensionContext printExtensionContext;
    EXPECT_NE(printExtensionContext.TerminateAbility(), ERR_OK);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0007, TestSize.Level0)
{
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.GetAbilityInfoType(), AppExecFwk::AbilityType::UNKNOWN);
}
}  // namespace AbilityRuntime
}  // namespace OHOS