/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "napi/native_api.h"
#include "print_margin.h"
#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintMarginTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintMarginTest::SetUpTestCase(void) {}

void PrintMarginTest::TearDownTestCase(void) {}

void PrintMarginTest::SetUp(void) {}

void PrintMarginTest::TearDown(void) {}

/**
 * @tc.name: PrintMarginTest_001
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_001, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    EXPECT_EQ(0, margin.GetTop());
}

/**
 * @tc.name: PrintMarginTest_002
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_002, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    EXPECT_EQ(0, margin.GetBottom());
}

/**
 * @tc.name: PrintMarginTest_003
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_003, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    EXPECT_EQ(0, margin.GetLeft());
}

/**
 * @tc.name: PrintMarginTest_004
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_004, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    EXPECT_EQ(0, margin.GetRight());
}

/**
 * @tc.name: PrintMarginTest_005
 * @tc.desc: Verify the Reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_005, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Reset();
    EXPECT_EQ(0, margin.GetTop());
}

/**
 * @tc.name: PrintMarginTest_006
 * @tc.desc: Verify the Reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_006, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Reset();
    EXPECT_EQ(0, margin.GetBottom());
}

/**
 * @tc.name: PrintMarginTest_007
 * @tc.desc: Verify the Reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_007, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Reset();
    EXPECT_EQ(0, margin.GetLeft());
}

/**
 * @tc.name: PrintMarginTest_008
 * @tc.desc: Verify the Reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_008, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Reset();
    EXPECT_EQ(0, margin.GetRight());
}
} // namespace Print
} // namespace OHOS