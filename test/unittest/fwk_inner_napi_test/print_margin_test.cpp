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

#include <gtest/gtest.h>
#include "print_margin.h"
#include "printer_capability.h"

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
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_001, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Dump();
    margin.~PrintMargin();
}

/**
 * @tc.name: PrintMarginTest_002
 * @tc.desc: Verify the getBottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_002, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    OHOS::Print::PrintMargin right;
    margin.Set(right);
    EXPECT_EQ((uint32_t)0, margin.GetBottom());
}

/**
 * @tc.name: PrintMarginTest_003
 * @tc.desc: Verify the reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_003, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.Reset();
    EXPECT_EQ((uint32_t)0, margin.GetBottom());
}

/**
 * @tc.name: PrintMarginTest_004
 * @tc.desc: Verify the hasTop function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_004, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    EXPECT_TRUE(margin.HasTop());
}

/**
 * @tc.name: PrintMarginTest_005
 * @tc.desc: Verify the getTop function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_005, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    EXPECT_EQ((uint32_t)6, margin.GetTop());
}

/**
 * @tc.name: PrintMarginTest_006
 * @tc.desc: Verify the hasBottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_006, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetBottom(6);
    EXPECT_TRUE(margin.HasBottom());
}

/**
 * @tc.name: PrintMarginTest_007
 * @tc.desc: Verify the getBottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_007, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetBottom(6);
    EXPECT_EQ((uint32_t)6, margin.GetBottom());
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
    margin.SetLeft(6);
    EXPECT_TRUE(margin.HasLeft());
}

/**
 * @tc.name: PrintMarginTest_009
 * @tc.desc: Verify the Reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_009, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetLeft(6);
    EXPECT_EQ((uint32_t)6, margin.GetLeft());
}

/**
 * @tc.name: PrintMarginTest_0010
 * @tc.desc: Verify the hasRight function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetRight(6);
    EXPECT_TRUE(margin.HasRight());
}

/**
 * @tc.name: PrintMarginTest_0011
 * @tc.desc: Verify the getRight function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetRight(6);
    EXPECT_EQ((uint32_t)6, margin.GetRight());
}

/**
 * @tc.name: PrintMarginTest_0012
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    EXPECT_TRUE(margin.Marshalling(parcel));
}

/**
 * @tc.name: PrintMarginTest_0013
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetBottom(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    EXPECT_TRUE(margin.Marshalling(parcel));
}

/**
 * @tc.name: PrintMarginTest_0014
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    EXPECT_TRUE(margin.Marshalling(parcel));
}

/**
 * @tc.name: PrintMarginTest_0015
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetRight(6);
    Parcel parcel;
    EXPECT_TRUE(margin.Marshalling(parcel));
}

/**
 * @tc.name: PrintMarginTest_0016
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0016, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetLeft(6);
    Parcel parcel;
    EXPECT_TRUE(margin.Marshalling(parcel));
}

/**
 * @tc.name: PrintMarginTest_0017
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    margin.Marshalling(parcel);
    auto result = OHOS::Print::PrintMargin::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintMarginTest_0018
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0018, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetBottom(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    margin.Marshalling(parcel);
    auto result = OHOS::Print::PrintMargin::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintMarginTest_0019
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0019, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetLeft(6);
    margin.SetRight(6);
    Parcel parcel;
    margin.Marshalling(parcel);
    auto result = OHOS::Print::PrintMargin::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintMarginTest_0020
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0020, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetRight(6);
    Parcel parcel;
    margin.Marshalling(parcel);
    auto result = OHOS::Print::PrintMargin::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintMarginTest_0021
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0021, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    margin.SetBottom(6);
    margin.SetLeft(6);
    Parcel parcel;
    margin.Marshalling(parcel);
    auto result = OHOS::Print::PrintMargin::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintMarginTest_0022
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    OHOS::Print::PrintMargin copyMargin(margin);
    EXPECT_EQ(copyMargin.GetTop(), margin.GetTop());
}

/**
 * @tc.name: PrintMarginTest_0023
 * @tc.desc: Verify the bottom function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMarginTest, PrintMarginTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintMargin margin;
    margin.SetTop(6);
    OHOS::Print::PrintMargin copyMargin = margin;
    EXPECT_EQ(copyMargin.GetTop(), margin.GetTop());
}
} // namespace Print
} // namespace OHOS
