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
#include "print_attributes.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_range.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintAttributesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    OHOS::Print::PrintAttributes GetDefaultPrintAttributes();
};

void PrintAttributesTest::SetUpTestCase(void) {}

void PrintAttributesTest::TearDownTestCase(void) {}

void PrintAttributesTest::SetUp(void) {}

void PrintAttributesTest::TearDown(void) {}

OHOS::Print::PrintAttributes PrintAttributesTest::GetDefaultPrintAttributes()
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetCopyNumber(1);
    OHOS::Print::PrintRange range;
    range.SetStartPage(1);
    printAttributes.SetPageRange(range);
    printAttributes.SetIsSequential(true);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("1");
    printAttributes.SetPageSize(pageSize);
    printAttributes.SetIsLandscape(true);
    printAttributes.SetDirectionMode(1);
    printAttributes.SetColorMode(1);
    printAttributes.SetDuplexMode(1);
    OHOS::Print::PrintMargin margin;
    margin.SetTop(1);
    printAttributes.SetMargin(margin);
    printAttributes.SetOption("1");
    return printAttributes;
}

/**
 * @tc.name: PrintAttributesTest_002
 * @tc.desc: Verify the UpdateParams function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_002, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    OHOS::Print::PrintAttributes right;
    printAttributes.UpdateParams(right);
    EXPECT_EQ(printAttributes.GetCopyNumber(), 0);
}

/**
 * @tc.name: PrintAttributesTest_003
 * @tc.desc: Verify the SetCopyNumber function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_003, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetCopyNumber(1);
    EXPECT_EQ(printAttributes.HasCopyNumber(), true);
    EXPECT_EQ(printAttributes.GetCopyNumber(), 1);
}

/**
 * @tc.name: PrintAttributesTest_004
 * @tc.desc: Verify the SetPageRange function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_004, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    OHOS::Print::PrintRange range, getRange;
    range.SetStartPage(1);
    printAttributes.SetPageRange(range);
    printAttributes.GetPageRange(getRange);
    EXPECT_EQ(printAttributes.HasPageRange(), true);
    EXPECT_EQ(getRange.GetStartPage(), 1);
}

/**
 * @tc.name: PrintAttributesTest_005
 * @tc.desc: Verify the SetIsSequential function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_005, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetIsSequential(true);
    EXPECT_EQ(printAttributes.HasSequential(), true);
    EXPECT_EQ(printAttributes.GetIsSequential(), true);
}

/**
 * @tc.name: PrintAttributesTest_006
 * @tc.desc: Verify the SetPageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_006, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("1");
    printAttributes.SetPageSize(pageSize);
    printAttributes.GetPageSize(getPageSize);
    EXPECT_EQ(printAttributes.HasPageSize(), true);
    EXPECT_EQ(getPageSize.GetId(), "1");
}

/**
 * @tc.name: PrintAttributesTest_007
 * @tc.desc: Verify the SetIsLandscape function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_007, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetIsLandscape(true);
    EXPECT_EQ(printAttributes.HasLandscape(), true);
    EXPECT_EQ(printAttributes.GetIsLandscape(), true);
}

/**
 * @tc.name: PrintAttributesTest_008
 * @tc.desc: Verify the SetDirectionMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_008, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetDirectionMode(1);
    EXPECT_EQ(printAttributes.HasDirectionMode(), true);
    EXPECT_EQ(printAttributes.GetDirectionMode(), 1);
}

/**
 * @tc.name: PrintAttributesTest_009
 * @tc.desc: Verify the SetColorMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_009, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetColorMode(1);
    EXPECT_EQ(printAttributes.HasColorMode(), true);
    EXPECT_EQ(printAttributes.GetColorMode(), 1);
}

/**
 * @tc.name: PrintAttributesTest_0010
 * @tc.desc: Verify the SetDuplexMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetDuplexMode(1);
    EXPECT_EQ(printAttributes.HasDuplexMode(), true);
    EXPECT_EQ(printAttributes.GetDuplexMode(), 1);
}

/**
 * @tc.name: PrintAttributesTest_0011
 * @tc.desc: Verify the SetMargin function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    OHOS::Print::PrintMargin margin, getMargin;
    margin.SetTop(1);
    printAttributes.SetMargin(margin);
    printAttributes.GetMargin(getMargin);
    EXPECT_EQ(printAttributes.HasMargin(), true);
    EXPECT_EQ(getMargin.GetTop(), 1);
}

/**
 * @tc.name: PrintAttributesTest_0012
 * @tc.desc: Verify the SetOption function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.SetOption("1");
    EXPECT_EQ(printAttributes.HasOption(), true);
    EXPECT_EQ(printAttributes.GetOption(), "1");
}

/**
 * @tc.name: PrintAttributesTest_0013
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes = GetDefaultPrintAttributes();
    Parcel parcel;
    EXPECT_TRUE(printAttributes.Marshalling(parcel));
    auto result = OHOS::Print::PrintAttributes::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintAttributesTest_0014
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintAttributesTest, PrintAttributesTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintAttributes printAttributes;
    printAttributes.Dump();
    Parcel parcel;
    EXPECT_TRUE(printAttributes.Marshalling(parcel));
    auto result = OHOS::Print::PrintAttributes::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}
} // namespace Print
} // namespace OHOS
