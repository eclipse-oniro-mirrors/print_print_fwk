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
#include "print_preview_attribute.h"
#include "printer_capability.h"
#include "print_margin.h"
#include "print_range.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintPreviewAttributeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintPreviewAttributeTest::SetUpTestCase(void) {}

void PrintPreviewAttributeTest::TearDownTestCase(void) {}

void PrintPreviewAttributeTest::SetUp(void) {}

void PrintPreviewAttributeTest::TearDown(void) {}

/**
 * @tc.name: PrintPreviewAttributeTest_0001
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.Dump();
}

/**
 * @tc.name: PrintPreviewAttributeTest_0002
 * @tc.desc: Verify the hasResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.Reset();
    EXPECT_FALSE(attribute.HasResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0003
 * @tc.desc: Verify the getResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(6);
    EXPECT_EQ((uint32_t)6, attribute.GetResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0004
 * @tc.desc: Verify the hasStartPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetResult(6);
    attribute.SetPreviewRange(printRange);
    PrintRange previewRange;
    attribute.GetPreviewRange(previewRange);
    EXPECT_FALSE(previewRange.HasStartPage());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0005
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    Parcel parcel;
    EXPECT_TRUE(attribute.Marshalling(parcel));
}

/**
 * @tc.name: PrintPreviewAttributeTest_0006
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    attribute.SetResult(6);
    Parcel parcel;
    EXPECT_TRUE(attribute.Marshalling(parcel));
}

/**
 * @tc.name: PrintPreviewAttributeTest_0007
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    Parcel parcel;
    attribute.Marshalling(parcel);
    auto result = OHOS::Print::PrintPreviewAttribute::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}
} // namespace Print
} // namespace OHOS