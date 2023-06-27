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
#include "print_range.h"
#include "printer_capability.h"
#include "print_margin.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintRangeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintRangeTest::SetUpTestCase(void) {}

void PrintRangeTest::TearDownTestCase(void) {}

void PrintRangeTest::SetUp(void) {}

void PrintRangeTest::TearDown(void) {}

/**
 * @tc.name: PrintRangeTest_0001
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.Dump();
}

/**
 * @tc.name: PrintRangeTest_0002
 * @tc.desc: Verify the reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.Reset();
    EXPECT_FALSE(range.HasStartPage());
}

/**
 * @tc.name: PrintRangeTest_0003
 * @tc.desc: Verify the getStartPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetStartPage(6);
    EXPECT_EQ((uint32_t)6, range.GetStartPage());
}

/**
 * @tc.name: PrintRangeTest_0004
 * @tc.desc: Verify the hasEndPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetEndPage(6);
    EXPECT_TRUE(range.HasEndPage());
}

/**
 * @tc.name: PrintRangeTest_0005
 * @tc.desc: Verify the getEndPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetEndPage(6);
    EXPECT_EQ((uint32_t)6, range.GetEndPage());
}

/**
 * @tc.name: PrintRangeTest_0006
 * @tc.desc: Verify the hasPages function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    EXPECT_TRUE(range.HasPages());
}

/**
 * @tc.name: PrintRangeTest_0007
 * @tc.desc: Verify the getPages function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    std::vector<uint32_t> getPages;
    range.GetPages(getPages);
    EXPECT_EQ((uint32_t)1, getPages[0]);
}

/**
 * @tc.name: PrintRangeTest_0008
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    range.SetEndPage(6);
    range.SetStartPage(6);
    Parcel parcel;
    EXPECT_TRUE(range.Marshalling(parcel));
}

/**
 * @tc.name: PrintRangeTest_0009
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    range.SetEndPage(6);
    range.SetStartPage(6);
    Parcel parcel;
    EXPECT_TRUE(range.Marshalling(parcel));
}

/**
 * @tc.name: PrintRangeTest_0010
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    range.SetEndPage(6);
    Parcel parcel;
    EXPECT_TRUE(range.Marshalling(parcel));
}

/**
 * @tc.name: PrintRangeTest_0011
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    range.SetStartPage(6);
    Parcel parcel;
    EXPECT_TRUE(range.Marshalling(parcel));
}

/**
 * @tc.name: PrintRangeTest_0012
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetEndPage(6);
    range.SetStartPage(6);
    Parcel parcel;
    EXPECT_TRUE(range.Marshalling(parcel));
}

/**
 * @tc.name: PrintRangeTest_0013
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    range.SetEndPage(6);
    range.SetStartPage(6);
    Parcel parcel;
    range.Marshalling(parcel);
    auto result = OHOS::Print::PrintRange::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintRangeTest_0014
 * @tc.desc: Verify the copy constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetEndPage(6);
    OHOS::Print::PrintRange copyRange(range);
    EXPECT_EQ(copyRange.GetEndPage(), range.GetEndPage());
}

/**
 * @tc.name: PrintRangeTest_0015
 * @tc.desc: Verify the assignment construction function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    range.SetEndPage(6);
    OHOS::Print::PrintRange copyRange = range;
    EXPECT_EQ(copyRange.GetEndPage(), range.GetEndPage());
}
} // namespace Print
} // namespace OHOS