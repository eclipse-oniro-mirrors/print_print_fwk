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
#include "print_page_size.h"
#include "printer_capability.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintPageSizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintPageSizeTest::SetUpTestCase(void) {}

void PrintPageSizeTest::TearDownTestCase(void) {}

void PrintPageSizeTest::SetUp(void) {}

void PrintPageSizeTest::TearDown(void) {}

/**
 * @tc.name: PrintPageSizeTest_0001
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    OHOS::Print::PrintPageSize::BuildPageSizeMap();
    printpageSize.Dump();
}

/**
 * @tc.name: PrintPageSizeTest_0002
 * @tc.desc: Verify the getPageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0002, TestSize.Level1)
{
    auto pageSize = OHOS::Print::PrintPageSize::GetPageSize(ISO_A3);
    EXPECT_EQ((uint32_t)0, pageSize.GetWidth());
}

/**
 * @tc.name: PrintPageSizeTest_0003
 * @tc.desc: Verify the reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.Reset();
    EXPECT_EQ("", printpageSize.GetId());
}

/**
 * @tc.name: PrintPageSizeTest_0004
 * @tc.desc: Verify the getId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetId("Test");
    EXPECT_EQ("Test", printpageSize.GetId());
}

/**
 * @tc.name: PrintPageSizeTest_0005
 * @tc.desc: Verify the getName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetName("Test");
    EXPECT_EQ("Test", printpageSize.GetName());
}

/**
 * @tc.name: PrintPageSizeTest_0006
 * @tc.desc: Verify the getWidth function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetWidth(6);
    EXPECT_EQ((uint32_t)6, printpageSize.GetWidth());
}

/**
 * @tc.name: PrintPageSizeTest_0007
 * @tc.desc: Verify the getHeight function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetHeight(6);
    EXPECT_EQ((uint32_t)6, printpageSize.GetHeight());
}

/**
 * @tc.name: PrintPageSizeTest_0008
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetId("id-1234");
    printpageSize.SetName("Test");
    printpageSize.SetWidth(6);
    printpageSize.SetHeight(6);
    Parcel parcel;
    EXPECT_EQ(printpageSize.Marshalling(parcel), true);
}

/**
 * @tc.name: PrintPageSizeTest_0009
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetId("id-1234");
    Parcel parcel;
    printpageSize.Marshalling(parcel);
    auto result = OHOS::Print::PrintPageSize::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintPageSizeTest_0010
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize("Test", "Test", 6, 6);
    EXPECT_EQ((uint32_t)6, printpageSize.GetWidth());
}

/**
 * @tc.name: PrintPageSizeTest_0011
 * @tc.desc: Verify the copy constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetWidth(6);
    OHOS::Print::PrintPageSize copyPageSize(printpageSize);
    EXPECT_EQ(copyPageSize.GetWidth(), printpageSize.GetWidth());
}

/**
 * @tc.name: PrintPageSizeTest_0012
 * @tc.desc: Verify the copy constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    printpageSize.SetWidth(6);
    OHOS::Print::PrintPageSize copyPageSize = printpageSize;
    EXPECT_EQ(copyPageSize.GetWidth(), printpageSize.GetWidth());
}
} // namespace Print
} // namespace OHOS