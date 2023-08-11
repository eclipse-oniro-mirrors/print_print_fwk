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
#include "print_resolution.h"
#include "printer_capability.h"
#include "print_margin.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintResolutionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintResolutionTest::SetUpTestCase(void) {}

void PrintResolutionTest::TearDownTestCase(void) {}

void PrintResolutionTest::SetUp(void) {}

void PrintResolutionTest::TearDown(void) {}

/**
 * @tc.name: PrintResolutionTest_001
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_001, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    OHOS::Print::PrintResolution res;
    res = resolution;
    resolution.Dump();
}

/**
 * @tc.name: PrintResolutionTest_002
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_002, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.Reset();
    EXPECT_EQ("", resolution.GetId());
}

/**
 * @tc.name: PrintResolutionTest_003
 * @tc.desc: Verify the getId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_003, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetId("test");
    EXPECT_EQ("test", resolution.GetId());
}

/**
 * @tc.name: PrintResolutionTest_004
 * @tc.desc: Verify the getHorizontalDpi function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_004, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetHorizontalDpi(32);
    EXPECT_EQ((uint32_t)32, resolution.GetHorizontalDpi());
}

/**
 * @tc.name: PrintResolutionTest_005
 * @tc.desc: Verify the getVerticalDpi function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_005, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetVerticalDpi(32);
    EXPECT_EQ((uint32_t)32, resolution.GetVerticalDpi());
}

/**
 * @tc.name: PrintResolutionTest_006
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_006, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetId("test");
    resolution.SetHorizontalDpi(32);
    resolution.SetVerticalDpi(32);
    Parcel parcel;
    EXPECT_EQ(resolution.Marshalling(parcel), true);
}

/**
 * @tc.name: PrintResolutionTest_007
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_007, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetId("test");
    resolution.SetHorizontalDpi(32);
    resolution.SetVerticalDpi(32);
    Parcel parcel;
    resolution.Marshalling(parcel);
    auto result = OHOS::Print::PrintResolution::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintResolutionTest_008
 * @tc.desc: Verify the copy constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_008, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetId("test");
    OHOS::Print::PrintResolution copyResolution(resolution);
    EXPECT_EQ(copyResolution.GetId(), resolution.GetId());
}

/**
 * @tc.name: PrintResolutionTest_009
 * @tc.desc: Verify the assignment construction function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_009, TestSize.Level1)
{
    OHOS::Print::PrintResolution resolution;
    resolution.SetId("test");
    OHOS::Print::PrintResolution copyResolution = resolution;
    EXPECT_EQ(copyResolution.GetId(), resolution.GetId());
}
}  // namespace Print
}  // namespace OHOS
