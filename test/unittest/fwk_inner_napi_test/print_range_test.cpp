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
#include "napi/native_api.h"
#include "print_range.h"

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
 * @tc.name: PrintRangeTest_001
 * @tc.desc: Verify the StartPag function.
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_001, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    EXPECT_EQ(0, range.GetStartPage());
}

/**
 * @tc.name: PrintRangeTest_002
 * @tc.desc: Verify the EndPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintRangeTest, PrintRangeTest_002, TestSize.Level1)
{
    OHOS::Print::PrintRange range;
    EXPECT_EQ(0, range.GetEndPage());
}
} // namespace Print
} // namespace OHOS