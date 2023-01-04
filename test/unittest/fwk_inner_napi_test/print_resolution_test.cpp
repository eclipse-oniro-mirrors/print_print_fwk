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
#include "print_resolution.h"
#include <gtest/gtest.h>

using namespace testing::ext;

class PrintResolutionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintResolutionTest::SetUpTestCase(void) {
}

void PrintResolutionTest::TearDownTestCase(void) {
}

void PrintResolutionTest::SetUp(void) {
}

void PrintResolutionTest::TearDown(void) {
}

/**
 * @tc.name: PrintResolutionTest_001
 * @tc.desc: Verify the id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_001, TestSize.Level1) {
    OHOS::Print::PrintResolution resolution;
    resolution.Reset();
    EXPECT_EQ("", resolution.GetId());
}

/**
 * @tc.name: PrintResolutionTest_002
 * @tc.desc: Verify the dpi function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_002, TestSize.Level1) {
    OHOS::Print::PrintResolution resolution;
    resolution.Reset();
    EXPECT_EQ(0, resolution.GetHorizontalDpi());
}

/**
 * @tc.name: PrintResolutionTest_003
 * @tc.desc: Verify the dpi function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintResolutionTest, PrintResolutionTest_003, TestSize.Level1) {
    OHOS::Print::PrintResolution resolution;
    resolution.Reset();
    EXPECT_EQ(0, resolution.GetVerticalDpi());
}