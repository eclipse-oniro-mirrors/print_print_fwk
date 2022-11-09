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

#include "printer_capability.h"
#include "napi/native_api.h"
#include <gtest/gtest.h>

using namespace testing::ext;

class PrinterCapabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrinterCapabilityTest::SetUpTestCase(void)
{
    // step 2: input testsuit setup step
}

void PrinterCapabilityTest::TearDownTestCase(void)
{
    // step 2: input testsuit teardown step
}

void PrinterCapabilityTest::SetUp(void)
{
    // step 3: input testcase setup step
}

void PrinterCapabilityTest::TearDown(void)
{
    // step 3: input testcase teardown step
}



/**
 * @tc.name: PrinterCapabilityTest_001
 * @tc.desc: Verify the colormode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_001, TestSize.Level1)
{
    OHOS::Print::PrinterCapability capability;
    capability.Reset();
    EXPECT_EQ(0, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_002
 * @tc.desc: Verify the duplexmode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_002, TestSize.Level1)
{
    OHOS::Print::PrinterCapability capability;
    capability.Reset();
    EXPECT_EQ(0, capability.GetDuplexMode());
}



