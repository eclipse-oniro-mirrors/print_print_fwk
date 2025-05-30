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

namespace OHOS {
namespace Scan {
class ScanManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<ScanManagerClient> smgPtr;
};

void ScanManagerClientTest::SetUpTestCase(void) {}

void ScanManagerClientTest::TearDownTestCase(void) {}

void ScanManagerClientTest::SetUp(void)
{
    smgPtr = std::make_shared<ScanManagerClient>();
    EXPECT_NE(smgPtr, nullptr);
}

void ScanManagerClientTest::TearDown(void) {}

/**
 * @tc.name: ScanManagerClientTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_0001_NeedRename, TestSize.Level1)
{
    int32_t scanVersion = 0;
    auto status = smgPtr->InitScan(scanVersion);
    EXPECT_NE(scanVersion, 0);
    EXPECT_EQ(status, 0);
}

/**
 * @tc.name: ScanManagerClientTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_0002_NeedRename, TestSize.Level1)
{
    int32_t scanVersion = 0;
    auto status = smgPtr->ExitScan(scanVersion);
    EXPECT_NE(scanVersion, 0);
    EXPECT_EQ(status, 0);
}

} // namespace Scan
} // namespace OHOS