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
#include "print_bms_death_recipient.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintBMSDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintBMSDeathRecipientTest::SetUpTestCase(void) {}

void PrintBMSDeathRecipientTest::TearDownTestCase(void) {}

void PrintBMSDeathRecipientTest::SetUp(void) {}

void PrintBMSDeathRecipientTest::TearDown(void) {}

/**
* @tc.name: PrintBMSDeathRecipientTest_0001
* @tc.desc: OnRemoteRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSDeathRecipientTest, PrintBMSDeathRecipientTest_0001, TestSize.Level1)
{
    PrintBMSDeathRecipient dr;
    wptr<IRemoteObject> testRemote = nullptr;
    dr.OnRemoteDied(testRemote);
}

}  // namespace Print
}  // namespace OHOS
