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
#include "print_callback_stub.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_resolution.h"
#include "print_sa_death_recipient.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSaDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintSaDeathRecipientTest::SetUpTestCase(void) {}

void PrintSaDeathRecipientTest::TearDownTestCase(void) {}

void PrintSaDeathRecipientTest::SetUp(void) {}

void PrintSaDeathRecipientTest::TearDown(void) {}

HWTEST_F(PrintSaDeathRecipientTest, PrintSaDeathRecipientTest_0001, TestSize.Level1)
{
    wptr<IRemoteObject> remote;
    PrintSaDeathRecipient rec;
    rec.OnRemoteDied(remote);
}
}  // namespace Print
}  // namespace OHOS
