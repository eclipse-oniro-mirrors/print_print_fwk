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
#include "print_sync_load_callback.h"
#include "iservice_registry.h"
#include "isystem_ability_load_callback.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSyncLoadCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintSyncLoadCallbackTest::SetUpTestCase(void) {}

void PrintSyncLoadCallbackTest::TearDownTestCase(void) {}

void PrintSyncLoadCallbackTest::SetUp(void) {}

void PrintSyncLoadCallbackTest::TearDown(void) {}

/**
 * @tc.name: PrintSyncLoadCallbackTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSyncLoadCallbackTest, PrintSyncLoadCallbackTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintSyncLoadCallback printSyncLoadCallback;
    int32_t systemAbilityId = 0;
    const sptr<IRemoteObject> remoteObject;
    printSyncLoadCallback.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    printSyncLoadCallback.OnLoadSystemAbilityFail(systemAbilityId);
}
} // namespace Print
} // namespace OHOS