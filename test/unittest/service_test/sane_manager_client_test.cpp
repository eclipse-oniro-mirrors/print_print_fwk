/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <thread>
#define private public
#include "sane_manager_client.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Scan {

class SaneManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SaneManagerClientTest::SetUpTestCase(void) {}

void SaneManagerClientTest::TearDownTestCase(void) {}

void SaneManagerClientTest::SetUp(void)
{
    static int32_t testNo = 0;
    SCAN_HILOGI("SaneManagerClientTest_%{public}d", ++testNo);
}

void SaneManagerClientTest::TearDown(void) {}

/**
 * @tc.name: SaneManagerClientTest_LoadSystemAbilityFail_0001
 * @tc.desc: LoadSystemAbilityFail wakes a wait_for-blocked thread promptly (no 15s block).
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
// ponytail: full 15s-deadlock reproduction needs SystemAbilityManager mock (LoadSystemAbility
// returning ERR_OK to reach the wait). Out of scope here. This test directly verifies the fix's
// core contract: Fail marks isLoadFailed_ + notifies, so a wait_for waiter is released promptly.
HWTEST_F(SaneManagerClientTest, SaneManagerClientTest_LoadSystemAbilityFail_0001, TestSize.Level1)
{
    auto client = SaneManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);
    {
        std::unique_lock<std::shared_mutex> lk(client->serviceLock_);
        client->isLoadFailed_ = false;
        client->proxy_ = nullptr;
    }
    std::atomic<bool> woke{false};
    std::thread waiter([&]() {
        std::unique_lock<std::shared_mutex> lk(client->serviceLock_);
        client->syncCon_.wait_for(lk, std::chrono::seconds(5),
            [client]() { return client->proxy_ != nullptr || client->isLoadFailed_; });
        woke.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto t0 = std::chrono::steady_clock::now();
    client->LoadSystemAbilityFail();
    waiter.join();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    EXPECT_TRUE(woke.load());
    EXPECT_LT(elapsedMs, 3000);
    EXPECT_TRUE(client->isLoadFailed_);
    EXPECT_EQ(client->proxy_, nullptr);
}

/**
 * @tc.name: SaneManagerClientTest_LoadSystemAbilitysuccess_0002
 * @tc.desc: LoadSystemAbilitysuccess with null remoteObject must not notify (proxy stays null).
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SaneManagerClientTest, SaneManagerClientTest_LoadSystemAbilitysuccess_0002, TestSize.Level1)
{
    auto client = SaneManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);
    {
        std::unique_lock<std::shared_mutex> lk(client->serviceLock_);
        client->proxy_ = nullptr;
        client->isLoadFailed_ = true;
    }
    const sptr<IRemoteObject> nullObj;
    client->LoadSystemAbilitysuccess(nullObj);
    EXPECT_EQ(client->proxy_, nullptr);
}
}  // namespace Scan
}  // namespace OHOS
