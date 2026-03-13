/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <mutex>
#include "kia_interceptor_manager.h"
#include "mock_kia_interceptor_callback.h"
#include "print_constant.h"
#include "ipc_skeleton.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class KiaInterceptorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    void ResetKiaInterceptorManager();
};

void KiaInterceptorManagerTest::SetUpTestCase(void)
{
}

void KiaInterceptorManagerTest::TearDownTestCase(void)
{
}

void KiaInterceptorManagerTest::SetUp(void)
{
    ResetKiaInterceptorManager();
}

void KiaInterceptorManagerTest::TearDown(void)
{
    ResetKiaInterceptorManager();
}

void KiaInterceptorManagerTest::ResetKiaInterceptorManager()
{
    auto &manager = KiaInterceptorManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager.mutex_);
    manager.callback_ = nullptr;
    manager.deathRecipient_ = nullptr;
    manager.jobIdToAppIdMap_.clear();
}

/**
 * @tc.name: KiaInterceptorManagerTest_GetInstance_001
 * @tc.desc: Test GetInstance returns singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_GetInstance_001, TestSize.Level1)
{
    auto &instance1 = KiaInterceptorManager::GetInstance();
    auto &instance2 = KiaInterceptorManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: KiaInterceptorManagerTest_RegisterCallback_001
 * @tc.desc: Test RegisterCallback with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_RegisterCallback_001, TestSize.Level1)
{
    auto callback = sptr<MockKiaInterceptorCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = KiaInterceptorManager::GetInstance();
    int32_t result = manager.RegisterCallback(callback);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: KiaInterceptorManagerTest_RegisterCallback_002
 * @tc.desc: Test RegisterCallback with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_RegisterCallback_002, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();
    int32_t result = manager.RegisterCallback(nullptr);
    EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: Test RegisterCallback with already registered callback
 * @tc.desc: Test RegisterCallback with already registered callback (replace)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_RegisterCallback_003, TestSize.Level1)
{
    auto callback1 = sptr<MockKiaInterceptorCallback>::MakeSptr();
    auto callback2 = sptr<MockKiaInterceptorCallback>::MakeSptr();
    EXPECT_NE(callback1, nullptr);
    EXPECT_NE(callback2, nullptr);

    auto &manager = KiaInterceptorManager::GetInstance();

    int32_t result1 = manager.RegisterCallback(callback1);
    EXPECT_EQ(result1, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    int32_t result2 = manager.RegisterCallback(callback2);
    EXPECT_EQ(result2, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: KiaInterceptorManagerTest_IsCallbackRegistered_001
 * @tc.desc: Test IsCallbackRegistered returns false when no callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_IsCallbackRegistered_001, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: KiaInterceptorManagerTest_IsCallbackRegistered_002
 * @tc.desc: Test IsCallbackRegistered returns true when callback registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_IsCallbackRegistered_002, TestSize.Level1)
{
    auto callback = sptr<MockKiaInterceptorCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = KiaInterceptorManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: KiaInterceptorManagerTest_UnregisterCallback_001
 * @tc.desc: Test UnregisterCallback with registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_UnregisterCallback_001, TestSize.Level1)
{
    auto callback = sptr<MockKiaInterceptorCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = KiaInterceptorManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    int32_t result = manager.UnregisterCallback();
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: KiaInterceptorManagerTest_UnregisterCallback_002
 * @tc.desc: Test UnregisterCallback with no callback registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_UnregisterCallback_002, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());

    int32_t result = manager.UnregisterCallback();
    EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: KiaInterceptorManagerTest_CheckPrintJobNeedReject_001
 * @tc.desc: Test CheckPrintJobNeedReject when no callback registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_CheckPrintJobNeedReject_001, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());

    std::string jobId = "test_job_001";
    bool shouldReject = manager.CheckPrintJobNeedReject(jobId);
    EXPECT_FALSE(shouldReject);
}

/**
 * @tc.name: KiaInterceptorManagerTest_CheckPrintJobNeedReject_002
 * @tc.desc: Test CheckPrintJobNeedReject with callback returning true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_CheckPrintJobNeedReject_002, TestSize.Level1)
{
    auto callback = sptr<MockKiaInterceptorCallback>::MakeSptr();
    auto &manager = KiaInterceptorManager::GetInstance();
    EXPECT_NE(callback, nullptr);

    std::string jobId = "123";
    int32_t pid = IPCSkeleton::GetCallingPid();
    std::string testCallerAppId = "";

    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(pid, testCallerAppId))
        .WillRepeatedly(Return(true));

    manager.RegisterCallback(callback);

    bool shouldReject = manager.CheckPrintJobNeedReject(jobId);
    EXPECT_TRUE(shouldReject);
}

/**
 * @tc.name: KiaInterceptorManagerTest_RegisterCallerAppId_001
 * @tc.desc: Test RegisterCallerAppId with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_RegisterCallerAppId_001, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();

    std::string jobId = "test_job_001";
    std::string callerBundleName = "com.example.test";
    int32_t userId = 100;
    int32_t result = manager.RegisterCallerAppId(jobId, callerBundleName, userId);
    EXPECT_EQ(result, E_PRINT_NONE);
}

/**
 * @tc.name: KiaInterceptorManagerTest_RemoveCallerAppId_001
 * @tc.desc: Test RemoveCallerAppId with existing jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_RemoveCallerAppId_001, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();

    std::string jobId = "test_job_001";
    std::string callerBundleName = "com.example.test";
    int32_t userId = 100;
    manager.RegisterCallerAppId(jobId, callerBundleName, userId);

    manager.RemoveCallerAppId(jobId);

    std::string retrievedAppId = manager.GetCallerAppId(jobId);
    EXPECT_EQ(retrievedAppId, "");
}

/**
 * @tc.name: KiaInterceptorManagerTest_GetCallerAppId_001
 * @tc.desc: Test GetCallerAppId with non-existing jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorManagerTest, KiaInterceptorManagerTest_GetCallerAppId_001, TestSize.Level1)
{
    auto &manager = KiaInterceptorManager::GetInstance();

    std::string jobId = "test_job";
    std::string retrievedAppId = manager.GetCallerAppId(jobId);
    EXPECT_EQ(retrievedAppId, "");
}

}  // namespace Print
}  // namespace OHOS
