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
#include <thread>
#include <chrono>
#include "watermark_manager.h"
#include "ipc_skeleton.h"
#include "print_constant.h"
#include "print_log.h"
#include "mock_watermark_callback.h"
#include "parameter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

static const char *WATERMARK_PARAM_KEY = "persist.pc_service_file_guard_watermarkprint";

class WatermarkManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    void SetWatermarkEnabled(bool enabled);
    void ResetWatermarkManager();

private:
    static std::string originalWatermarkParam_;
};

std::string WatermarkManagerTest::originalWatermarkParam_;

void WatermarkManagerTest::SetUpTestCase(void)
{
    char value[128] = {0};
    GetParameter(WATERMARK_PARAM_KEY, "false", value, sizeof(value));
    originalWatermarkParam_ = value;
}

void WatermarkManagerTest::TearDownTestCase(void)
{
    SetParameter(WATERMARK_PARAM_KEY, originalWatermarkParam_.c_str());
}

void WatermarkManagerTest::SetUp(void)
{
    ResetWatermarkManager();
}

void WatermarkManagerTest::TearDown(void)
{
    SetWatermarkEnabled(false);
    ResetWatermarkManager();
}

void WatermarkManagerTest::SetWatermarkEnabled(bool enabled)
{
    SetParameter(WATERMARK_PARAM_KEY, enabled ? "true" : "false");
}

void WatermarkManagerTest::ResetWatermarkManager()
{
    auto &manager = WatermarkManager::GetInstance();
    manager.UnregisterCallback();
}

/**
 * @tc.name: WatermarkManagerTest_GetInstance_001
 * @tc.desc: Test GetInstance returns singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_GetInstance_001, TestSize.Level1)
{
    auto &instance1 = WatermarkManager::GetInstance();
    auto &instance2 = WatermarkManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: WatermarkManagerTest_RegisterCallback_001
 * @tc.desc: Test RegisterCallback with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_RegisterCallback_001, TestSize.Level1)
{
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = WatermarkManager::GetInstance();
    int32_t result = manager.RegisterCallback(callback);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_RegisterCallback_002
 * @tc.desc: Test RegisterCallback with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_RegisterCallback_002, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();
    int32_t result = manager.RegisterCallback(nullptr);
    EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_RegisterCallback_003
 * @tc.desc: Test RegisterCallback updates existing callback for same PID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_RegisterCallback_003, TestSize.Level1)
{
    auto callback1 = sptr<MockWatermarkCallback>::MakeSptr();
    auto callback2 = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback1, nullptr);
    EXPECT_NE(callback2, nullptr);

    auto &manager = WatermarkManager::GetInstance();

    // Register first callback
    int32_t result1 = manager.RegisterCallback(callback1);
    EXPECT_EQ(result1, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Register second callback from same PID (should update, not add)
    int32_t result2 = manager.RegisterCallback(callback2);
    EXPECT_EQ(result2, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_RegisterCallback_004
 * @tc.desc: Test DeathRecipient is properly replaced when updating callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_RegisterCallback_004, TestSize.Level1)
{
    auto callback1 = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();

    // Register first callback
    int32_t result1 = manager.RegisterCallback(callback1);
    EXPECT_EQ(result1, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Register second callback (should replace the first one)
    auto callback2 = sptr<MockWatermarkCallback>::MakeSptr();
    int32_t result2 = manager.RegisterCallback(callback2);
    EXPECT_EQ(result2, E_PRINT_NONE);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Verify: simulate process death, should clean up the second callback
    int32_t pid = IPCSkeleton::GetCallingPid();
    manager.OnCallbackDied(pid);
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_RegisterCallback_MemoryStress_001
 * @tc.desc: Test repeated callback updates don't cause memory issues
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_RegisterCallback_MemoryStress_001, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();

    // Repeatedly update callback 100 times
    for (int i = 0; i < 100; ++i) {
        auto callback = sptr<MockWatermarkCallback>::MakeSptr();
        int32_t result = manager.RegisterCallback(callback);
        EXPECT_EQ(result, E_PRINT_NONE);
    }

    // Verify that only one callback is registered
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Cleanup
    int32_t result = manager.UnregisterCallback();
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_UnregisterCallback_001
 * @tc.desc: Test UnregisterCallback with registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_UnregisterCallback_001, TestSize.Level1)
{
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    int32_t result = manager.UnregisterCallback();
    EXPECT_EQ(result, E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkManagerTest_UnregisterCallback_002
 * @tc.desc: Test UnregisterCallback without registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_UnregisterCallback_002, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());

    int32_t result = manager.UnregisterCallback();
    EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: WatermarkManagerTest_IsCallbackRegistered_001
 * @tc.desc: Test IsCallbackRegistered returns false when no callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_IsCallbackRegistered_001, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_IsCallbackRegistered_002
 * @tc.desc: Test IsCallbackRegistered returns true when callback registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_IsCallbackRegistered_002, TestSize.Level1)
{
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_IsWatermarkEnabled_001
 * @tc.desc: Test IsWatermarkEnabled returns false when disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_IsWatermarkEnabled_001, TestSize.Level1)
{
    SetWatermarkEnabled(false);
    auto &manager = WatermarkManager::GetInstance();
    EXPECT_FALSE(manager.IsWatermarkEnabled());
}

/**
 * @tc.name: WatermarkManagerTest_IsWatermarkEnabled_002
 * @tc.desc: Test IsWatermarkEnabled returns true when enabled with "true"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_IsWatermarkEnabled_002, TestSize.Level1)
{
    SetParameter(WATERMARK_PARAM_KEY, "true");
    auto &manager = WatermarkManager::GetInstance();
    EXPECT_TRUE(manager.IsWatermarkEnabled());
}

/**
 * @tc.name: WatermarkManagerTest_IsWatermarkEnabled_003
 * @tc.desc: Test IsWatermarkEnabled returns true when enabled with "1"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_IsWatermarkEnabled_003, TestSize.Level1)
{
    SetParameter(WATERMARK_PARAM_KEY, "1");
    auto &manager = WatermarkManager::GetInstance();
    EXPECT_TRUE(manager.IsWatermarkEnabled());
}

/**
 * @tc.name: WatermarkManagerTest_ProcessWatermarkForFiles_001
 * @tc.desc: Test ProcessWatermarkForFiles when watermark disabled - should skip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ProcessWatermarkForFiles_001, TestSize.Level1)
{
    SetWatermarkEnabled(false);

    auto &manager = WatermarkManager::GetInstance();
    std::vector<uint32_t> fdList = {1, 2, 3};

    int32_t result = manager.ProcessWatermarkForFiles("job_001", fdList);
    EXPECT_EQ(result, E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkManagerTest_ProcessWatermarkForFiles_002
 * @tc.desc: Test ProcessWatermarkForFiles when watermark enabled but no callback - should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ProcessWatermarkForFiles_002, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    auto &manager = WatermarkManager::GetInstance();
    EXPECT_FALSE(manager.IsCallbackRegistered());

    std::vector<uint32_t> fdList = {1, 2, 3};
    int32_t result = manager.ProcessWatermarkForFiles("job_002", fdList);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: WatermarkManagerTest_ProcessWatermarkForFiles_003
 * @tc.desc: Test ProcessWatermarkForFiles with empty file list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ProcessWatermarkForFiles_003, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);

    std::vector<uint32_t> fdList;  // Empty list
    int32_t result = manager.ProcessWatermarkForFiles("job_003", fdList);
    EXPECT_EQ(result, E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkManagerTest_ProcessWatermarkForFiles_004
 * @tc.desc: Test ProcessWatermarkForFiles when NotifyComplete reports failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ProcessWatermarkForFiles_004, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    std::string testJobId = "job_004";
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();

    std::thread notifyThread;

    // When callback is called, notify complete with failure
    EXPECT_CALL(*callback, OnCallback(testJobId, _))
        .WillOnce(Invoke([&manager, &testJobId, &notifyThread]
            (const std::string &jobId, int32_t fd) {
            notifyThread = std::thread([&manager, &testJobId]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                manager.NotifyComplete(testJobId, WATERMARK_HANDLE_FAILURE);
            });
        }));

    manager.RegisterCallback(callback);

    std::vector<uint32_t> fdList = {1};
    int32_t result = manager.ProcessWatermarkForFiles(testJobId, fdList);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);

    if (notifyThread.joinable()) {
        notifyThread.join();
    }
}

/**
 * @tc.name: WatermarkManagerTest_ProcessWatermarkForFiles_005
 * @tc.desc: Test ProcessWatermarkForFiles success with notify complete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ProcessWatermarkForFiles_005, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    std::string testJobId = "job_005";
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();

    auto &manager = WatermarkManager::GetInstance();

    std::thread notifyThread;

    // When callback is called, start a thread to notify complete
    EXPECT_CALL(*callback, OnCallback(testJobId, _))
        .WillOnce(Invoke([&manager, &testJobId, &notifyThread]
            (const std::string &jobId, int32_t fd) {
            // Simulate MDM app processing and notifying complete in another thread
            notifyThread = std::thread([&manager, &testJobId]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                manager.NotifyComplete(testJobId, 0);
            });
        }));

    manager.RegisterCallback(callback);

    std::vector<uint32_t> fdList = {1};
    int32_t result = manager.ProcessWatermarkForFiles(testJobId, fdList);
    EXPECT_EQ(result, E_PRINT_NONE);

    // Wait for the notify thread to complete
    if (notifyThread.joinable()) {
        notifyThread.join();
    }
}

/**
 * @tc.name: WatermarkManagerTest_ConcurrentRegister_001
 * @tc.desc: Test concurrent callback registration - thread safety
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_ConcurrentRegister_001, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();

    std::vector<std::thread> threads;
    const int threadCount = 5;

    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&manager, i]() {
            auto callback = sptr<MockWatermarkCallback>::MakeSptr();
            manager.RegisterCallback(callback);
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    // Should not crash, and should have some callbacks registered
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_NotifyComplete_001
 * @tc.desc: Test NotifyComplete with non-existent job
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_NotifyComplete_001, TestSize.Level1)
{
    auto &manager = WatermarkManager::GetInstance();
    int32_t result = manager.NotifyComplete("non_existent_job", 0);
    EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: WatermarkManagerTest_NotifyComplete_002
 * @tc.desc: Test NotifyComplete with failure result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_NotifyComplete_002, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    std::string testJobId = "job_notify_002";
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();

    auto &manager = WatermarkManager::GetInstance();

    std::thread notifyThread;

    // When callback is called, notify complete with failure
    EXPECT_CALL(*callback, OnCallback(testJobId, _))
        .WillOnce(Invoke([&manager, &testJobId, &notifyThread]
            (const std::string &jobId, int32_t fd) {
            notifyThread = std::thread([&manager, &testJobId]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                manager.NotifyComplete(testJobId, -1);  // Failure
            });
        }));

    manager.RegisterCallback(callback);

    std::vector<uint32_t> fdList = {1};
    int32_t result = manager.ProcessWatermarkForFiles(testJobId, fdList);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);

    if (notifyThread.joinable()) {
        notifyThread.join();
    }
}

/**
 * @tc.name: WatermarkManagerTest_EmptyJobId_001
 * @tc.desc: Test ProcessWatermarkForFiles with empty jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_EmptyJobId_001, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);

    std::thread notifyThread;

    EXPECT_CALL(*callback, OnCallback("", _))
        .WillOnce(Invoke([&manager, &notifyThread](const std::string &jobId, int32_t fd) {
            notifyThread = std::thread([&manager]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                manager.NotifyComplete("", 0);
            });
        }));

    std::vector<uint32_t> fdList = {1};
    int32_t result = manager.ProcessWatermarkForFiles("", fdList);
    EXPECT_EQ(result, E_PRINT_NONE);

    if (notifyThread.joinable()) {
        notifyThread.join();
    }
}

/**
 * @tc.name: WatermarkManagerTest_LongJobId_001
 * @tc.desc: Test ProcessWatermarkForFiles with very long jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_LongJobId_001, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    std::string longJobId(1000, 'x');  // 1000 character jobId
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);

    std::thread notifyThread;

    EXPECT_CALL(*callback, OnCallback(longJobId, _))
        .WillOnce(Invoke([&manager, &longJobId, &notifyThread]
            (const std::string &jobId, int32_t fd) {
            notifyThread = std::thread([&manager, longJobId]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                manager.NotifyComplete(longJobId, 0);
            });
        }));

    std::vector<uint32_t> fdList = {1};
    int32_t result = manager.ProcessWatermarkForFiles(longJobId, fdList);
    EXPECT_EQ(result, E_PRINT_NONE);

    if (notifyThread.joinable()) {
        notifyThread.join();
    }
}

/**
 * @tc.name: WatermarkManagerTest_MultipleFiles_001
 * @tc.desc: Test ProcessWatermarkForFiles with multiple files
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_MultipleFiles_001, TestSize.Level1)
{
    SetWatermarkEnabled(true);

    std::string testJobId = "job_multi_files";
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);

    int callCount = 0;
    std::vector<std::thread> notifyThreads;

    EXPECT_CALL(*callback, OnCallback(testJobId, _))
        .Times(3)
        .WillRepeatedly(Invoke([&manager, &testJobId, &callCount, &notifyThreads]
            (const std::string &jobId, int32_t fd) {
            callCount++;
            notifyThreads.emplace_back([&manager, &testJobId]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                manager.NotifyComplete(testJobId, 0);
            });
        }));

    std::vector<uint32_t> fdList = {1, 2, 3};
    int32_t result = manager.ProcessWatermarkForFiles(testJobId, fdList);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_EQ(callCount, 3);

    for (auto &thread : notifyThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

/**
 * @tc.name: WatermarkManagerTest_OnCallbackDied_001
 * @tc.desc: Test OnCallbackDied removes callback for dead process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_OnCallbackDied_001, TestSize.Level1)
{
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Simulate process death using current test process PID
    int32_t pid = IPCSkeleton::GetCallingPid();
    manager.OnCallbackDied(pid);

    EXPECT_FALSE(manager.IsCallbackRegistered());
}

/**
 * @tc.name: WatermarkManagerTest_OnCallbackDied_002
 * @tc.desc: Test OnCallbackDied with non-existent PID does nothing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkManagerTest, WatermarkManagerTest_OnCallbackDied_002, TestSize.Level1)
{
    auto callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);

    auto &manager = WatermarkManager::GetInstance();
    manager.RegisterCallback(callback);
    EXPECT_TRUE(manager.IsCallbackRegistered());

    // Try to remove non-existent PID - should not affect registered callback
    manager.OnCallbackDied(99999);

    // Callback should still be registered
    EXPECT_TRUE(manager.IsCallbackRegistered());
}

}  // namespace Print
}  // namespace OHOS