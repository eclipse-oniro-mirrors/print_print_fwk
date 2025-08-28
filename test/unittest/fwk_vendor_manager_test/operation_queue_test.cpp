/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define private public
#include "operation_queue.h"
#undef private
#include "print_constant.h"
#include "print_log.h"

using namespace testing;
using namespace testing::ext;

namespace {
const int WAIT_TIME_MS = 100;
const size_t OPERATOIN_QUEUE_COUNT_TEST = 2;
}  // namespace

namespace OHOS {
namespace Print {
class OperatonQueueTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OperatonQueueTest::SetUpTestCase(void)
{}

void OperatonQueueTest::TearDownTestCase(void)
{}

void OperatonQueueTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("OperatonQueueTest_%{public}d", ++testNo);
}

void OperatonQueueTest::TearDown(void)
{}

HWTEST_F(OperatonQueueTest, OperatonQueueTest_0001, TestSize.Level1)
{
    PRINT_HILOGI("OperatonQueueTest_0001 enter");
    OperationQueue operationQueue;
    operationQueue.Stop();
    operationQueue.Run();
    EXPECT_TRUE(operationQueue.isRunning);
    operationQueue.Run();
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    operationQueue.Stop();
    EXPECT_FALSE(operationQueue.isRunning);
    PRINT_HILOGI("OperatonQueueTest_0001 quit");
}

HWTEST_F(OperatonQueueTest, OperatonQueueTest_0002, TestSize.Level2)
{
    PRINT_HILOGI("OperatonQueueTest_0002 enter");
    std::function<void()> op = []() {
        ThreadSyncWait syncWait;
        PRINT_HILOGI("wait begin");
        syncWait.Wait(WAIT_TIME_MS);
        PRINT_HILOGI("wait end");
    };
    OperationQueue operationQueue;
    EXPECT_EQ(operationQueue.Push(op), false);
    operationQueue.maxCount = OPERATOIN_QUEUE_COUNT_TEST;
    operationQueue.Run();
    EXPECT_TRUE(operationQueue.isRunning);
    EXPECT_EQ(operationQueue.Push(op), true);
    operationQueue.Push(op);
    operationQueue.Push(op);
    ThreadSyncWait syncWait;
    syncWait.Wait(WAIT_TIME_MS);
    PRINT_HILOGI("stop queue");
    operationQueue.Stop();
    EXPECT_FALSE(operationQueue.isRunning);
    PRINT_HILOGI("OperatonQueueTest_0002 quit");
}

HWTEST_F(OperatonQueueTest, OperatonQueueTest_0003, TestSize.Level2)
{
    ThreadSyncWait syncWait;
    OperationQueue operationQueue;
    operationQueue.Run();
    EXPECT_TRUE(operationQueue.isRunning);
    syncWait.Wait(WAIT_TIME_MS);
    operationQueue.Stop();
    EXPECT_FALSE(operationQueue.isRunning);
    operationQueue.Stop();
    syncWait.Wait(WAIT_TIME_MS);
    operationQueue.Run();
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_TRUE(operationQueue.isRunning);
    operationQueue.Run();
    operationQueue.Stop();
    syncWait.Wait(WAIT_TIME_MS);
    EXPECT_FALSE(operationQueue.isRunning);
}
}  // namespace Print
}  // namespace OHOS