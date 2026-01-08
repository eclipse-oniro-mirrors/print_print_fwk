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
#include <string>
#include <fstream>
#include <map>
#define private public
#include "print_caller_app_monitor.h"
#undef private
#include "print_log.h"
#include "print_constant.h"
#include "mock_print_caller_app_monitor.h"

#include "ipc_skeleton.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintCallerAppMonitorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    PrintCallerAppMonitor& printCallerAppMonitor = PrintCallerAppMonitor::GetInstance();
};

void PrintCallerAppMonitorTest::SetUpTestCase(void)
{}

void PrintCallerAppMonitorTest::TearDownTestCase(void)
{}

void PrintCallerAppMonitorTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCallerAppMonitorTest_%{public}d", ++testNo);
}

void PrintCallerAppMonitorTest::TearDown(void)
{}

HWTEST_F(PrintCallerAppMonitorTest, IsProcessForeground_GetCallingPid_returnFalse, TestSize.Level1)
{
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    EXPECT_EQ(printCallerAppMonitor.IsProcessForeground(callerPid), false);
}

HWTEST_F(PrintCallerAppMonitorTest, IncrementPrintCounter_jobIdEmpty_countIncrement, TestSize.Level1)
{
    int count = printCallerAppMonitor.counter_.Value();
    std::string jobId = "";
    printCallerAppMonitor.IncrementPrintCounter(jobId);
    EXPECT_EQ(printCallerAppMonitor.counter_.Value(), count + 1);
    printCallerAppMonitor.DecrementPrintCounter(jobId);
    EXPECT_EQ(printCallerAppMonitor.counter_.Value(), count);
}

HWTEST_F(PrintCallerAppMonitorTest, IncrementPrintCounter_jobIdNotEmpty_countIncrement, TestSize.Level1)
{
    int count = printCallerAppMonitor.counter_.Value();
    std::string jobId = "testJobId";
    printCallerAppMonitor.IncrementPrintCounter(jobId);
    EXPECT_EQ(printCallerAppMonitor.counter_.Value(), count + 1);
    printCallerAppMonitor.DecrementPrintCounter(jobId);
    EXPECT_EQ(printCallerAppMonitor.counter_.Value(), count);
}

HWTEST_F(PrintCallerAppMonitorTest, RemovePrintJobFromMap_jobIdEmpty_cannotErase, TestSize.Level1)
{
    uint32_t size = printCallerAppMonitor.printJobMap_.size();
    std::string jobId1 = "testJobId1";
    std::string jobId2 = "";
    printCallerAppMonitor.printJobMap_[jobId1] = true;
    printCallerAppMonitor.RemovePrintJobFromMap(jobId2);
    EXPECT_EQ(printCallerAppMonitor.printJobMap_.size(), size + 1);
}

HWTEST_F(PrintCallerAppMonitorTest, RemovePrintJobFromMap_jobIdNotInMap_cannotErase, TestSize.Level1)
{
    uint32_t size = printCallerAppMonitor.printJobMap_.size();
    std::string jobId1 = "testJobId1";
    std::string jobId2 = "testJobId2";
    printCallerAppMonitor.printJobMap_[jobId1] = true;
    printCallerAppMonitor.RemovePrintJobFromMap(jobId2);
    EXPECT_EQ(printCallerAppMonitor.printJobMap_.size(), size);
}

HWTEST_F(PrintCallerAppMonitorTest, RemovePrintJobFromMap_jobIdInMap_eraseSuccess, TestSize.Level1)
{
    uint32_t size = printCallerAppMonitor.printJobMap_.size();
    std::string jobId = "testJobId";
    printCallerAppMonitor.printJobMap_[jobId] = true;
    printCallerAppMonitor.RemovePrintJobFromMap(jobId);
    EXPECT_EQ(printCallerAppMonitor.printJobMap_.size(), size - 1);
}

HWTEST_F(PrintCallerAppMonitorTest, CheckCallerAppInMap_pidNotInMap_returnFalse, TestSize.Level1)
{
    int32_t callerPid = 9999;
    std::string bundleName = "testBundleName";
    EXPECT_EQ(printCallerAppMonitor.CheckCallerAppInMap(callerPid, bundleName), false);
}

HWTEST_F(PrintCallerAppMonitorTest, CheckCallerAppInMap_pidInMapButNullptr_returnFalse, TestSize.Level1)
{
    int32_t callerPid = 9999;
    std::string bundleName = "testBundleName";
    printCallerAppMonitor.callerMap_[callerPid] = nullptr;
    EXPECT_EQ(printCallerAppMonitor.CheckCallerAppInMap(callerPid, bundleName), false);
}

HWTEST_F(PrintCallerAppMonitorTest, CheckCallerAppInMap_pidInMapButBundleNotMatch_returnFalse, TestSize.Level1)
{
    int32_t callerPid = 9999;
    std::string bundleName = "testBundleName";
    std::shared_ptr<PrintCallerAppInfo> callerAppInfo = std::make_shared<PrintCallerAppInfo>(callerPid, -1, "");
    printCallerAppMonitor.callerMap_[callerPid] = callerAppInfo;
    EXPECT_EQ(printCallerAppMonitor.CheckCallerAppInMap(callerPid, bundleName), false);
}

HWTEST_F(PrintCallerAppMonitorTest, CheckCallerAppInMap_matchCallerAppInfoInMap_returnTrue, TestSize.Level1)
{
    int32_t callerPid = 9999;
    std::string bundleName = "testBundleName";
    std::shared_ptr<PrintCallerAppInfo> callerAppInfo = std::make_shared<PrintCallerAppInfo>(callerPid, -1, bundleName);
    callerAppInfo->bundleName_ = bundleName;
    printCallerAppMonitor.callerMap_[callerPid] = callerAppInfo;
    EXPECT_EQ(printCallerAppMonitor.CheckCallerAppInMap(callerPid, bundleName), true);
}

HWTEST_F(PrintCallerAppMonitorTest,
    AddCallerAppToMap_MockIsProcessForegroundReturnTrue_delayUnloadIsTrue, TestSize.Level1)
{
    auto mockPtr = std::make_shared<MockPrintCallerAppMonitor>();
    EXPECT_CALL(*mockPtr, IsProcessForeground(_))
        .WillRepeatedly(Return(true));
    mockPtr->delayUnload_.store(false);
    mockPtr->AddCallerAppToMap();
    EXPECT_EQ(mockPtr->delayUnload_.load(), true);
}

HWTEST_F(PrintCallerAppMonitorTest,
    AddCallerAppToMap_MockIsProcessForegroundReturnFalse_delayUnloadIsFalse, TestSize.Level1)
{
    auto mockPtr = std::make_shared<MockPrintCallerAppMonitor>();
    EXPECT_CALL(*mockPtr, IsProcessForeground(_))
        .WillRepeatedly(Return(false));
    mockPtr->delayUnload_.store(false);
    mockPtr->AddCallerAppToMap();
    EXPECT_EQ(mockPtr->delayUnload_.load(), false);
}

HWTEST_F(PrintCallerAppMonitorTest, IsProcessForeground_AppStateReady_delayUnloadIsFalse, TestSize.Level1)
{
    auto mockPtr = std::make_shared<MockGetRunningProcessInfoByPid>();
    AppExecFwk::RunningProcessInfo processInfo;
    processInfo.state_ = AppExecFwk::AppProcessState::APP_STATE_READY;
    EXPECT_CALL(*mockPtr, GetRunningProcessInfoByPid(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(processInfo), Return(true)));
    int32_t pid = 9999;
    EXPECT_EQ(mockPtr->IsProcessForeground(pid), false);
}

HWTEST_F(PrintCallerAppMonitorTest, IsProcessForeground_AppStateEnd_delayUnloadIsFalse, TestSize.Level1)
{
    auto mockPtr = std::make_shared<MockGetRunningProcessInfoByPid>();
    AppExecFwk::RunningProcessInfo processInfo;
    processInfo.state_ = AppExecFwk::AppProcessState::APP_STATE_END;
    EXPECT_CALL(*mockPtr, GetRunningProcessInfoByPid(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(processInfo), Return(true)));
    int32_t pid = 9999;
    EXPECT_EQ(mockPtr->IsProcessForeground(pid), false);
}

HWTEST_F(PrintCallerAppMonitorTest, IsProcessForeground_AppStateForeground_delayUnloadIsFalse, TestSize.Level1)
{
    auto mockPtr = std::make_shared<MockGetRunningProcessInfoByPid>();
    AppExecFwk::RunningProcessInfo processInfo;
    processInfo.state_ = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    EXPECT_CALL(*mockPtr, GetRunningProcessInfoByPid(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(processInfo), Return(true)));
    int32_t pid = 9999;
    EXPECT_EQ(mockPtr->IsProcessForeground(pid), true);
}
}  // namespace Print
}  // namespace OHOS
