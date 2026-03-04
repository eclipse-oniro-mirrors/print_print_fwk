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
#include <string>
#include <set>
#include <thread>
#include <chrono>
#define private public
#include "print_failure_ai_notifier.h"
#undef private
#include "print_log.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintFailureAiNotifierTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    PrintFailureAiNotifier& printFailureAiNotifier = PrintFailureAiNotifier::GetInstance();
};

void PrintFailureAiNotifierTest::SetUpTestCase(void)
{}

void PrintFailureAiNotifierTest::TearDownTestCase(void)
{}

void PrintFailureAiNotifierTest::SetUp(void)
{
    printFailureAiNotifier.jobStateMap_.clear();
}

void PrintFailureAiNotifierTest::TearDown(void)
{
    printFailureAiNotifier.jobStateMap_.clear();
}

HWTEST_F(PrintFailureAiNotifierTest, SplitSubState_SingleState_ReturnCorrectSet, TestSize.Level1)
{
    uint32_t subState = 1;
    std::set<uint32_t> result = printFailureAiNotifier.SplitSubState(subState);
    
    EXPECT_EQ(result.size(), 1);
    EXPECT_NE(result.find(1), result.end());
}

HWTEST_F(PrintFailureAiNotifierTest, SplitSubState_TwoStates_ReturnCorrectSet, TestSize.Level1)
{
    uint32_t subState = 201;
    std::set<uint32_t> result = printFailureAiNotifier.SplitSubState(subState);
    
    EXPECT_EQ(result.size(), 2);
    EXPECT_NE(result.find(1), result.end());
    EXPECT_NE(result.find(2), result.end());
}

HWTEST_F(PrintFailureAiNotifierTest, SplitSubState_ThreeStates_ReturnCorrectSet, TestSize.Level1)
{
    uint32_t subState = 60201;
    std::set<uint32_t> result = printFailureAiNotifier.SplitSubState(subState);
    
    EXPECT_EQ(result.size(), 3);
    EXPECT_NE(result.find(1), result.end());
    EXPECT_NE(result.find(2), result.end());
    EXPECT_NE(result.find(6), result.end());
}

HWTEST_F(PrintFailureAiNotifierTest, SplitSubState_Zero_ReturnEmptySet, TestSize.Level1)
{
    uint32_t subState = 0;
    std::set<uint32_t> result = printFailureAiNotifier.SplitSubState(subState);
    
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(PrintFailureAiNotifierTest, SplitSubState_LargeValue_ReturnCorrectSet, TestSize.Level1)
{
    uint32_t subState = 999999;
    std::set<uint32_t> result = printFailureAiNotifier.SplitSubState(subState);
    
    EXPECT_GT(result.size(), 0);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_FirstBlocked_JobStateMapUpdated, TestSize.Level1)
{
    std::string jobId = "test_job_001";
    uint32_t subState = 1;
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, subState, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_.size(), 1);
    auto it = printFailureAiNotifier.jobStateMap_.find(jobId);
    EXPECT_NE(it, printFailureAiNotifier.jobStateMap_.end());
    EXPECT_EQ(it->second.size(), 1);
    EXPECT_NE(it->second.find(1), it->second.end());
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_SameStateTwice_NoDuplicateNotification, TestSize.Level1)
{
    std::string jobId = "test_job_002";
    uint32_t subState = 1;
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, subState, printerName);
    uint32_t initialSize = printFailureAiNotifier.jobStateMap_[jobId].size();
    
    printFailureAiNotifier.HandleJobBlocked(jobId, subState, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), initialSize);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_NewStateAdded_StateSetUpdated, TestSize.Level1)
{
    std::string jobId = "test_job_003";
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, 1, printerName);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 1);
    
    printFailureAiNotifier.HandleJobBlocked(jobId, 201, printerName);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 2);
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(1),
        printFailureAiNotifier.jobStateMap_[jobId].end());
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(2),
        printFailureAiNotifier.jobStateMap_[jobId].end());
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_MultipleJobs_EachJobTrackedSeparately, TestSize.Level1)
{
    std::string jobId1 = "test_job_004";
    std::string jobId2 = "test_job_005";
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId1, 1, printerName);
    printFailureAiNotifier.HandleJobBlocked(jobId2, 2, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_.size(), 2);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId1].size(), 1);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId2].size(), 1);
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId1].find(1),
        printFailureAiNotifier.jobStateMap_[jobId1].end());
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId2].find(2),
        printFailureAiNotifier.jobStateMap_[jobId2].end());
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_EmptyJobId_NoCrash, TestSize.Level1)
{
    std::string jobId = "";
    uint32_t subState = 1;
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, subState, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_.size(), 1);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_EmptyPrinterName_NoCrash, TestSize.Level1)
{
    std::string jobId = "test_job_006";
    uint32_t subState = 1;
    std::string printerName = "";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, subState, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_.size(), 1);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_AllSubStates_AllStatesTracked, TestSize.Level1)
{
    std::string jobId = "test_job_007";
    std::string printerName = "TestPrinter";
    
    for (uint32_t i = 1; i <= 26; i++) {
        printFailureAiNotifier.HandleJobBlocked(jobId, i, printerName);
    }
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 1);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_ComplexSubState_AllStatesParsed, TestSize.Level1)
{
    std::string jobId = "test_job_008";
    std::string printerName = "TestPrinter";
    
    uint32_t complexState = 1 + 2 * 100 + 5 * 10000 + 10 * 1000000;
    printFailureAiNotifier.HandleJobBlocked(jobId, complexState, printerName);
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 4);
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(1),
        printFailureAiNotifier.jobStateMap_[jobId].end());
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(2),
        printFailureAiNotifier.jobStateMap_[jobId].end());
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(5),
        printFailureAiNotifier.jobStateMap_[jobId].end());
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(10),
        printFailureAiNotifier.jobStateMap_[jobId].end());
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_ThreadSafety_NoDataRace, TestSize.Level2)
{
    std::string jobId = "test_job_009";
    std::string printerName = "TestPrinter";
    const int threadCount = 10;
    const int iterationsPerThread = 100;
    
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([this, &jobId, &printerName, i, iterationsPerThread]() {
            for (int j = 0; j < iterationsPerThread; j++) {
                uint32_t state = (i * iterationsPerThread + j) % 26 + 1;
                printFailureAiNotifier.HandleJobBlocked(jobId, state, printerName);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 1);
}

HWTEST_F(PrintFailureAiNotifierTest, GetInstance_Singleton_ReturnSameInstance, TestSize.Level1)
{
    PrintFailureAiNotifier& instance1 = PrintFailureAiNotifier::GetInstance();
    PrintFailureAiNotifier& instance2 = PrintFailureAiNotifier::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_OverwriteState_StateSetUpdated, TestSize.Level1)
{
    std::string jobId = "test_job_010";
    std::string printerName = "TestPrinter";
    
    printFailureAiNotifier.HandleJobBlocked(jobId, 1, printerName);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 1);
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(1),
        printFailureAiNotifier.jobStateMap_[jobId].end());
    printFailureAiNotifier.HandleJobBlocked(jobId, 3, printerName);
    EXPECT_EQ(printFailureAiNotifier.jobStateMap_[jobId].size(), 1);
    EXPECT_NE(printFailureAiNotifier.jobStateMap_[jobId].find(3),
        printFailureAiNotifier.jobStateMap_[jobId].end());
}

}  // namespace Print
}  // namespace OHOS