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

#include "print_failure_ai_notifier_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class PrintFailureAiNotifierImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintFailureAiNotifierImplTest::SetUpTestCase(void)
{
}

void PrintFailureAiNotifierImplTest::TearDownTestCase(void)
{
}

void PrintFailureAiNotifierImplTest::SetUp(void)
{
}

void PrintFailureAiNotifierImplTest::TearDown(void)
{
}

HWTEST_F(PrintFailureAiNotifierImplTest, QueryInterface_CorrectIid_ReturnThis, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    void *ptr = notifier.QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER);
    EXPECT_EQ(ptr, &notifier);
}

HWTEST_F(PrintFailureAiNotifierImplTest, QueryInterface_WrongIid_ReturnNull, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    void *ptr = notifier.QueryInterface(PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(ptr, nullptr);
}

HWTEST_F(PrintFailureAiNotifierImplTest, HandleJobBlocked_FirstTime_StateTracked, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    notifier.HandleJobBlocked("job_001", 1, "Printer");
    EXPECT_EQ(notifier.jobStateMap_.size(), 1);
    auto it = notifier.jobStateMap_.find("job_001");
    EXPECT_NE(it, notifier.jobStateMap_.end());
    EXPECT_EQ(it->second.size(), 1);
    EXPECT_NE(it->second.find(1), it->second.end());
}

HWTEST_F(PrintFailureAiNotifierImplTest, HandleJobBlocked_SameStateTwice_NoDuplicate, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    notifier.HandleJobBlocked("job_002", 1, "Printer");
    notifier.HandleJobBlocked("job_002", 1, "Printer");
    EXPECT_EQ(notifier.jobStateMap_["job_002"].size(), 1);
}

HWTEST_F(PrintFailureAiNotifierImplTest, HandleJobBlocked_NewStateAdded_StateUpdated, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    notifier.HandleJobBlocked("job_003", 1, "Printer");
    notifier.HandleJobBlocked("job_003", 201, "Printer");
    EXPECT_EQ(notifier.jobStateMap_["job_003"].size(), 2);
    EXPECT_NE(notifier.jobStateMap_["job_003"].find(1), notifier.jobStateMap_["job_003"].end());
    EXPECT_NE(notifier.jobStateMap_["job_003"].find(2), notifier.jobStateMap_["job_003"].end());
}

HWTEST_F(PrintFailureAiNotifierImplTest, ClearJobState_ExistingJob_Removed, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    notifier.HandleJobBlocked("job_004", 1, "Printer");
    EXPECT_EQ(notifier.jobStateMap_.size(), 1);
    notifier.ClearJobState("job_004");
    EXPECT_EQ(notifier.jobStateMap_.size(), 0);
}

HWTEST_F(PrintFailureAiNotifierImplTest, ClearJobState_NonExistingJob_NoEffect, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    notifier.HandleJobBlocked("job_005", 1, "Printer");
    notifier.ClearJobState("job_006");
    EXPECT_EQ(notifier.jobStateMap_.size(), 1);
}

HWTEST_F(PrintFailureAiNotifierImplTest, SplitSubState_Zero_ReturnEmpty, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    auto states = notifier.SplitSubState(0);
    EXPECT_EQ(states.size(), 0);
}

HWTEST_F(PrintFailureAiNotifierImplTest, SplitSubState_CompoundValue_ReturnAllStates, TestSize.Level1)
{
    PrintFailureAiNotifierImpl notifier;
    uint32_t compoundState = 1 + 2 * 100 + 5 * 10000;
    auto states = notifier.SplitSubState(compoundState);
    EXPECT_EQ(states.size(), 3);
    EXPECT_NE(states.find(1), states.end());
    EXPECT_NE(states.find(2), states.end());
    EXPECT_NE(states.find(5), states.end());
}

} // namespace OHOS::Print
