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

#include "print_constant.h"
#include "print_failure_ai_notifier.h"

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
};

void PrintFailureAiNotifierTest::SetUpTestCase(void)
{}

void PrintFailureAiNotifierTest::TearDownTestCase(void)
{}

void PrintFailureAiNotifierTest::SetUp(void)
{}

void PrintFailureAiNotifierTest::TearDown(void)
{}

HWTEST_F(PrintFailureAiNotifierTest, GetInstance_ReturnsSameInstance, TestSize.Level1)
{
    PrintFailureAiNotifier &instance1 = PrintFailureAiNotifier::GetInstance();
    PrintFailureAiNotifier &instance2 = PrintFailureAiNotifier::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(PrintFailureAiNotifierTest, HandleJobBlocked_NoPluginLoaded_NoCrash, TestSize.Level1)
{
    PrintFailureAiNotifier &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_NO_FATAL_FAILURE(notifier.HandleJobBlocked("job_001", 1, "Printer", INVALID_USER_ID));
}

HWTEST_F(PrintFailureAiNotifierTest, ClearJobState_NoPluginLoaded_NoCrash, TestSize.Level1)
{
    PrintFailureAiNotifier &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_NO_FATAL_FAILURE(notifier.ClearJobState("job_001"));
}

HWTEST_F(PrintFailureAiNotifierTest, Reset_NoPluginLoaded_NoCrash, TestSize.Level1)
{
    PrintFailureAiNotifier &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_NO_FATAL_FAILURE(notifier.Reset());
}

} // namespace Print
} // namespace OHOS
