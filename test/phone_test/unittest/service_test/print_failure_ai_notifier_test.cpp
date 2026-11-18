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

#include "print_failure_ai_notifier.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintFailureAiNotifierTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
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

} // namespace Print
} // namespace OHOS
