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
#include "napi/native_api.h"

#include "print_service_ability.cpp"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceAbilityTest::SetUpTestCase(void) {}

void PrintServiceAbilityTest::TearDownTestCase(void) {}

void PrintServiceAbilityTest::SetUp(void) {}

void PrintServiceAbilityTest::TearDown(void) {}

/**
* @tc.name: PrintServiceAbilityTest_0001
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001, TestSize.Level1)
{
    PrintServiceAbility::PrintServiceAbility();
    PrintServiceAbility::PrintServiceAbility(32, true);
    ~PrintServiceAbility();
}

/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {"1", "2", "3"};
    std::vector<std::string> fileList_err = {};
    std::vector<uint32_t> fdList_err = {};
    std::string taskId = "taskId_1";
    PrintServiceAbility::StartPrint(fileList, fdList, taskId);
    PrintServiceAbility::StartPrint(fileList_err, fdList_err, taskId);
}
} // namespace Print
} // namespace OHOS