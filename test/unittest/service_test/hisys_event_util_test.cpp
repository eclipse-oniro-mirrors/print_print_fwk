/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "hisys_event_util.h"
#include "print_constant.h"

#include "mock_hisys_event_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class HisysEventUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HisysEventUtilTest::SetUpTestCase(void) {}

void HisysEventUtilTest::TearDownTestCase(void) {}

void HisysEventUtilTest::SetUp(void) {}

void HisysEventUtilTest::TearDown(void) {}

/**
* @tc.name: HisysEventUtilTest_0001
* @tc.desc: reportPrintSuccess
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0001, TestSize.Level1)
{
    OHOS::Print::HisysEventUtil util;
    std::string param = "";
    util->reportBehaviorEvent("test", HisysEventUtil::SEND_TASK, param);
    EXPECT_CALL(util, reportBehaviorEvent(_, _, _)).Times(1);
}
} // namespace Print
} // namespace OHOS