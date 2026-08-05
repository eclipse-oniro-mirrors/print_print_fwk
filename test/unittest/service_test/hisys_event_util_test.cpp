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
#include <string>
#include "hisys_event_util.h"
#include "print_constant.h"

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

void HisysEventUtilTest::SetUpTestCase(void)
{}

void HisysEventUtilTest::TearDownTestCase(void)
{}

void HisysEventUtilTest::SetUp(void)
{}

void HisysEventUtilTest::TearDown(void)
{}

/**
 * @tc.name: HisysEventUtilTest_0001
 * @tc.desc: ReportFailureEvent PRINT_FAILURE (non-empty key -> write; empty key -> skip)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0001, TestSize.Level1)
{
    HisysEventParams nonEmpty{
        .eventType = HisysEventType::PRINT_FAILURE,
        .resourceKey = "test",
        .subState = 10
    };
    HisysEventUtil::ReportFailureEvent(nonEmpty);
    HisysEventParams empty{
        .eventType = HisysEventType::PRINT_FAILURE,
        .resourceKey = "",
        .subState = 10
    };
    HisysEventUtil::ReportFailureEvent(empty);
    SUCCEED();
}

/**
 * @tc.name: HisysEventUtilTest_0002
 * @tc.desc: ReportFailureEvent CONNECT_FAILURE (non-empty key -> write; empty key -> skip)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0002, TestSize.Level1)
{
    HisysEventParams nonEmpty{
        .eventType = HisysEventType::CONNECT_FAILURE,
        .resourceKey = "test",
        .printerModel = "printerModel"
    };
    HisysEventUtil::ReportFailureEvent(nonEmpty);
    HisysEventParams empty{
        .eventType = HisysEventType::CONNECT_FAILURE,
        .resourceKey = "",
        .printerModel = "printerModel"
    };
    HisysEventUtil::ReportFailureEvent(empty);
    SUCCEED();
}

/**
 * @tc.name: HisysEventUtilTest_0003
 * @tc.desc: ReportFailureEvent with invalid eventType (switch default branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0003, TestSize.Level1)
{
    HisysEventParams params{
        .eventType = static_cast<HisysEventType>(999),
        .resourceKey = "test"
    };
    HisysEventUtil::ReportFailureEvent(params);
    SUCCEED();
}
}  // namespace Print
}  // namespace OHOS
