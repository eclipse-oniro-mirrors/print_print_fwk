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
#define private public
#include "hisys_event_util.h"
#undef private
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
 * @tc.desc: ReportPrintFailure empty-key guard: non-empty key reaches HiSysEventWrite, empty key early-returns
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportPrintFailure(10, "test_print_failure"));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportPrintFailure(10, ""));
    HisysEventParams params{
        .eventType = HisysEventType::PRINT_FAILURE,
        .resourceKey = "dispatch_test",
        .subState = 10
    };
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportFailureEvent(params));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportPrintFailure(0, "guard_non_empty"));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportPrintFailure(0, ""));
}

/**
 * @tc.name: HisysEventUtilTest_0002
 * @tc.desc: ReportConnectFailure empty-key guard and printerModel default ("unknown") logic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportConnectFailure("test_connect", "PrinterX"));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportConnectFailure("test_connect_empty_model", ""));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportConnectFailure("", "PrinterX"));
    HisysEventParams params{
        .eventType = HisysEventType::CONNECT_FAILURE,
        .resourceKey = "dispatch_test",
        .printerModel = "printerModel"
    };
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportFailureEvent(params));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportConnectFailure("ternary_with_model", "ModelA"));
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportConnectFailure("ternary_without_model", ""));
}

/**
 * @tc.name: HisysEventUtilTest_0003
 * @tc.desc: ReportFailureEvent with invalid eventType hits switch default (no dispatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0003, TestSize.Level1)
{
    HisysEventParams invalidParams{
        .eventType = static_cast<HisysEventType>(999),
        .resourceKey = "test"
    };
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportFailureEvent(invalidParams));
    HisysEventParams invalidEmptyParams{
        .eventType = static_cast<HisysEventType>(999),
        .resourceKey = ""
    };
    EXPECT_NO_FATAL_FAILURE(HisysEventUtil::ReportFailureEvent(invalidEmptyParams));
}
}  // namespace Print
}  // namespace OHOS
