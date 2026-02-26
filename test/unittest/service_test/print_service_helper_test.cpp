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
#define private public
#include "print_service_helper.h"
#undef private
#include "print_constant.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PACKAGE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_STATUS_BAR_ABILITY_NAME = "PluginPrintIconExtAbility";
static const std::string CALLER_PKG_NAME = "caller.pkgName";

class PrintServiceHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void PrintServiceHelperTest::SetUpTestCase(void)
{}

void PrintServiceHelperTest::TearDownTestCase(void)
{}

void PrintServiceHelperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintServiceHelperTest_%{public}d", ++testNo);
}

/**
 * @tc.name: PrintServiceHelperTest_0002
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0002_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    EXPECT_EQ(helper.CheckPermission(""), false);
}

/**
 * @tc.name: PrintServiceHelperTest_0003
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0003_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_EQ(helper.GetBundleMgr(), systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
}

/**
 * @tc.name: PrintServiceHelperTest_0004
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0004_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    std::vector<int> accountList;
    EXPECT_EQ(helper.QueryAccounts(accountList), true);
}

/**
 * @tc.name: PrintServiceHelperTest_0005
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0005_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    std::vector<int> accountList = {};
    EXPECT_EQ(helper.QueryAccounts(accountList), true);
}

/**
 * @tc.name: PrintServiceHelperTest_0006
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0006_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    sptr<AppExecFwk::IBundleMgr> mgr;
    int userId = 0;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(helper.QueryExtension(mgr, userId, extensionInfos), false);
}

/**
 * @tc.name: PrintServiceHelperTest_0007
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0007_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    sptr<AppExecFwk::IBundleMgr> mgr;
    int userId = 0;
    std::string userName;
    EXPECT_EQ(helper.QueryNameForUid(mgr, userId, userName), false);
}

/**
 * @tc.name: PrintServiceHelperTest_0008
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0008_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    EXPECT_EQ(helper.IsSyncMode(), false);
}

/**
 * @tc.name: PrintServiceHelperTest_009
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0009_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    AAFwk::Want want;
    EXPECT_FALSE(helper.StartAbility(want));
}

/**
 * @tc.name: PrintServiceHelperTest_0010
 * @tc.desc: faultPrint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0010_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.PrintSubscribeCommonEvent();
    helper.PrintSubscribeCommonEvent();
    EXPECT_EQ(helper.isSubscribeCommonEvent, true);
}

/**
 * @tc.name: PrintServiceHelperTest_0011
 * @tc.desc: StartExtensionAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0011_NeedRename, TestSize.Level1)
{
    PrintServiceHelper helper;
    AAFwk::Want want;
    EXPECT_FALSE(helper.StartExtensionAbility(want));
}

class PrintServiceHelperCommon {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};

struct BuildSubscribeInfoParam{
    std::string action;
};

class CheckSubscribeInfoTest : public PrintServiceHelperCommon,
                        public testing::TestWithParam<BuildSubscribeInfoParam> {
public:
    using PrintServiceHelperCommon::SetUp;
    using PrintServiceHelperCommon::SetUpTestCase;
    using PrintServiceHelperCommon::TearDown;
    using PrintServiceHelperCommon::TearDownTestCase;
};

void TestSubscribeEventTemplate(const std::string action)
{
    PrintServiceHelper helper;
    helper.PrintSubscribeCommonEvent();
    OHOS::EventFwk::Want want;
    want.SetAction(action);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(100);
    helper.userStatusListener->OnReceiveEvent(data);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

HWTEST_P(CheckSubscribeInfoTest, CheckSubscribeInfoTest_P, TestSize.Level1)
{
    BuildSubscribeInfoParam param = GetParam();
    TestSubscribeEventTemplate(param.action);
}

INSTANTIATE_TEST_SUITE_P(CheckSubscribeInfoTest, CheckSubscribeInfoTest,
    testing::Values(
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_ENTER_HIBERNATE},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_EXIT_HIBERNATE},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_ENTER_FORCE_SLEEP},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_EXIT_FORCE_SLEEP},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED},
        BuildSubscribeInfoParam{EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN},
        BuildSubscribeInfoParam{"unknown.event"},
        BuildSubscribeInfoParam{""}
    ));
}  // namespace Print
}  // namespace OHOS