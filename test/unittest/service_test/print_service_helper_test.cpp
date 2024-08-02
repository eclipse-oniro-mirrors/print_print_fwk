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
#include "print_service_helper.h"
#include "print_constant.h"
#include "ipc_skeleton.h"

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
    void TearDown();
};

void PrintServiceHelperTest::SetUpTestCase(void) {}

void PrintServiceHelperTest::TearDownTestCase(void) {}

void PrintServiceHelperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintServiceHelperTest_%{public}d", ++testNo);
}

void PrintServiceHelperTest::TearDown(void) {}

/**
* @tc.name: PrintServiceHelperTest_0001
* @tc.desc: reportPrintSuccess
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0001, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.~PrintServiceHelper();
}

/**
* @tc.name: PrintServiceHelperTest_0002
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0002, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.CheckPermission("");
}

/**
* @tc.name: PrintServiceHelperTest_0003
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0003, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.GetBundleMgr();
}

/**
* @tc.name: PrintServiceHelperTest_0004
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0004, TestSize.Level1)
{
    PrintServiceHelper helper;
    std::vector<int> accountList;
    helper.QueryAccounts(accountList);
}

/**
* @tc.name: PrintServiceHelperTest_0005
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0005, TestSize.Level1)
{
    PrintServiceHelper helper;
    std::vector<int> accountList = {};
    helper.QueryAccounts(accountList);
}

/**
* @tc.name: PrintServiceHelperTest_0006
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0006, TestSize.Level1)
{
    PrintServiceHelper helper;
    sptr<AppExecFwk::IBundleMgr> mgr;
    int userId = 0;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    helper.QueryExtension(mgr, userId, extensionInfos);
}

/**
* @tc.name: PrintServiceHelperTest_0007
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0007, TestSize.Level1)
{
    PrintServiceHelper helper;
    sptr<AppExecFwk::IBundleMgr> mgr;
    int userId = 0;
    std::string userName;
    helper.QueryNameForUid(mgr, userId, userName);
}

/**
* @tc.name: PrintServiceHelperTest_0008
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0008, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.IsSyncMode();
}

/**
* @tc.name: PrintServiceHelperTest_009
* @tc.desc: faultPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0009, TestSize.Level1) {
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
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0010, TestSize.Level1)
{
    PrintServiceHelper helper;
    helper.PrintSubscribeCommonEvent();
    helper.PrintSubscribeCommonEvent();
}

/**
* @tc.name: PrintServiceHelperTest_0011
* @tc.desc: StartPluginPrintIconExtAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceHelperTest, PrintServiceHelperTest_0011, TestSize.Level1) {
    PrintServiceHelper helper;
    AAFwk::Want want;
    EXPECT_FALSE(helper.StartPluginPrintIconExtAbility(want));
}
} // namespace Print
} // namespace OHOS