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

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceHelperTest::SetUpTestCase(void) {}

void PrintServiceHelperTest::TearDownTestCase(void) {}

void PrintServiceHelperTest::SetUp(void) {}

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
} // namespace Print
} // namespace OHOS