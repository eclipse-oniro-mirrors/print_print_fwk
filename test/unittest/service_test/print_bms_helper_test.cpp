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
#include "print_bms_helper.h"
#include "print_constant.h"
#include "mock_bundle_mgr.h"
#include "mock_print_service_helper.h"
#include "mock_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintBMSHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CallRemoteObject(const sptr<MockBundleMgr> &obj, sptr<IRemoteObject::DeathRecipient> &dr);
};

void PrintBMSHelperTest::SetUpTestCase(void) {}

void PrintBMSHelperTest::TearDownTestCase(void) {}

void PrintBMSHelperTest::SetUp(void) {}

void PrintBMSHelperTest::TearDown(void) {}

void PrintBMSHelperTest::CallRemoteObject(const sptr<MockBundleMgr> &obj,
    sptr<IRemoteObject::DeathRecipient> &dr)
{
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillRepeatedly(
        [&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });
}

/**
* @tc.name: PrintBMSHelperTest_0001
* @tc.desc: PrintBMSHelper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0001, TestSize.Level1)
{
    PrintBMSHelper printBMSHelper;
    printBMSHelper.~PrintBMSHelper();
}

/**
* @tc.name: PrintBMSHelperTest_0002
* @tc.desc: PrintBMSHelper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0002, TestSize.Level1)
{
    PrintBMSHelper printBMSHelper;
    auto helper = std::make_shared<MockPrintServiceHelper>();
    printBMSHelper.SetHelper(helper);
}

/**
* @tc.name: PrintBMSHelperTest_0003
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0003, TestSize.Level1)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> resultInfo;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(nullptr);
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
}

/**
* @tc.name: PrintBMSHelperTest_0004
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0004, TestSize.Level1)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> resultInfo;
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper);
    EXPECT_CALL(*helper, GetBundleMgr()).Times(1).WillOnce(Return(nullptr));
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
}

/**
* @tc.name: PrintBMSHelperTest_0005
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0005, TestSize.Level1)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> resultInfo;
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper);
    EXPECT_CALL(*helper, GetBundleMgr()).Times(1);
    ON_CALL(*helper, GetBundleMgr).WillByDefault(
        []() -> sptr<IRemoteObject> {
            return new (std::nothrow) MockRemoteObject();
        });
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
}

/**
* @tc.name: PrintBMSHelperTest_0006
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0006, TestSize.Level1)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> resultInfo;
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper);
    sptr<MockBundleMgr> obj = new (std::nothrow) MockBundleMgr();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*helper, GetBundleMgr()).Times(1);
    ON_CALL(*helper, GetBundleMgr).WillByDefault(
        [&obj]() -> sptr<IRemoteObject> {
            return obj;
        });
    EXPECT_CALL(*helper, QueryAccounts(_)).Times(1).WillOnce(Return(false));
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(obj, dr);
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintBMSHelperTest_0007
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0007, TestSize.Level1)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> resultInfo;

    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper);
    sptr<MockBundleMgr> obj = new (std::nothrow) MockBundleMgr();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*helper, GetBundleMgr()).Times(1);
    ON_CALL(*helper, GetBundleMgr).WillByDefault(
        [&obj]() -> sptr<IRemoteObject> {
            return obj;
        });
    ON_CALL(*helper, QueryAccounts).WillByDefault(
        [](std::vector<int> &accountList) {
            accountList.emplace_back(1);
            return true;
        });
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    EXPECT_CALL(*helper, QueryExtension(_, _, _)).WillRepeatedly(Return(true));
    CallRemoteObject(obj, dr);
    EXPECT_TRUE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintBMSHelperTest_0008
* @tc.desc: QueryCallerBundleName fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0008, TestSize.Level1)
{
    std::string testName = "";
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(nullptr);
    EXPECT_EQ(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName(), testName);
}

/**
* @tc.name: PrintBMSHelperTest_0009
* @tc.desc: QueryCallerBundleName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0009, TestSize.Level1)
{
    std::string testName = "com.example.ext.extability";

    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper);
    sptr<MockBundleMgr> obj = new (std::nothrow) MockBundleMgr();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*helper, GetBundleMgr()).Times(1).WillOnce(Return(obj));
    EXPECT_CALL(*helper, QueryNameForUid(_, _, _)).WillRepeatedly(Return(true));
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(obj, dr);
    EXPECT_EQ(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName(), "");
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintBMSHelperTest_0010
* @tc.desc: QueryCallerBundleName fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0010, TestSize.Level1)
{
    const wptr<IRemoteObject> testObj = nullptr;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->ResetProxy(testObj);
}

/**
* @tc.name: PrintBMSHelperTest_0011
* @tc.desc: QueryCallerBundleName fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0011, TestSize.Level1)
{
    wptr<IRemoteObject> testObj = new (std::nothrow) MockBundleMgr();
    DelayedSingleton<PrintBMSHelper>::GetInstance()->ResetProxy(testObj);
}
}  // namespace Print
}  // namespace OHOS
