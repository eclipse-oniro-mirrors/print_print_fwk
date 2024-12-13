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
#include "print_bms_helper.h"
#undef private
#include "print_constant.h"
#include "mock_bundle_mgr.h"
#include "mock_print_service_helper.h"
#include "mock_remote_object.h"
#include "print_log.h"

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

void PrintBMSHelperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintBMSHelperTest_%{public}d", ++testNo);
}

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
* @tc.name: PrintBMSHelperTest_0002
* @tc.desc: PrintBMSHelper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0002, TestSize.Level1)
{
    PrintBMSHelper printBMSHelper;
    auto helper = std::make_shared<MockPrintServiceHelper>();
    std::shared_ptr<PrintServiceHelper> temp = std::shared_ptr<PrintServiceHelper>(helper);
    printBMSHelper.SetHelper(temp);
    EXPECT_EQ(printBMSHelper.helper_, temp);
    EXPECT_EQ(printBMSHelper.sptrBundleMgr_, nullptr);
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
    std::shared_ptr<PrintServiceHelper> temp = nullptr;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(temp);
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
    auto helper = std::make_shared<MockPrintServiceHelper>();
    temp = std::shared_ptr<PrintServiceHelper>(helper);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(temp);
    EXPECT_FALSE(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(resultInfo));
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
    std::shared_ptr<PrintServiceHelper> temp = nullptr;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(temp);
    EXPECT_EQ(DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName(), testName);
}

/**
* @tc.name: PrintBMSHelperTest_0009
* @tc.desc: QueryCallerBundleName fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0009, TestSize.Level1)
{
    PrintBMSHelper printBMSHelper;
    std::shared_ptr<PrintServiceHelper> temp = nullptr;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(temp);
    EXPECT_EQ(DelayedSingleton<PrintBMSHelper>::GetInstance()->GetProxy(), false);
    auto helper = std::make_shared<MockPrintServiceHelper>();
    temp = std::shared_ptr<PrintServiceHelper>(helper);
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(temp);
    EXPECT_EQ(DelayedSingleton<PrintBMSHelper>::GetInstance()->GetProxy(), false);
}

/**
* @tc.name: PrintBMSHelperTest_0010
* @tc.desc: QueryCallerBundleName fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0010, TestSize.Level1)
{
    PrintBMSHelper printBMSHelper;
    const wptr<IRemoteObject> testObj = nullptr;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->ResetProxy(testObj);
    wptr<IRemoteObject> testObj2 = new (std::nothrow) MockBundleMgr();
    printBMSHelper.ResetProxy(testObj2);
    EXPECT_EQ(printBMSHelper.sptrBundleMgr_, nullptr);
    EXPECT_EQ(printBMSHelper.printBMSDeath_, nullptr);
}
}  // namespace Print
}  // namespace OHOS
