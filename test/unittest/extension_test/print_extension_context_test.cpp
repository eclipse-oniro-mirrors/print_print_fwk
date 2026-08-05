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
#include "print_extension_context.h"
#undef private
#include "print_constant.h"
#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "connection_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class PrintExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionContextTest::SetUpTestCase(void)
{}
void PrintExtensionContextTest::TearDownTestCase(void)
{}

void PrintExtensionContextTest::SetUp(void)
{
    // Reset mock state before each test
    AAFwk::AbilityManagerClient::ResetInstance();
    auto &connMgr = AbilityRuntime::ConnectionManager::GetInstance();
    connMgr.connectAbilityResult_ = ERR_OK;
    connMgr.disconnectAbilityResult_ = ERR_OK;
}

void PrintExtensionContextTest::TearDown(void)
{
    AAFwk::AbilityManagerClient::ResetInstance();
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0001, TestSize.Level0)
{
    AAFwk::Want want;
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.StartAbility(want), Print::E_PRINT_SERVER_FAILURE);
    auto mockClient = std::make_shared<AAFwk::AbilityManagerClient>();
    mockClient->startAbilityResult_ = ERR_OK;
    AAFwk::AbilityManagerClient::SetInstance(mockClient);
    EXPECT_EQ(printExtensionContext.StartAbility(want), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0002, TestSize.Level0)
{
    AAFwk::Want want;
    AAFwk::StartOptions startOptions;
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.StartAbility(want, startOptions), Print::E_PRINT_SERVER_FAILURE);
    auto mockClient = std::make_shared<AAFwk::AbilityManagerClient>();
    mockClient->startAbilityResult_ = ERR_OK;
    AAFwk::AbilityManagerClient::SetInstance(mockClient);
    EXPECT_EQ(printExtensionContext.StartAbility(want, startOptions), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0003, TestSize.Level0)
{
    AAFwk::Want want;
    int accountId = 0;
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.StartAbilityWithAccount(want, accountId), Print::E_PRINT_SERVER_FAILURE);
    auto mockClient = std::make_shared<AAFwk::AbilityManagerClient>();
    mockClient->startAbilityResult_ = ERR_OK;
    AAFwk::AbilityManagerClient::SetInstance(mockClient);
    EXPECT_EQ(printExtensionContext.StartAbilityWithAccount(want, accountId), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0004, TestSize.Level0)
{
    AAFwk::Want want;
    int accountId = 0;
    AAFwk::StartOptions startOptions;
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.StartAbilityWithAccount(want, accountId, startOptions),
        Print::E_PRINT_SERVER_FAILURE);
    auto mockClient = std::make_shared<AAFwk::AbilityManagerClient>();
    mockClient->startAbilityResult_ = ERR_OK;
    AAFwk::AbilityManagerClient::SetInstance(mockClient);
    EXPECT_EQ(printExtensionContext.StartAbilityWithAccount(want, accountId, startOptions), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0005, TestSize.Level0)
{
    AAFwk::Want want;
    sptr<AbilityConnectCallback> connectCallback;
    PrintExtensionContext printExtensionContext;
    auto &connMgr = AbilityRuntime::ConnectionManager::GetInstance();
    connMgr.disconnectAbilityResult_ = AAFwk::CONNECTION_NOT_EXIST;
    EXPECT_EQ(printExtensionContext.DisconnectAbility(want, connectCallback), Print::E_PRINT_RPC_FAILURE);
    connMgr.disconnectAbilityResult_ = ERR_OK;
    EXPECT_EQ(printExtensionContext.DisconnectAbility(want, connectCallback), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0006, TestSize.Level0)
{
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.TerminateAbility(), Print::E_PRINT_SERVER_FAILURE);
    auto mockClient = std::make_shared<AAFwk::AbilityManagerClient>();
    mockClient->terminateAbilityResult_ = ERR_OK;
    AAFwk::AbilityManagerClient::SetInstance(mockClient);
    EXPECT_EQ(printExtensionContext.TerminateAbility(), Print::E_PRINT_NONE);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_0007, TestSize.Level0)
{
    PrintExtensionContext printExtensionContext;
    EXPECT_EQ(printExtensionContext.GetAbilityInfoType(), AppExecFwk::AbilityType::UNKNOWN);
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_ConnectAbility, TestSize.Level0)
{
    AAFwk::Want want;
    sptr<AbilityConnectCallback> connectCallback = nullptr;
    PrintExtensionContext printExtensionContext;
    auto &connMgr = AbilityRuntime::ConnectionManager::GetInstance();
    connMgr.connectAbilityResult_ = ERR_OK;
    EXPECT_TRUE(printExtensionContext.ConnectAbility(want, connectCallback));
    connMgr.connectAbilityResult_ = AAFwk::CONNECTION_NOT_EXIST;
    EXPECT_FALSE(printExtensionContext.ConnectAbility(want, connectCallback));
}

HWTEST_F(PrintExtensionContextTest, PrintExtensionContextTest_ConnectAbilityWithAccount, TestSize.Level0)
{
    AAFwk::Want want;
    int accountId = 0;
    sptr<AbilityConnectCallback> connectCallback = nullptr;
    PrintExtensionContext printExtensionContext;
    auto &connMgr = AbilityRuntime::ConnectionManager::GetInstance();
    connMgr.connectAbilityResult_ = ERR_OK;
    EXPECT_TRUE(printExtensionContext.ConnectAbilityWithAccount(want, accountId, connectCallback));
    connMgr.connectAbilityResult_ = AAFwk::CONNECTION_NOT_EXIST;
    EXPECT_FALSE(printExtensionContext.ConnectAbilityWithAccount(want, accountId, connectCallback));
}
}  // namespace AbilityRuntime
}  // namespace OHOS
