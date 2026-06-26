/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#define private public
#include "print_ipc_connection.h"
#undef private
#include "print_constant.h"
#include "message_parcel.h"
#include "message_option.h"
#include "element_name.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class PrintIpcConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintIpcConnectionTest::SetUpTestCase(void)
{}

void PrintIpcConnectionTest::TearDownTestCase(void)
{}

void PrintIpcConnectionTest::SetUp(void)
{}

void PrintIpcConnectionTest::TearDown(void)
{}

/**
 * @tc.name: Constructor_001
 * @tc.desc: Branch: default constructor -> remoteObject_ == nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, Constructor_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: IsConnected_001
 * @tc.desc: Branch: remoteObject_ == nullptr -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, IsConnected_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: GetRemoteObject_001
 * @tc.desc: Branch: remoteObject_ == nullptr -> return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, GetRemoteObject_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    sptr<IRemoteObject> remote = connection.GetRemoteObject();
    EXPECT_EQ(nullptr, remote);
}

/**
 * @tc.name: OnAbilityConnectDone_001
 * @tc.desc: Branch: resultCode == ERR_OK && remoteObject != nullptr -> set remoteObject_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, OnAbilityConnectDone_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    connection.OnAbilityConnectDone(element, remoteObject, ERR_OK);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: OnAbilityConnectDone_002
 * @tc.desc: Branch: resultCode != ERR_OK -> remoteObject_ remains nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, OnAbilityConnectDone_002, TestSize.Level1)
{
    PrintIpcConnection connection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    connection.OnAbilityConnectDone(element, remoteObject, -1);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: OnAbilityDisconnectDone_001
 * @tc.desc: Branch: resultCode == ERR_OK -> remoteObject_ set to nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, OnAbilityDisconnectDone_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    AppExecFwk::ElementName element;
    connection.OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: OnAbilityDisconnectDone_002
 * @tc.desc: Branch: resultCode != ERR_OK -> no change
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, OnAbilityDisconnectDone_002, TestSize.Level1)
{
    PrintIpcConnection connection;
    AppExecFwk::ElementName element;
    connection.OnAbilityDisconnectDone(element, -1);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: WaitForConnection_001
 * @tc.desc: Branch: timeout with no connection -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, WaitForConnection_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    bool result = connection.WaitForConnection(100);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: WaitForConnection_002
 * @tc.desc: Branch: timeout 0 -> return false immediately
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, WaitForConnection_002, TestSize.Level1)
{
    PrintIpcConnection connection;
    bool result = connection.WaitForConnection(0);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendData_001
 * @tc.desc: Branch: remoteObject_ == nullptr -> return E_PRINT_RPC_FAILURE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, SendData_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = connection.SendData(1, data, reply, option);
    EXPECT_EQ(E_PRINT_RPC_FAILURE, result);
}

/**
 * @tc.name: SendData_002
 * @tc.desc: Branch: remoteObject_ != nullptr -> SendRequest called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, SendData_002, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject;
    PrintIpcConnection connection;
    connection.remoteObject_ = remoteObject;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = connection.SendData(99999, data, reply, option);
    EXPECT_EQ(E_PRINT_RPC_FAILURE, result);
}

/**
 * @tc.name: DeathRecipient_001
 * @tc.desc: Branch: OnAbilityConnectDone with ERR_OK -> deathRecipient_ created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, DeathRecipient_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    EXPECT_EQ(nullptr, connection.deathRecipient_);
}

/**
 * @tc.name: OnAbilityDisconnectDone_003
 * @tc.desc: Branch: disconnect with deathRecipient_ -> removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, OnAbilityDisconnectDone_003, TestSize.Level1)
{
    PrintIpcConnection connection;
    AppExecFwk::ElementName element;
    connection.OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_EQ(nullptr, connection.deathRecipient_);
    EXPECT_EQ(nullptr, connection.remoteObject_);
}

} // namespace OHOS::Print