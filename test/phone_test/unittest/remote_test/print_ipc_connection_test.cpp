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
#include "mock_remote_object.h"


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
* @tc.name: OnAbilityConnectDone_004
* @tc.desc: Branch: connect success -> deathRecipient created and added
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintIpcConnectionTest, OnAbilityConnectDone_004, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    EXPECT_NE(nullptr, connection->deathRecipient_);
    EXPECT_NE(nullptr, connection->remoteObject_);
}

/**
* @tc.name: OnAbilityDisconnectDone_004
* @tc.desc: Branch: disconnect success -> deathRecipient removed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintIpcConnectionTest, OnAbilityDisconnectDone_004, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityDisconnectDone(element, ERR_OK);
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    connection->OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_EQ(nullptr, connection->deathRecipient_);
    EXPECT_EQ(nullptr, connection->remoteObject_);
}

/**
 * @tc.name: ClearConnection_001
 * @tc.desc: Branch: remoteObject_ set, deathRecipient_ null -> skip remove, null both
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, ClearConnection_001, TestSize.Level1)
{
    PrintIpcConnection connection;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    connection.remoteObject_ = mockRemote;
    EXPECT_TRUE(connection.IsConnected());
    connection.ClearConnection();
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_EQ(nullptr, connection.remoteObject_);
}

/**
 * @tc.name: ClearConnection_002
 * @tc.desc: Branch: remoteObject_ and deathRecipient_ both set -> remove recipient, null both
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIpcConnectionTest, ClearConnection_002, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    EXPECT_TRUE(connection->IsConnected());
    connection->ClearConnection();
    EXPECT_FALSE(connection->IsConnected());
    EXPECT_EQ(nullptr, connection->deathRecipient_);
    EXPECT_EQ(nullptr, connection->remoteObject_);
}

HWTEST_F(PrintIpcConnectionTest, SendData_RemoteObjectValid_SendRequestFails_ClearsObject, TestSize.Level1)
{
    PrintIpcConnection connection;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _)).WillRepeatedly(Return(-1));
    connection.remoteObject_ = mockRemote;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = connection.SendData(1, data, reply, option);

    EXPECT_EQ(-1, result);
    EXPECT_EQ(nullptr, connection.remoteObject_);
}

HWTEST_F(PrintIpcConnectionTest, IsConnectedAndGetRemoteObject_WithRemoteObject_ReturnTrueAndObject, TestSize.Level1)
{
    PrintIpcConnection connection;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    connection.remoteObject_ = mockRemote;

    EXPECT_TRUE(connection.IsConnected());
    EXPECT_NE(nullptr, connection.GetRemoteObject());
}

HWTEST_F(PrintIpcConnectionTest, WaitForConnection_AlreadyConnected_ReturnsTrue, TestSize.Level1)
{
    PrintIpcConnection connection;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    connection.remoteObject_ = mockRemote;

    EXPECT_TRUE(connection.WaitForConnection(0));
}

HWTEST_F(PrintIpcConnectionTest, OnAbilityConnectDone_AddDeathRecipientFail_LogsWarning, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(false));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    EXPECT_NE(nullptr, connection->remoteObject_);
    EXPECT_NE(nullptr, connection->deathRecipient_);
}

HWTEST_F(PrintIpcConnectionTest, OnAbilityDisconnectDone_RemoveDeathRecipientFail_LogsWarning, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);

    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(false));
    connection->OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_EQ(nullptr, connection->remoteObject_);
    EXPECT_EQ(nullptr, connection->deathRecipient_);
}

HWTEST_F(PrintIpcConnectionTest, ClearConnection_NoRemoteObject_DoesNothing, TestSize.Level1)
{
    PrintIpcConnection connection;
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_NO_FATAL_FAILURE(connection.ClearConnection());
    EXPECT_EQ(nullptr, connection.remoteObject_);
}

HWTEST_F(PrintIpcConnectionTest, SendData_RemoteObjectValid_SendRequestSucceeds, TestSize.Level1)
{
    PrintIpcConnection connection;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _)).WillRepeatedly(Return(ERR_OK));
    connection.remoteObject_ = mockRemote;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = connection.SendData(1, data, reply, option);

    EXPECT_EQ(ERR_OK, result);
    EXPECT_NE(nullptr, connection.remoteObject_);
}

HWTEST_F(PrintIpcConnectionTest, OnAbilityConnectDone_RemoteObjectWithoutDeathRecipient_SetsRecipient, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    connection->remoteObject_ = mockRemote;
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);
    EXPECT_EQ(connection->remoteObject_.GetRefPtr(), mockRemote.GetRefPtr());
    EXPECT_NE(nullptr, connection->deathRecipient_);
}

HWTEST_F(PrintIpcConnectionTest, ClearConnection_RemoveDeathRecipientFail_LogsWarning, TestSize.Level1)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockRemote, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    AppExecFwk::ElementName element;
    connection->OnAbilityConnectDone(element, mockRemote, ERR_OK);

    EXPECT_CALL(*mockRemote, RemoveDeathRecipient(_)).WillRepeatedly(Return(false));
    connection->ClearConnection();
    EXPECT_EQ(nullptr, connection->remoteObject_);
    EXPECT_EQ(nullptr, connection->deathRecipient_);
}

} // namespace OHOS::Print
