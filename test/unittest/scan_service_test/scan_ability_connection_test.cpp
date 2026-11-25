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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "element_name.h"
#include "errors.h"
#include "mock_remote_object.h"
#include "scan_ability_connection.h"
#include "scan_cert_dialog_callback.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;

namespace OHOS {
namespace Scan {

class ScanAbilityConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static sptr<ScanCertDecisionCallback> MakeDecisionCallback()
    {
        return new ScanCertDecisionCallback(
            [](const std::string &, const std::string &, const std::string &, int32_t) {});
    }
};

void ScanAbilityConnectionTest::SetUpTestCase(void) {}
void ScanAbilityConnectionTest::TearDownTestCase(void) {}

/**
 * @tc.name: ScanAbilityConnectionTest_InitialState_0001
 * @tc.desc: Verify a fresh connection is disconnected and has no remote.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_InitialState_0001, TestSize.Level2)
{
    ScanAbilityConnection connection(nullptr, nullptr);
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_EQ(nullptr, connection.GetRemote().GetRefPtr());
    EXPECT_FALSE(connection.SendDismiss("session-1"));
}

/**
 * @tc.name: ScanAbilityConnectionTest_ConnectDone_ErrorResult_0002
 * @tc.desc: Verify a failed connect result leaves the connection disconnected.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_ConnectDone_ErrorResult_0002, TestSize.Level2)
{
    bool connected = false;
    ScanAbilityConnection connection([&connected](const std::string &) { connected = true; }, nullptr);
    sptr<OHOS::Print::MockRemoteObject> remote = new OHOS::Print::MockRemoteObject();
    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, remote, -1);
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_FALSE(connected);
    EXPECT_EQ(nullptr, connection.GetRemote().GetRefPtr());
}

/**
 * @tc.name: ScanAbilityConnectionTest_ConnectDone_NullRemote_0003
 * @tc.desc: Verify a null remote marks connected but never fires onConnected.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_ConnectDone_NullRemote_0003, TestSize.Level2)
{
    bool connected = false;
    ScanAbilityConnection connection([&connected](const std::string &) { connected = true; }, nullptr);
    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, nullptr, ERR_OK);
    EXPECT_TRUE(connection.IsConnected());
    EXPECT_FALSE(connected);
}

/**
 * @tc.name: ScanAbilityConnectionTest_ConnectDone_NoDeathRecipient_0004
 * @tc.desc: Verify connect without a decision callback does not register a death recipient or remote.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_ConnectDone_NoDeathRecipient_0004, TestSize.Level2)
{
    bool connected = false;
    ScanAbilityConnection connection([&connected](const std::string &) { connected = true; }, nullptr);
    sptr<OHOS::Print::MockRemoteObject> remote = new OHOS::Print::MockRemoteObject();
    EXPECT_CALL(*remote, AddDeathRecipient(_)).Times(0);
    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, remote, ERR_OK);
    EXPECT_TRUE(connection.IsConnected());
    EXPECT_FALSE(connected);
    EXPECT_EQ(nullptr, connection.GetRemote().GetRefPtr());
}

/**
 * @tc.name: ScanAbilityConnectionTest_ConnectDone_WithDecisionCallback_0005
 * @tc.desc: Verify connect registers the callback, sends REGISTER_CALLBACK and fires onConnected.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_ConnectDone_WithDecisionCallback_0005, TestSize.Level2)
{
    std::string connectedSession;
    ScanAbilityConnection connection([&connectedSession](const std::string &session) {
        connectedSession = session;
    }, nullptr);
    connection.SetDecisionCallback(MakeDecisionCallback(), "session-1");

    sptr<OHOS::Print::MockRemoteObject> remote = new OHOS::Print::MockRemoteObject();
    EXPECT_CALL(*remote, AddDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_CALL(*remote, SendRequest(
        static_cast<uint32_t>(ScanCertDialogCode::REGISTER_CALLBACK), _, _, _))
        .WillOnce(Return(ERR_NONE));

    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, remote, ERR_OK);
    EXPECT_TRUE(connection.IsConnected());
    EXPECT_EQ("session-1", connectedSession);
    EXPECT_EQ(remote.GetRefPtr(), connection.GetRemote().GetRefPtr());
}

/**
 * @tc.name: ScanAbilityConnectionTest_RemoteDied_FiresOnClosed_0006
 * @tc.desc: Verify the death recipient captured for the session invokes onClosed with that session.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_RemoteDied_FiresOnClosed_0006, TestSize.Level2)
{
    std::string closedSession;
    ScanAbilityConnection connection(nullptr, [&closedSession](const std::string &session) {
        closedSession = session;
    });
    connection.SetDecisionCallback(MakeDecisionCallback(), "session-2");

    sptr<OHOS::Print::MockRemoteObject> remote = new OHOS::Print::MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> capturedRecipient;
    EXPECT_CALL(*remote, AddDeathRecipient(_))
        .WillOnce(DoAll(SaveArg<0>(&capturedRecipient), Return(true)));
    EXPECT_CALL(*remote, SendRequest(
        static_cast<uint32_t>(ScanCertDialogCode::REGISTER_CALLBACK), _, _, _))
        .WillOnce(Return(ERR_NONE));

    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, remote, ERR_OK);
    ASSERT_NE(nullptr, capturedRecipient.GetRefPtr());

    capturedRecipient->OnRemoteDied(nullptr);
    EXPECT_EQ("session-2", closedSession);
}

/**
 * @tc.name: ScanAbilityConnectionTest_DisconnectDone_0007
 * @tc.desc: Verify disconnect clears the connected flag and fires onClosed with the session.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_DisconnectDone_0007, TestSize.Level2)
{
    std::string closedSession;
    ScanAbilityConnection connection(nullptr, [&closedSession](const std::string &session) {
        closedSession = session;
    });
    connection.SetDecisionCallback(MakeDecisionCallback(), "session-3");

    AppExecFwk::ElementName element;
    connection.OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_EQ("session-3", closedSession);
}

/**
 * @tc.name: ScanAbilityConnectionTest_SendDismiss_0008
 * @tc.desc: Verify SendDismiss returns true on success and false on transport failure.
 */
HWTEST_F(ScanAbilityConnectionTest, ScanAbilityConnectionTest_SendDismiss_0008, TestSize.Level2)
{
    ScanAbilityConnection connection(nullptr, nullptr);
    connection.SetDecisionCallback(MakeDecisionCallback(), "session-4");

    sptr<OHOS::Print::MockRemoteObject> remote = new OHOS::Print::MockRemoteObject();
    EXPECT_CALL(*remote, AddDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_CALL(*remote, SendRequest(
        static_cast<uint32_t>(ScanCertDialogCode::REGISTER_CALLBACK), _, _, _))
        .WillOnce(Return(ERR_NONE));
    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, remote, ERR_OK);

    EXPECT_CALL(*remote, SendRequest(static_cast<uint32_t>(ScanCertDialogCode::DISMISS), _, _, _))
        .WillOnce(Return(ERR_NONE));
    EXPECT_TRUE(connection.SendDismiss("session-4"));

    EXPECT_CALL(*remote, SendRequest(static_cast<uint32_t>(ScanCertDialogCode::DISMISS), _, _, _))
        .WillOnce(Return(ERR_INVALID_OPERATION));
    EXPECT_FALSE(connection.SendDismiss("session-4"));
}

}  // namespace Scan
}  // namespace OHOS
