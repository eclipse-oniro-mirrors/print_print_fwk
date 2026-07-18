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
#include "iremote_object.h"
#include "ability_manager_adapter.h"
#include "print_constant.h"

using namespace testing;
using testing::ext::TestSize;

namespace OHOS {
namespace Print {

class MockAbilityMgrRemoteObject : public IRemoteObject {
public:
    MockAbilityMgrRemoteObject() : IRemoteObject(u"")
    {}
    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_CONST_METHOD0(IsProxyObject, bool());
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
};

class MockIAbilityConnection : public IAbilityConnection {
public:
    MockIAbilityConnection() : IAbilityConnection()
    {}
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD3(OnAbilityConnectDone,
        void(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode));
    MOCK_METHOD2(OnAbilityDisconnectDone, void(const AppExecFwk::ElementName &element, int resultCode));
};

class AbilityManagerAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityManagerAdapterTest::SetUpTestCase()
{}

void AbilityManagerAdapterTest::TearDownTestCase()
{}

void AbilityManagerAdapterTest::SetUp()
{}

void AbilityManagerAdapterTest::TearDown()
{
    AbilityManagerAdapter::GetInstance().proxy_ = nullptr;
    AbilityManagerAdapter::GetInstance().deathRecipient_ = nullptr;
}

HWTEST_F(AbilityManagerAdapterTest, Connect_CallSucceeds, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    ErrCode result = AbilityManagerAdapter::GetInstance().Connect();
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, StartAbility_CallSucceeds, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().StartAbility(want);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, GetAbilityManagerProxy_ReturnsNotNull, TestSize.Level1)
{
    auto proxy = AbilityManagerAdapter::GetInstance().GetAbilityManagerProxy();
    EXPECT_NE(proxy, nullptr);
}

HWTEST_F(AbilityManagerAdapterTest, DisconnectAbility_ErrorResponse, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    auto mockRemoteObj = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockRemoteObj, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(mockRemoteObj));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(E_PRINT_GENERIC_FAILURE);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    ErrCode result = AbilityManagerAdapter::GetInstance().DisconnectAbility(mockConnect);
    EXPECT_EQ(result, E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(AbilityManagerAdapterTest, ResetProxy_CallsRemoveDeathRecipient, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockDeathRecipient =
        sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AbilityManagerAdapter::AbilityMgrDeathRecipient());
    ASSERT_NE(mockDeathRecipient, nullptr);

    EXPECT_CALL(*mockProxy, RemoveDeathRecipient(::testing::_)).WillOnce(testing::Return(true));

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;
    AbilityManagerAdapter::GetInstance().deathRecipient_ = mockDeathRecipient;

    wptr<IRemoteObject> weakProxy = mockProxy;
    AbilityManagerAdapter::GetInstance().ResetProxy(weakProxy);

    EXPECT_EQ(AbilityManagerAdapter::GetInstance().proxy_, nullptr);
}

HWTEST_F(AbilityManagerAdapterTest, OnRemoteDied_CallsResetProxy, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockDeathRecipient =
        sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AbilityManagerAdapter::AbilityMgrDeathRecipient());
    ASSERT_NE(mockDeathRecipient, nullptr);

    EXPECT_CALL(*mockProxy, RemoveDeathRecipient(::testing::_)).WillOnce(testing::Return(true));

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;
    AbilityManagerAdapter::GetInstance().deathRecipient_ = mockDeathRecipient;

    AbilityManagerAdapter::AbilityMgrDeathRecipient recipient;
    wptr<IRemoteObject> weakProxy = mockProxy;
    recipient.OnRemoteDied(weakProxy);

    EXPECT_EQ(AbilityManagerAdapter::GetInstance().proxy_, nullptr);
}

HWTEST_F(AbilityManagerAdapterTest, DisconnectAbility_CallSucceeds, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    auto mockRemoteObj = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockRemoteObj, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(mockRemoteObj));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    ErrCode result = AbilityManagerAdapter::GetInstance().DisconnectAbility(mockConnect);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, StartAbility_SendRequestFails, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return E_PRINT_RPC_FAILURE;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().StartAbility(want);
    EXPECT_EQ(result, E_PRINT_RPC_FAILURE);
}

HWTEST_F(AbilityManagerAdapterTest, ConnectAbility_Success, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    auto mockRemoteObj = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockRemoteObj, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(mockRemoteObj));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().ConnectAbility(want, mockConnect, 0);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, ConnectAbilityWithExtensionType_Success, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    auto mockRemoteObj = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockRemoteObj, nullptr);

    auto mockCallerToken = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockCallerToken, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(mockRemoteObj));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().ConnectAbilityWithExtensionType(
        want, mockConnect, mockCallerToken, 0, AppExecFwk::ExtensionAbilityType::SERVICE);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, ConnectAbilityCommon_ConnectAsObjectIsNull, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            return NO_ERROR;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().ConnectAbilityWithExtensionType(
        want, mockConnect, nullptr, 0, AppExecFwk::ExtensionAbilityType::SERVICE);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(AbilityManagerAdapterTest, ConnectAbilityCommon_SendRequestFails, TestSize.Level1)
{
    auto mockProxy = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockProxy, nullptr);

    auto mockConnect = sptr<MockIAbilityConnection>(new (std::nothrow) MockIAbilityConnection());
    ASSERT_NE(mockConnect, nullptr);

    auto mockRemoteObj = sptr<MockAbilityMgrRemoteObject>(new (std::nothrow) MockAbilityMgrRemoteObject());
    ASSERT_NE(mockRemoteObj, nullptr);

    EXPECT_CALL(*mockConnect, AsObject()).WillOnce(testing::Return(mockRemoteObj));
    EXPECT_CALL(*mockProxy, SendRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return E_PRINT_RPC_FAILURE;
        });

    AbilityManagerAdapter::GetInstance().proxy_ = mockProxy;

    Want want;
    want.SetElementName("test.bundle", "test.ability");
    ErrCode result = AbilityManagerAdapter::GetInstance().ConnectAbilityWithExtensionType(
        want, mockConnect, nullptr, 0, AppExecFwk::ExtensionAbilityType::SERVICE);
    EXPECT_EQ(result, E_PRINT_RPC_FAILURE);
}

}  // namespace Print
}  // namespace OHOS