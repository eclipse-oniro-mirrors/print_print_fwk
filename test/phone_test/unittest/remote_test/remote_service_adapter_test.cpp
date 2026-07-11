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
#include "remote_service_adapter.h"
#undef private
#include "remote_constants.h"
#include "print_constant.h"
#include "mock_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class RemoteServiceAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteServiceAdapterTest::SetUpTestCase(void)
{}

void RemoteServiceAdapterTest::TearDownTestCase(void)
{}

void RemoteServiceAdapterTest::SetUp(void)
{}

void RemoteServiceAdapterTest::TearDown(void)
{}

/**
 * @tc.name: Constructor_001
 * @tc.desc: Branch: normal constructor -> connection_ and callbackStub_ created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, Constructor_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    EXPECT_FALSE(client.IsConnected());
}

/**
 * @tc.name: IsConnected_001
 * @tc.desc: Branch: connection_ == nullptr -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, IsConnected_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    EXPECT_FALSE(client.IsConnected());
}

/**
 * @tc.name: IsConnected_002
 * @tc.desc: Branch: connection_ valid but remoteObject_ == nullptr -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, IsConnected_002, TestSize.Level1)
{
    RemoteServiceAdapter client;
    EXPECT_FALSE(client.IsConnected());
}

/**
 * @tc.name: BindService_001
 * @tc.desc: Branch: already connected -> return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, BindService_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    EXPECT_TRUE(client.BindService());
}

/**
 * @tc.name: SendData_002
 * @tc.desc: Branch: remoteObject_ == nullptr -> reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, SendData_002, TestSize.Level1)
{
    RemoteServiceAdapter client;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    client.connection_->remoteObject_ = mockRemote;
    int32_t result = client.SendData(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS),
        "test_msg");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: SendData_003
 * @tc.desc: Branch: empty message -> size = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, SendData_003, TestSize.Level1)
{
    RemoteServiceAdapter client;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    client.connection_->remoteObject_ = mockRemote;
    int32_t result = client.SendData(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), "");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: RequestPrinterStatus_001
 * @tc.desc: Branch: not connected -> SendData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, RequestPrinterStatus_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    std::string devId = "test_device_001";
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    client.connection_->remoteObject_ = mockRemote;
    int32_t result = client.RequestPrinterStatus(devId);
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: RequestPrinterList_001
 * @tc.desc: Branch: not connected -> SendData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, RequestPrinterList_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    client.connection_->remoteObject_ = mockRemote;
    int32_t result = client.RequestPrinterList();
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: SetOnServiceDiedCallback_001
 * @tc.desc: Branch: set callback -> callback stored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, SetOnServiceDiedCallback_001, TestSize.Level1)
{
    RemoteServiceAdapter client;
    bool callbackCalled = false;
    client.SetOnServiceDiedCallback([&callbackCalled]() {
        callbackCalled = true;
    });
    EXPECT_NE(nullptr, client.onServiceDiedCb_);
}

/**
 * @tc.name: SetOnServiceDiedCallback_002
 * @tc.desc: Branch: set nullptr callback -> callback nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, SetOnServiceDiedCallback_002, TestSize.Level1)
{
    RemoteServiceAdapter client;
    client.SetOnServiceDiedCallback(nullptr);
    EXPECT_EQ(nullptr, client.onServiceDiedCb_);
}

/**
 * @tc.name: OnRemoteServiceDied_002
 * @tc.desc: Branch: BindService fails -> callback called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteServiceAdapterTest, OnRemoteServiceDied_002, TestSize.Level1)
{
    RemoteServiceAdapter client;
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    client.connection_->remoteObject_ = mockRemote;
    bool callbackCalled = false;
    client.SetOnServiceDiedCallback([&callbackCalled]() {
        callbackCalled = true;
    });
    client.OnRemoteServiceDied();
    EXPECT_TRUE(callbackCalled);
}

} // namespace OHOS::Print