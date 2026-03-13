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
#include <unistd.h>
#include <string>
#include "kia_interceptor_callback_proxy.h"
#include "ikia_interceptor_callback.h"
#include "mock_remote_object.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class KiaInterceptorCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void KiaInterceptorCallbackProxyTest::SetUpTestCase(void)
{
}

void KiaInterceptorCallbackProxyTest::TearDownTestCase(void)
{
}

void KiaInterceptorCallbackProxyTest::SetUp(void)
{
}

void KiaInterceptorCallbackProxyTest::TearDown(void)
{
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_001
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_001, TestSize.Level1)
{
    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(nullptr);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "com.example.app"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_002
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with valid remote object - success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_002, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_NONE));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "com.example.app"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_003
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest when SendRequest fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_003, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_DEAD_OBJECT));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "com.example.app"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_004
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with empty callerAppId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_004, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            data.ReadInterfaceToken();  // Skip interface token
            std::string callerAppId = data.ReadString();
            EXPECT_EQ(callerAppId, "");
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, ""));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_005
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with very long callerAppId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_005, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    std::string longAppId(1000, 'x');

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_NONE));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, longAppId));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_006
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest verifies correct command code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_006, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            EXPECT_EQ(code, static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT));
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "test_app_id"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_007
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with remote returning true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_007, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteBool(true);
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_TRUE(proxy->OnCheckPrintJobNeedReject(123, "test_app_id"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_008
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest when remote dies during call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_008, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_DEAD_OBJECT));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "test_app_id"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_009
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest with IPC timeout error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_009, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_TIMED_OUT));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "test_app_id"));
}

/**
 * @tc.name: OnCheckPrintJobNeedRejectTest_010
 * @tc.desc: Test OnCheckPrintJobNeedRejectTest uses sync message option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackProxyTest, OnCheckPrintJobNeedRejectTest_010, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            EXPECT_EQ(option.GetFlags(), MessageOption::TF_SYNC);
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<KiaInterceptorCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->OnCheckPrintJobNeedReject(123, "test_app_id"));
}

}  // namespace Print
}  // namespace OHOS
