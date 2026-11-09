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
#include "watermark_callback_proxy.h"
#include "iwatermark_callback.h"
#include "mock_remote_object.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class WatermarkCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    const static int testFd_ = 1;
};

void WatermarkCallbackProxyTest::SetUpTestCase(void)
{
}

void WatermarkCallbackProxyTest::TearDownTestCase(void)
{
}

void WatermarkCallbackProxyTest::SetUp(void)
{
}

void WatermarkCallbackProxyTest::TearDown(void)
{
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_001
 * @tc.desc: Test OnCallback with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_001, TestSize.Level1)
{
    auto proxy = std::make_shared<WatermarkCallbackProxy>(nullptr);
    ASSERT_NE(proxy, nullptr);

    EXPECT_NO_FATAL_FAILURE(proxy->OnCallback("test_job", testFd_));
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);
    EXPECT_CALL(*mockRemote, SendRequest(WATERMARK_CALLBACK_ADD, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_NONE));
    auto validProxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(validProxy, nullptr);
    validProxy->OnCallback("test_job_after_null", testFd_);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_002
 * @tc.desc: Test OnCallback with valid remote object - success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_002, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    uint32_t capturedCode = 0;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedCode](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            capturedCode = code;
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_001", testFd_);
    EXPECT_EQ(capturedCode, static_cast<uint32_t>(WATERMARK_CALLBACK_ADD));
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_003
 * @tc.desc: Test OnCallback when SendRequest fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_003, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    int32_t capturedRet = ERR_NONE;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedRet](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            capturedRet = ERR_DEAD_OBJECT;
            return ERR_DEAD_OBJECT;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_003", testFd_);
    EXPECT_EQ(capturedRet, ERR_DEAD_OBJECT);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_004
 * @tc.desc: Test OnCallback with empty jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_004, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    std::string capturedJobId = "UNSET";
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedJobId](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            data.ReadInterfaceToken();  // Skip interface token
            capturedJobId = data.ReadString();
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("", testFd_);
    EXPECT_EQ(capturedJobId, "");
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_005
 * @tc.desc: Test OnCallback with very long jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_005, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    std::string longJobId(1000, 'x');
    std::string capturedJobId;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedJobId](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            data.ReadInterfaceToken();
            capturedJobId = data.ReadString();
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback(longJobId, testFd_);
    EXPECT_EQ(capturedJobId, longJobId);
    EXPECT_EQ(capturedJobId.size(), 1000);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_006
 * @tc.desc: Test OnCallback verifies correct command code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_006, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    uint32_t capturedCode = 0;
    EXPECT_CALL(*mockRemote, SendRequest(WATERMARK_CALLBACK_ADD, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedCode](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            capturedCode = code;
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_code", testFd_);
    EXPECT_EQ(capturedCode, static_cast<uint32_t>(WATERMARK_CALLBACK_ADD));
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_007
 * @tc.desc: Test OnCallback multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_007, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    int callCount = 0;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke([&callCount](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            callCount++;
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("job_1", testFd_);
    proxy->OnCallback("job_2", testFd_);
    proxy->OnCallback("job_3", testFd_);
    EXPECT_EQ(callCount, 3);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_008
 * @tc.desc: Test OnCallback when remote dies during call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_008, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    bool sendRequestCalled = false;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&sendRequestCalled](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            sendRequestCalled = true;
            return ERR_DEAD_OBJECT;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_dead", testFd_);
    EXPECT_TRUE(sendRequestCalled);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_009
 * @tc.desc: Test OnCallback with IPC timeout error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_009, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    int32_t capturedRet = ERR_NONE;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedRet](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            capturedRet = ERR_TIMED_OUT;
            return ERR_TIMED_OUT;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_timeout", testFd_);
    EXPECT_EQ(capturedRet, ERR_TIMED_OUT);
}

/**
 * @tc.name: WatermarkCallbackProxyTest_OnCallback_010
 * @tc.desc: Test OnCallback uses async message option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackProxyTest, WatermarkCallbackProxyTest_OnCallback_010, TestSize.Level1)
{
    auto mockRemote = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(mockRemote, nullptr);

    int capturedFlags = -1;
    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&capturedFlags](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            capturedFlags = option.GetFlags();
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    ASSERT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_async", testFd_);
    EXPECT_EQ(capturedFlags, MessageOption::TF_ASYNC);
}

}  // namespace Print
}  // namespace OHOS
