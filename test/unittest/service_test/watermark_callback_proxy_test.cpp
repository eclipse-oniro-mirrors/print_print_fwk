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
    EXPECT_NE(proxy, nullptr);

    // Should not crash with null remote
    proxy->OnCallback("test_job", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_NONE));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_001", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_DEAD_OBJECT));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    // Should not crash when SendRequest fails
    proxy->OnCallback("test_job_003", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // Verify empty jobId is passed correctly
            data.ReadInterfaceToken();  // Skip interface token
            std::string jobId = data.ReadString();
            EXPECT_EQ(jobId, "");
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback("", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    std::string longJobId(1000, 'x');

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_NONE));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback(longJobId, testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(WATERMARK_CALLBACK_ADD, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            EXPECT_EQ(code, static_cast<uint32_t>(WATERMARK_CALLBACK_ADD));
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_code", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Return(ERR_NONE));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback("job_1", testFd_);
    proxy->OnCallback("job_2", testFd_);
    proxy->OnCallback("job_3", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_DEAD_OBJECT));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    // Should not crash when remote dies
    proxy->OnCallback("test_job_dead", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_TIMED_OUT));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    // Should not crash on timeout
    proxy->OnCallback("test_job_timeout", testFd_);
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
    EXPECT_NE(mockRemote, nullptr);

    EXPECT_CALL(*mockRemote, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // Verify async option is used
            EXPECT_EQ(option.GetFlags(), MessageOption::TF_ASYNC);
            return ERR_NONE;
        }));

    auto proxy = std::make_shared<WatermarkCallbackProxy>(mockRemote);
    EXPECT_NE(proxy, nullptr);

    proxy->OnCallback("test_job_async", testFd_);
}

}  // namespace Print
}  // namespace OHOS
