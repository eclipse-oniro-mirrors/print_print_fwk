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
#include "mock_watermark_callback_stub.h"
#include "iremote_broker.h"
#include "iwatermark_callback.h"
#include "print_constant.h"
#include "print_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class WatermarkCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    const static int testFd_ = 1;
};

void WatermarkCallbackStubTest::SetUpTestCase(void)
{
}

void WatermarkCallbackStubTest::TearDownTestCase(void)
{
}

void WatermarkCallbackStubTest::SetUp(void)
{
}

void WatermarkCallbackStubTest::TearDown(void)
{
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_001
 * @tc.desc: Test OnRemoteRequest with invalid interface token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_002
 * @tc.desc: Test OnRemoteRequest with unknown command code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD + 100);  // Unknown code

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_003
 * @tc.desc: Test OnRemoteRequest with valid callback - success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    std::string testJobId = "test_job_001";

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteFileDescriptor(testFd_));

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(testJobId, _)).Times(1);

    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_004
 * @tc.desc: Test OnRemoteRequest with valid callback - different jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    std::string testJobId = "test_job_002";

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteFileDescriptor(testFd_));

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(testJobId, _)).Times(1);

    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_005
 * @tc.desc: Test OnRemoteRequest with empty jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    std::string testJobId = "";  // Empty job ID

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteFileDescriptor(testFd_));

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(testJobId, _)).Times(1);

    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}


/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_008
 * @tc.desc: Test OnRemoteRequest with missing jobId in data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_008, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    // Missing jobId and fd

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);

    // Missing jobId and fd data causes ReadFileDescriptor to return invalid fd (<0)
    // HandleAddWatermarkEvent returns false, OnRemoteRequest returns E_PRINT_SERVER_FAILURE
    int32_t result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_009
 * @tc.desc: Test OnRemoteRequest with very long jobId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_009, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    std::string testJobId(1000, 'x');  // 1000 character jobId

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteFileDescriptor(testFd_));

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(testJobId, _)).Times(1);

    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

/**
 * @tc.name: WatermarkCallbackStubTest_OnRemoteRequest_010
 * @tc.desc: Test OnRemoteRequest with async option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WatermarkCallbackStubTest, WatermarkCallbackStubTest_OnRemoteRequest_010, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);  // Async option
    uint32_t code = static_cast<uint32_t>(WATERMARK_CALLBACK_ADD);

    std::string testJobId = "test_job_async";

    EXPECT_TRUE(data.WriteInterfaceToken(IWatermarkCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteFileDescriptor(testFd_));

    auto callback = std::make_shared<MockWatermarkCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(testJobId, _)).Times(1);

    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

}  // namespace Print
}  // namespace OHOS
