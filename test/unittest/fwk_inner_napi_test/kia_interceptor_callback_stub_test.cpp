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
#include "mock_kia_interceptor_callback_stub.h"
#include "iremote_broker.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class KiaInterceptorCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void KiaInterceptorCallbackStubTest::SetUpTestCase(void)
{}

void KiaInterceptorCallbackStubTest::TearDownTestCase(void)
{}

/**
 * @tc.name: HandleCheckRejectEventTest_001
 * @tc.desc: Test HandleCheckRejectEvent with callback returning true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT);
    int32_t testPid = 123;
    std::string testCallerAppId = "com.example.testapp";
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testPid));
    EXPECT_TRUE(data.WriteString(testCallerAppId));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(testPid, testCallerAppId))
        .WillOnce(Return(true));
    
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: HandleCheckRejectEventTest_002
 * @tc.desc: Test HandleCheckRejectEvent with callback returning false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT);
    int32_t testPid = 456;
    std::string testCallerAppId = "com.example.testapp2";
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testPid));
    EXPECT_TRUE(data.WriteString(testCallerAppId));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(testPid, testCallerAppId))
        .WillOnce(Return(false));
    
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: HandleCheckRejectEventTest_004
 * @tc.desc: Test HandleCheckRejectEvent with invalid command code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = 99999;  // Invalid code
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    int32_t result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, E_PRINT_NONE);
}

/**
 * @tc.name: HandleCheckRejectEventTest_005
 * @tc.desc: Test HandleCheckRejectEvent with empty callerAppId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT);
    int32_t testPid = 789;
    std::string testCallerAppId = "";
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testPid));
    EXPECT_TRUE(data.WriteString(testCallerAppId));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(testPid, testCallerAppId))
        .WillOnce(Return(true));
    
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: HandleCheckRejectEventTest_006
 * @tc.desc: Test HandleCheckRejectEvent with negative pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT);
    int32_t testPid = -1;
    std::string testCallerAppId = "com.example.testapp";
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testPid));
    EXPECT_TRUE(data.WriteString(testCallerAppId));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(testPid, testCallerAppId))
        .WillOnce(Return(false));
    
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: HandleCheckRejectEventTest_007
 * @tc.desc: Test HandleCheckRejectEvent with very long callerAppId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KiaInterceptorCallbackStubTest, HandleCheckRejectEventTest_007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT);
    int32_t testPid = 999;
    std::string testCallerAppId(1000, 'x');
    
    EXPECT_TRUE(data.WriteInterfaceToken(IKiaInterceptorCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testPid));
    EXPECT_TRUE(data.WriteString(testCallerAppId));
    
    auto callback = std::make_shared<MockKiaInterceptorCallbackStub>();
    EXPECT_NE(callback, nullptr);
    
    EXPECT_CALL(*callback, OnCheckPrintJobNeedReject(testPid, testCallerAppId))
        .WillOnce(Return(true));
    
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

}  // namespace Print
}  // namespace OHOS
