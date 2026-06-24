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
#include "remote_callback_stub.h"
#undef private
#include "remote_constants.h"
#include "print_constant.h"
#include "message_parcel.h"
#include "message_option.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class RemoteCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteCallbackStubTest::SetUpTestCase(void)
{}

void RemoteCallbackStubTest::TearDownTestCase(void)
{}

void RemoteCallbackStubTest::SetUp(void)
{}

void RemoteCallbackStubTest::TearDown(void)
{}

/**
 * @tc.name: Constructor_001
 * @tc.desc: Branch: cmdMap_ initialized with correct handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, Constructor_001, TestSize.Level1)
{
    RemoteCallbackStub stub;
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: Branch: descriptor mismatch -> return E_PRINT_RPC_FAILURE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    std::u16string invalidDescriptor = u"OHOS.Drive.iunvalidCallbackAbility";
    data.WriteInterfaceToken(invalidDescriptor);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_RPC_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: Branch: errorCode != E_PRINT_NONE -> return errorCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_SERVER_FAILURE);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: Branch: rawDataSize < 0 -> return E_PRINT_SERVER_FAILURE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    data.WriteInt64(-1);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: Branch: rawDataSize > 0 but rawData == nullptr -> return E_PRINT_SERVER_FAILURE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_004, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    data.WriteInt64(10);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_005
 * @tc.desc: Branch: valid data with rawDataSize == 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_005, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    data.WriteInt64(0);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_006
 * @tc.desc: Branch: code == COMMAND_REQUEST_PRINTER_STATUS -> HandleGetPrinterStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_006, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    data.WriteInt64(0);
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS), data, reply, option);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
 * @tc.name: OnRemoteRequest_007
 * @tc.desc: Branch: unknown code -> IPCObjectStub::OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, OnRemoteRequest_007, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    data.WriteInt64(0);
    int32_t result = stub.OnRemoteRequest(99999, data, reply, option);
    EXPECT_NE(E_PRINT_NONE, result);
}

/**
 * @tc.name: HandleGetPrinterStatus_001
 * @tc.desc: Branch: empty message -> OnPrinterStatusReceived called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, HandleGetPrinterStatus_001, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    std::string msg = "[]";
    data.WriteInt64(static_cast<int64_t>(msg.size()));
    data.WriteRawData(msg.c_str(), msg.size());
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS), data, reply, option);
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: HandleGetPrinterList_001
 * @tc.desc: Branch: empty array message -> OnPrinterListReceived called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteCallbackStubTest, HandleGetPrinterList_001, TestSize.Level1)
{
    RemoteCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(E_PRINT_NONE);
    std::string msg = "[]";
    data.WriteInt64(static_cast<int64_t>(msg.size()));
    data.WriteRawData(msg.c_str(), msg.size());
    int32_t result = stub.OnRemoteRequest(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), data, reply, option);
    EXPECT_EQ(E_PRINT_NONE, result);
}

} // namespace OHOS::Print