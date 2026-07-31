/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "mock_scan_callback_stub.h"
#include "iscan_callback.h"
#include "scan_constant.h"
#include "scanner_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Scan {
class ScanCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanCallbackStubTest::SetUpTestCase(void)
{}

void ScanCallbackStubTest::TearDownTestCase(void)
{}

HWTEST_F(ScanCallbackStubTest, OnRemoteRequest_WrongDescriptor, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE);
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanCallbackStubTest, OnRemoteRequest_UnknownCode, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = 100;
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

HWTEST_F(ScanCallbackStubTest, OnRemoteRequest_DeviceInfoEvent_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE);
    uint32_t state = 1;
    ScanDeviceInfo info;
    info.SetDeviceId("test_device");
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(state));
    EXPECT_TRUE(info.Marshalling(data));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(state, _)).Times(1).WillOnce(Return(true));
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

HWTEST_F(ScanCallbackStubTest, HandleDeviceInfoEvent_UnmarshallingNull, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE);
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(1));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_SERVER_FAILURE);
}

HWTEST_F(ScanCallbackStubTest, OnRemoteRequest_DeviceInfoSyncEvent_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_SYNC);
    uint32_t state = 2;
    ScanDeviceInfoSync info;
    info.SetDeviceId("test_sync_device");
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(state));
    EXPECT_TRUE(info.Marshalling(data));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallbackSync(state, _)).Times(1).WillOnce(Return(true));
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

HWTEST_F(ScanCallbackStubTest, HandleDeviceInfoSyncEvent_UnmarshallingNull, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_SYNC);
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(1));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_SERVER_FAILURE);
}

HWTEST_F(ScanCallbackStubTest, OnRemoteRequest_DeviceListEvent_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_LIST);
    int32_t infosSize = 1;
    ScanDeviceInfo info;
    info.SetDeviceId("test_device_list");
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(infosSize));
    EXPECT_TRUE(info.Marshalling(data));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnGetDevicesList(_)).Times(1).WillOnce(Return(true));
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_NONE);
    EXPECT_TRUE(reply.ReadBool());
}

HWTEST_F(ScanCallbackStubTest, HandleSendDeviceList_ExceedRange, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_LIST);
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(SCAN_MAX_COUNT + 1));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_SERVER_FAILURE);
}

HWTEST_F(ScanCallbackStubTest, HandleSendDeviceList_UnmarshallingNull, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_LIST);
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(1));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_SERVER_FAILURE);
}

HWTEST_F(ScanCallbackStubTest, HandleSendDeviceList_EmptyList, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(SCAN_CALLBACK_DEVICE_LIST);
    EXPECT_TRUE(data.WriteInterfaceToken(IScanCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(0));
    auto callback = std::make_shared<MockScanCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnGetDevicesList(_)).Times(1).WillOnce(Return(true));
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_SCAN_NONE);
}
}  // namespace OHOS::Scan