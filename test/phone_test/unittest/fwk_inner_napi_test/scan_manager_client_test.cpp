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
#include <memory>
#define private public
#include "scan_manager_client.h"
#undef private

#include "scan_constant.h"
#include "mock_scan_manager_client.h"
#include "mock_scan_service.h"
#include "mock_scan_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Scan {
class ScanManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void ScanManagerClientTest::SetUpTestCase(void)
{}

void ScanManagerClientTest::TearDownTestCase(void)
{}

void ScanManagerClientTest::SetUp(void)
{}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_InitScan_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    int32_t ret = mockClient->InitScan();
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_InitScan_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    EXPECT_CALL(*mockService, InitScan()).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->InitScan();
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_ExitScan_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    int32_t ret = mockClient->ExitScan();
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_ExitScan_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    EXPECT_CALL(*mockService, ExitScan()).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->ExitScan();
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScannerList_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    int32_t ret = mockClient->GetScannerList();
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScannerList_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    EXPECT_CALL(*mockService, GetScannerList()).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->GetScannerList();
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_OpenScanner_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    int32_t ret = mockClient->OpenScanner(scannerId);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_OpenScanner_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    EXPECT_CALL(*mockService, OpenScanner(_)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->OpenScanner(scannerId);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_CloseScanner_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    int32_t ret = mockClient->CloseScanner(scannerId);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_CloseScanner_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    EXPECT_CALL(*mockService, CloseScanner(_)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->CloseScanner(scannerId);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanOptionDesc_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    int32_t optionIndex = 0;
    ScanOptionDescriptor desc;
    int32_t ret = mockClient->GetScanOptionDesc(scannerId, optionIndex, desc);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanOptionDesc_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    int32_t optionIndex = 0;
    ScanOptionDescriptor desc;
    EXPECT_CALL(*mockService, GetScanOptionDesc(_, _, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->GetScanOptionDesc(scannerId, optionIndex, desc);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_OpScanOptionValue_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    int32_t optionIndex = 0;
    ScanOptionOpType op = SCAN_ACTION_GET_VALUE;
    ScanOptionValue value;
    int32_t ret = mockClient->OpScanOptionValue(scannerId, optionIndex, op, value);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_OpScanOptionValue_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    int32_t optionIndex = 0;
    ScanOptionOpType op = SCAN_ACTION_GET_VALUE;
    ScanOptionValue value;
    EXPECT_CALL(*mockService, OpScanOptionValue(_, _, _, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->OpScanOptionValue(scannerId, optionIndex, op, value);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanParameters_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    ScanParameters para;
    int32_t ret = mockClient->GetScanParameters(scannerId, para);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanParameters_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    ScanParameters para;
    EXPECT_CALL(*mockService, GetScanParameters(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->GetScanParameters(scannerId, para);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_StartScan_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    bool batchMode = false;
    int32_t ret = mockClient->StartScan(scannerId, batchMode);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_StartScan_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    bool batchMode = false;
    EXPECT_CALL(*mockService, StartScan(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->StartScan(scannerId, batchMode);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_CancelScan_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    int32_t ret = mockClient->CancelScan(scannerId);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_CancelScan_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    EXPECT_CALL(*mockService, CancelScan(_)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->CancelScan(scannerId);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_On_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string taskId = "test_task";
    std::string type = "test_type";
    sptr<IScanCallback> listener = nullptr;
    int32_t ret = mockClient->On(taskId, type, listener);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_On_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string taskId = "test_task";
    std::string type = "test_type";
    sptr<IScanCallback> listener = nullptr;
    EXPECT_CALL(*mockService, On(_, _, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->On(taskId, type, listener);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_Off_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string taskId = "test_task";
    std::string type = "test_type";
    int32_t ret = mockClient->Off(taskId, type);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_Off_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string taskId = "test_task";
    std::string type = "test_type";
    EXPECT_CALL(*mockService, Off(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->Off(taskId, type);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanProgress_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string scannerId = "test_scanner";
    ScanProgress prog;
    int32_t ret = mockClient->GetScanProgress(scannerId, prog);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetScanProgress_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string scannerId = "test_scanner";
    ScanProgress prog;
    EXPECT_CALL(*mockService, GetScanProgress(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->GetScanProgress(scannerId, prog);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_AddScanner_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string serialNumber = "test_serial";
    std::string discoverMode = "TCP";
    int32_t ret = mockClient->AddScanner(serialNumber, discoverMode);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_AddScanner_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string serialNumber = "test_serial";
    std::string discoverMode = "TCP";
    EXPECT_CALL(*mockService, AddScanner(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->AddScanner(serialNumber, discoverMode);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_DeleteScanner_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::string serialNumber = "test_serial";
    std::string discoverMode = "TCP";
    int32_t ret = mockClient->DeleteScanner(serialNumber, discoverMode);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_DeleteScanner_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::string serialNumber = "test_serial";
    std::string discoverMode = "TCP";
    EXPECT_CALL(*mockService, DeleteScanner(_, _)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->DeleteScanner(serialNumber, discoverMode);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetAddedScanner_Failure, TestSize.Level1)
{
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(nullptr));
    std::vector<ScanDeviceInfo> allAddedScanner;
    int32_t ret = mockClient->GetAddedScanner(allAddedScanner);
    EXPECT_EQ(ret, E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanManagerClientTest, ScanManagerClientTest_GetAddedScanner_Success, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    sptr<MockScanManagerClient> mockClient = new MockScanManagerClient();
    EXPECT_CALL(*mockClient, GetScanServiceProxy())
        .WillRepeatedly(Return(mockService));
    std::vector<ScanDeviceInfo> allAddedScanner;
    EXPECT_CALL(*mockService, GetAddedScanner(_)).WillOnce(Return(E_SCAN_NONE));
    int32_t ret = mockClient->GetAddedScanner(allAddedScanner);
    EXPECT_EQ(ret, E_SCAN_NONE);
}

HWTEST_F(ScanManagerClientTest, LoadServerSuccess_NullRemoteObject, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    client->ready_ = false;
    client->LoadServerSuccess(nullptr);
    EXPECT_EQ(client->scanServiceProxy_, nullptr);
    EXPECT_TRUE(client->ready_);
}

HWTEST_F(ScanManagerClientTest, LoadServerSuccess_WithRemoteObject, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanRemoteObject> obj = new MockScanRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillOnce(DoAll(SaveArg<0>(&dr), Return(true)));
    client->LoadServerSuccess(obj);
    EXPECT_NE(dr, nullptr);
    EXPECT_TRUE(client->ready_);
}

HWTEST_F(ScanManagerClientTest, LoadServerSuccess_DeathRecipientRecreated, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    client->deathRecipient_ = nullptr;
    sptr<MockScanRemoteObject> obj = new MockScanRemoteObject();
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillOnce(Return(true));
    client->LoadServerSuccess(obj);
    EXPECT_NE(client->deathRecipient_, nullptr);
    EXPECT_TRUE(client->ready_);
}

HWTEST_F(ScanManagerClientTest, LoadServerFail_ClearsProxy, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanService> mockService = new MockScanService();
    client->scanServiceProxy_ = mockService;
    client->ready_ = false;
    client->LoadServerFail();
    EXPECT_EQ(client->scanServiceProxy_, nullptr);
    EXPECT_TRUE(client->ready_);
}

HWTEST_F(ScanManagerClientTest, OnRemoteSaDied_NullObject, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanService> mockService = new MockScanService();
    client->scanServiceProxy_ = mockService;
    wptr<IRemoteObject> nullObj;
    client->OnRemoteSaDied(nullObj);
    EXPECT_NE(client->scanServiceProxy_, nullptr);
}

HWTEST_F(ScanManagerClientTest, OnRemoteSaDied_NullProxy, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    client->scanServiceProxy_ = nullptr;
    sptr<MockScanRemoteObject> obj = new MockScanRemoteObject();
    wptr<IRemoteObject> wpObj(obj);
    client->OnRemoteSaDied(wpObj);
    EXPECT_EQ(client->scanServiceProxy_, nullptr);
}

HWTEST_F(ScanManagerClientTest, OnRemoteSaDied_MatchingObject, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanService> mockService = new MockScanService();
    client->scanServiceProxy_ = mockService;
    client->deathRecipient_ = new ScanSaDeathRecipient();
    sptr<IRemoteObject> serviceRemote = mockService->AsObject();
    ASSERT_NE(serviceRemote, nullptr);
    wptr<IRemoteObject> wpObj(serviceRemote);
    client->OnRemoteSaDied(wpObj);
    EXPECT_EQ(client->scanServiceProxy_, nullptr);
    EXPECT_EQ(client->deathRecipient_, nullptr);
}

HWTEST_F(ScanManagerClientTest, OnRemoteSaDied_NonMatchingObject, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanService> mockService = new MockScanService();
    client->scanServiceProxy_ = mockService;
    client->deathRecipient_ = new ScanSaDeathRecipient();
    sptr<MockScanRemoteObject> otherObj = new MockScanRemoteObject();
    wptr<IRemoteObject> wpOther(otherObj);
    client->OnRemoteSaDied(wpOther);
    EXPECT_NE(client->scanServiceProxy_, nullptr);
    EXPECT_NE(client->deathRecipient_, nullptr);
}

HWTEST_F(ScanManagerClientTest, Destructor_WithProxy, TestSize.Level1)
{
    sptr<MockScanService> mockService = new MockScanService();
    {
        sptr<ScanManagerClient> client = new ScanManagerClient();
        client->scanServiceProxy_ = mockService;
    }
    EXPECT_NE(mockService, nullptr);
}

HWTEST_F(ScanManagerClientTest, GetScanServiceProxy_CachedProxy, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    sptr<MockScanService> mockService = new MockScanService();
    client->scanServiceProxy_ = mockService;
    auto result = client->GetScanServiceProxy();
    EXPECT_EQ(result, sptr<IScanService>(mockService));
}

HWTEST_F(ScanManagerClientTest, LoadScanService_SamgrUnavailable, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    client->ready_ = true;
    bool result = client->LoadScanService();
    EXPECT_FALSE(result);
    EXPECT_FALSE(client->ready_);
    EXPECT_EQ(client->scanServiceProxy_, nullptr);
}

HWTEST_F(ScanManagerClientTest, LoadScanService_ReadyStateReset, TestSize.Level1)
{
    sptr<ScanManagerClient> client = new ScanManagerClient();
    client->ready_ = true;
    client->LoadScanService();
    EXPECT_FALSE(client->ready_);
}
}  // namespace OHOS::Scan