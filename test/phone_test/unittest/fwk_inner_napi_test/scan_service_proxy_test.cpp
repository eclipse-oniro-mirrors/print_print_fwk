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
#include "scan_service_proxy.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "scanner_info.h"
#include "mock_scan_remote_object.h"
#include "mock_scan_service.h"
#include "mock_scan_callback_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Scan {
class ScanServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    void SetupSuccessEnv()
    {
        obj_ = new MockScanRemoteObject();
        proxy_ = std::make_shared<ScanServiceProxy>(obj_);
        service_ = std::make_shared<MockScanService>();
        EXPECT_NE(obj_, nullptr);
        EXPECT_NE(proxy_, nullptr);
        EXPECT_NE(service_, nullptr);
        EXPECT_CALL(*obj_, SendRequest(_, _, _, _)).Times(1);
        ON_CALL(*obj_, SendRequest)
            .WillByDefault([this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                service_->OnRemoteRequest(code, data, reply, option);
                return ERR_NONE;
            });
    }

    void SetupRpcErrorEnv()
    {
        obj_ = new MockScanRemoteObject();
        proxy_ = std::make_shared<ScanServiceProxy>(obj_);
        EXPECT_NE(obj_, nullptr);
        EXPECT_NE(proxy_, nullptr);
        EXPECT_CALL(*obj_, SendRequest(_, _, _, _)).Times(1).WillOnce(Return(ERR_TRANSACTION_FAILED));
    }

    void SetupRemoteNullEnv()
    {
        proxy_ = std::make_shared<ScanServiceProxy>(nullptr);
        EXPECT_NE(proxy_, nullptr);
    }

    void SetupProxyOnlyEnv()
    {
        obj_ = new MockScanRemoteObject();
        proxy_ = std::make_shared<ScanServiceProxy>(obj_);
        EXPECT_NE(obj_, nullptr);
        EXPECT_NE(proxy_, nullptr);
    }

    sptr<MockScanRemoteObject> obj_;
    std::shared_ptr<ScanServiceProxy> proxy_;
    std::shared_ptr<MockScanService> service_;
};

void ScanServiceProxyTest::SetUpTestCase(void)
{}

void ScanServiceProxyTest::TearDownTestCase(void)
{}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetResult_RpcFailure, TestSize.Level1)
{
    SetupProxyOnlyEnv();
    MessageParcel reply;
    EXPECT_EQ(proxy_->GetResult(1, reply), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetResult_ReadInt32Fail, TestSize.Level1)
{
    SetupProxyOnlyEnv();
    MessageParcel reply;
    EXPECT_EQ(proxy_->GetResult(ERR_NONE, reply), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_InitScan_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, InitScan()).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->InitScan(), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_InitScan_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->InitScan(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_InitScan_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->InitScan(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExitScan_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, ExitScan()).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->ExitScan(), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExitScan_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->ExitScan(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExitScan_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->ExitScan(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScannerList_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, GetScannerList()).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->GetScannerList(), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScannerList_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->GetScannerList(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScannerList_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->GetScannerList(), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpenScanner_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, OpenScanner(_)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->OpenScanner("test_scanner"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpenScanner_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->OpenScanner("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpenScanner_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->OpenScanner("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CloseScanner_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, CloseScanner(_)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->CloseScanner("test_scanner"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CloseScanner_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->CloseScanner("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CloseScanner_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->CloseScanner("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanOptionDesc_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    ScanOptionDescriptor desc;
    EXPECT_CALL(*service_, GetScanOptionDesc(_, _, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->GetScanOptionDesc("test_scanner", 0, desc), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanOptionDesc_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    ScanOptionDescriptor desc;
    EXPECT_EQ(proxy_->GetScanOptionDesc("test_scanner", 0, desc), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanOptionDesc_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    ScanOptionDescriptor desc;
    EXPECT_EQ(proxy_->GetScanOptionDesc("test_scanner", 0, desc), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpScanOptionValue_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    ScanOptionValue value;
    EXPECT_CALL(*service_, OpScanOptionValue(_, _, _, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->OpScanOptionValue("test_scanner", 0, SCAN_ACTION_GET_VALUE, value), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpScanOptionValue_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    ScanOptionValue value;
    EXPECT_EQ(proxy_->OpScanOptionValue("test_scanner", 0, SCAN_ACTION_GET_VALUE, value), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_OpScanOptionValue_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    ScanOptionValue value;
    EXPECT_EQ(proxy_->OpScanOptionValue("test_scanner", 0, SCAN_ACTION_GET_VALUE, value), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanParameters_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    ScanParameters para;
    EXPECT_CALL(*service_, GetScanParameters(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->GetScanParameters("test_scanner", para), E_SCAN_INVALID_PARAMETER);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanParameters_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    ScanParameters para;
    EXPECT_EQ(proxy_->GetScanParameters("test_scanner", para), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanParameters_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    ScanParameters para;
    EXPECT_EQ(proxy_->GetScanParameters("test_scanner", para), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_StartScan_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, StartScan(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->StartScan("test_scanner", false), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_StartScan_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->StartScan("test_scanner", false), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_StartScan_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->StartScan("test_scanner", false), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CancelScan_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, CancelScan(_)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->CancelScan("test_scanner"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CancelScan_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->CancelScan("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_CancelScan_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->CancelScan("test_scanner"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_On_ListenerNull, TestSize.Level1)
{
    SetupProxyOnlyEnv();
    EXPECT_EQ(proxy_->On("test_task", "test_type", nullptr), E_SCAN_INVALID_PARAMETER);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_On_TypeEmpty, TestSize.Level1)
{
    SetupProxyOnlyEnv();
    sptr<IScanCallback> listener = new MockScanCallbackStub();
    EXPECT_NE(listener, nullptr);
    EXPECT_EQ(proxy_->On("test_task", "", listener), E_SCAN_INVALID_PARAMETER);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_On_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    sptr<IScanCallback> listener = new MockScanCallbackStub();
    EXPECT_NE(listener, nullptr);
    EXPECT_CALL(*service_, On(_, _, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->On("test_task", "test_type", listener), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_On_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    sptr<IScanCallback> listener = new MockScanCallbackStub();
    EXPECT_NE(listener, nullptr);
    EXPECT_EQ(proxy_->On("test_task", "test_type", listener), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_On_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    sptr<IScanCallback> listener = new MockScanCallbackStub();
    EXPECT_NE(listener, nullptr);
    EXPECT_EQ(proxy_->On("test_task", "test_type", listener), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_Off_TypeEmpty, TestSize.Level1)
{
    SetupProxyOnlyEnv();
    EXPECT_EQ(proxy_->Off("test_task", ""), E_SCAN_INVALID_PARAMETER);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_Off_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, Off(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->Off("test_task", "test_type"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_Off_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->Off("test_task", "test_type"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_Off_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->Off("test_task", "test_type"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanProgress_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    ScanProgress prog;
    EXPECT_CALL(*service_, GetScanProgress(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_NE(proxy_->GetScanProgress("test_scanner", prog), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanProgress_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    ScanProgress prog;
    EXPECT_EQ(proxy_->GetScanProgress("test_scanner", prog), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetScanProgress_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    ScanProgress prog;
    EXPECT_EQ(proxy_->GetScanProgress("test_scanner", prog), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_AddScanner_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, AddScanner(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->AddScanner("test_serial", "TCP"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_AddScanner_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->AddScanner("test_serial", "TCP"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_AddScanner_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->AddScanner("test_serial", "TCP"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_DeleteScanner_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    EXPECT_CALL(*service_, DeleteScanner(_, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->DeleteScanner("test_serial", "TCP"), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_DeleteScanner_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    EXPECT_EQ(proxy_->DeleteScanner("test_serial", "TCP"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_DeleteScanner_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    EXPECT_EQ(proxy_->DeleteScanner("test_serial", "TCP"), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetAddedScanner_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    std::vector<ScanDeviceInfo> allAddedScanner;
    EXPECT_CALL(*service_, GetAddedScanner(_)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_EQ(proxy_->GetAddedScanner(allAddedScanner), E_SCAN_NONE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetAddedScanner_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    std::vector<ScanDeviceInfo> allAddedScanner;
    EXPECT_EQ(proxy_->GetAddedScanner(allAddedScanner), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_GetAddedScanner_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    std::vector<ScanDeviceInfo> allAddedScanner;
    EXPECT_EQ(proxy_->GetAddedScanner(allAddedScanner), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExportScanPicture_Success, TestSize.Level1)
{
    SetupSuccessEnv();
    std::vector<int32_t> pictureFdList;
    std::vector<int32_t> exportedFdList;
    EXPECT_CALL(*service_, ExportScanPicture(_, _, _, _)).Times(Exactly(1)).WillOnce(Return(E_SCAN_NONE));
    EXPECT_NE(proxy_->ExportScanPicture("test_scanner", pictureFdList, 0, exportedFdList), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExportScanPicture_RemoteNull, TestSize.Level1)
{
    SetupRemoteNullEnv();
    std::vector<int32_t> pictureFdList;
    std::vector<int32_t> exportedFdList;
    EXPECT_EQ(proxy_->ExportScanPicture("test_scanner", pictureFdList, 0, exportedFdList), E_SCAN_RPC_FAILURE);
}

HWTEST_F(ScanServiceProxyTest, ScanServiceProxyTest_ExportScanPicture_RpcError, TestSize.Level1)
{
    SetupRpcErrorEnv();
    std::vector<int32_t> pictureFdList;
    std::vector<int32_t> exportedFdList;
    EXPECT_EQ(proxy_->ExportScanPicture("test_scanner", pictureFdList, 0, exportedFdList), E_SCAN_RPC_FAILURE);
}
}  // namespace OHOS::Scan
