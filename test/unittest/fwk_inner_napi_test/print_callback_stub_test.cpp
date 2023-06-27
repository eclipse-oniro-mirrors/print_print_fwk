/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "mock_print_callback_stub.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_resolution.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintCallbackStubTest::SetUpTestCase(void) {}

void PrintCallbackStubTest::TearDownTestCase(void) {}

void PrintCallbackStubTest::SetUp(void) {}

void PrintCallbackStubTest::TearDown(void) {}


/**
 * @tc.name: PrintCallbackStubTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_TASK);

    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintServiceProxyTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_TASK + 100);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: PrintServiceProxyTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_TASK);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback()).Times(1);
    EXPECT_TRUE(static_cast<bool>(callback->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINTER);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;
    testInfo.SetPrinterId("printId-123");

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(_, _)).Times(1);
    ON_CALL(*callback, OnCallback).WillByDefault(
            [&testState, &testInfo](uint32_t state, const PrinterInfo &info) {
                 EXPECT_EQ(testState, state);
                 EXPECT_EQ(testInfo.GetPrinterId(), info.GetPrinterId());
                return true;
            });
    EXPECT_TRUE(static_cast<bool>(callback->OnRemoteRequest(code, data, reply, option)));
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: PrintServiceProxyTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINTER + 100);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: PrintServiceProxyTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINTER);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;

    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintServiceProxyTest_0007
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINT_JOB);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;
    testInfo.SetPrinterId("printId-123");

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(_, _)).Times(1);
    ON_CALL(*callback, OnCallback).WillByDefault(
            [&testState, &testInfo](uint32_t state, const PrinterInfo &info) {
                 EXPECT_EQ(testState, state);
                 EXPECT_EQ(testInfo.GetPrinterId(), info.GetPrinterId());
                return true;
            });
    EXPECT_TRUE(static_cast<bool>(callback->OnRemoteRequest(code, data, reply, option)));
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: PrintServiceProxyTest_0008
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0008, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINT_JOB + 100);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: PrintServiceProxyTest_0009
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0009, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_PRINT_JOB);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;

    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(testInfo.Marshalling(data));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintServiceProxyTest_0010
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0010, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_EXTINFO);

    PrinterInfo testInfo;
    std::string testExtensionId = "extensionId-1";
    std::string infoStr = "info-1";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testExtensionId));
    EXPECT_TRUE(data.WriteString(infoStr));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnCallback(_, _)).Times(1);
    ON_CALL(*callback, OnCallback).WillByDefault(
            [&testExtensionId, &infoStr](const std::string &extensionId,const std::string &info) {
                 EXPECT_EQ(testExtensionId, extensionId);
                 EXPECT_EQ(infoStr, info);
                return true;
            });
    EXPECT_TRUE(static_cast<bool>(callback->OnRemoteRequest(code, data, reply, option)));
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: PrintServiceProxyTest_0011
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0011, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_EXTINFO);

    PrinterInfo testInfo;
    std::string testExtensionId = "extensionId-1";
    std::string infoStr = "info-1";
    EXPECT_TRUE(data.WriteString(testExtensionId));
    EXPECT_TRUE(data.WriteString(infoStr));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
    
}

/**
 * @tc.name: PrintServiceProxyTest_0012
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackStubTest, PrintCallbackStubTest_0012, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_CALLBACK_EXTINFO + 100);
    PrinterInfo testInfo;
    std::string testExtensionId = "extensionId-1";
    std::string infoStr = "info-1";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testExtensionId));
    EXPECT_TRUE(data.WriteString(infoStr));
    auto callback = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}
}  // namespace Print
}  // namespace OHOS
