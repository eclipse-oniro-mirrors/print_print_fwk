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
#include "print_extension_callback_stub.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_resolution.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintExtensionCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionCallbackStubTest::SetUpTestCase(void) {}

void PrintExtensionCallbackStubTest::TearDownTestCase(void) {}

void PrintExtensionCallbackStubTest::SetUp(void) {}

void PrintExtensionCallbackStubTest::TearDown(void) {}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB);

    PrintExtensionCallbackStub callback;
    EXPECT_EQ(callback.OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintServiceProxyTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB + 100);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    EXPECT_EQ(callback.OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: PrintServiceProxyTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    EXPECT_FALSE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    PrintExtCallback extCb = []() -> bool {
        return true;
    };
    callback.SetExtCallback(extCb);
    EXPECT_TRUE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTJOB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    EXPECT_FALSE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTJOB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    PrintJobCallback printJobCb = [](const PrintJob&) -> bool {
        return true;
    };
    callback.SetPrintJobCallback(printJobCb);
    EXPECT_TRUE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0007
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTER);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    EXPECT_FALSE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0008
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0008, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTER);

    std::string testPrinterId = "printerId:1234";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));
    PrintExtensionCallbackStub callback;
    PrinterCallback printerCb = [](const std::string&) -> bool {
        return true;
    };
    callback.SetPrinterCallback(printerCb);
    EXPECT_TRUE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0009
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0009, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTCAPABILITY);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    PrintExtensionCallbackStub callback;
    EXPECT_FALSE(callback.OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: PrintExtensionCallbackStubTest_0010
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0010, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(PRINT_EXTCB_PRINTCAPABILITY);
    std::string testPrinterId = "printerId:1234";
    PrinterCapability testCap;
    testCap.SetColorMode(10);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintExtensionCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));
    EXPECT_TRUE(testCap.Marshalling(data));

    PrintExtensionCallbackStub callback;
    PrinterCapabilityCallback testCb = [](const std::string &, PrinterCapability &) -> bool {
        return true;
    };
    callback.SetCapabilityCallback(testCb);
    EXPECT_TRUE(callback.OnRemoteRequest(code, data, reply, option));
    auto result = PrinterCapability::Unmarshalling(reply);
    EXPECT_NE(result, nullptr);
}
} // namespace Print
} // namespace OHOS
