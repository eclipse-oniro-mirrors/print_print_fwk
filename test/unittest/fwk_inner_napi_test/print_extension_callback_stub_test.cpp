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
#include "napi/native_api.h"

#include "print_extension_callback_stub.h"
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
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    uint32_t code = 0;
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    const std::string printerId;
    const OHOS::Print::PrintJob job;
    OHOS::Print::PrinterCapability cap;
    int32_t rq;
    rq = printExtensionCallbackStub.OnRemoteRequest(code, data, reply, option);
    bool cb = printExtensionCallbackStub.OnCallback();
    cb = printExtensionCallbackStub.OnCallback(printerId);
    cb = printExtensionCallbackStub.OnCallback(job);
    cb = printExtensionCallbackStub.OnCallback(printerId, cap);
}

/**
 * @tc.name: PrintServiceProxyTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    printExtensionCallbackStub.SetExtCallback(printExtensionCallbackStub.extCb_);
    MessageParcel data, reply;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    bool hb = false;
    hb = printExtensionCallbackStub.HandleExtCallback(data, reply);
}

/**
 * @tc.name: PrintServiceProxyTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    printExtensionCallbackStub.SetPrintJobCallback(printExtensionCallbackStub.jobCb_);
    MessageParcel data, reply;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    bool hb = false;
    hb = printExtensionCallbackStub.HandlePrintJobCallback(data, reply);
}

/**
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    printExtensionCallbackStub.SetPrinterCallback(printExtensionCallbackStub.cb_);
    MessageParcel data, reply;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    bool hb = false;
    hb = printExtensionCallbackStub.HandlePrinterCallback(data, reply);
}

/**
 * @tc.name: PrintServiceProxyTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    printExtensionCallbackStub.SetCapabilityCallback(printExtensionCallbackStub.capability_);
    MessageParcel data, reply;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    bool hb = false;
    hb = printExtensionCallbackStub.HandleCapabilityCallback(data, reply);
}

/**
 * @tc.name: PrintServiceProxyTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackStubTest, PrintExtensionCallbackStubTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintExtensionCallbackStub printExtensionCallbackStub;
    printExtensionCallbackStub.SetCapabilityCallback(printExtensionCallbackStub.capability_);
    MessageParcel data;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    OHOS::Print::PrintJob job;
    printExtensionCallbackStub.dataReadJob(data, job);
}
} // namespace Print
} // namespace OHOS