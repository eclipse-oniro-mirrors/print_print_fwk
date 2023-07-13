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
#include "print_extension_callback_proxy.h"
#include "print_extension_callback_stub.h"
#include "print_constant.h"
#include "mock_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintExtensionCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionCallbackProxyTest::SetUpTestCase(void) {}

void PrintExtensionCallbackProxyTest::TearDownTestCase(void) {}

void PrintExtensionCallbackProxyTest::SetUp(void) {}

void PrintExtensionCallbackProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0001
 * @tc.desc: PrintExtensionCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0001, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_FALSE(proxy->OnCallback());
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0002
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0002, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback());
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0003
 * @tc.desc: PrintExtensionCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0003, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_FALSE(proxy->OnCallback(testPrinterId));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0004
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0004, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testPrinterId));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0005
 * @tc.desc: PrintExtensionCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0005, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_FALSE(proxy->OnCallback(testJob));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0006
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0006, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testJob));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0007
 * @tc.desc: PrintExtensionCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0007, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string testPrinterId = "com.sample.ext:1";
    PrinterCapability testCap;

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_FALSE(proxy->OnCallback(testPrinterId, testCap));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0008
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0008, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintExtensionCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string testPrinterId = "com.sample.ext:1";
    PrinterCapability testCap;

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testPrinterId, testCap));
}
} // namespace Print
} // namespace OHOS