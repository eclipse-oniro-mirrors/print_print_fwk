/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applipcable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "iservice_registry.h"
#include "print_constant.h"
#include "print_callback_proxy.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"
#include "mock_remote_object.h"
#include "mock_print_callback_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintCallbackProxyTest::SetUpTestCase(void) {}

void PrintCallbackProxyTest::TearDownTestCase(void) {}

void PrintCallbackProxyTest::SetUp(void) {}

void PrintCallbackProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintCallbackProxyTest_0001
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0001, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCallback()).Times(Exactly(1)).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback());
}

/**
 * @tc.name: PrintCallbackProxyTest_0002
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0002, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCallback()).Times(Exactly(1)).WillOnce(Return(false));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback());
}

MATCHER_P(PrinterInfoMatcher, oParam, "Match Printer Info")
{
    const PrinterInfo& op = (const PrinterInfo&)arg;
    return op.GetPrinterId() == oParam.GetPrinterId();
}

MATCHER_P(PrintJobMatcher, oParam, "Match Print Job")
{
    const PrintJob& op = (const PrintJob&)arg;
    return op.GetJobId() == oParam.GetJobId();
}

/**
 * @tc.name: PrintCallbackProxyTest_0003
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0003, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);

    EXPECT_CALL(*service, OnCallback(testState,
        Matcher<const PrinterInfo&>(PrinterInfoMatcher(testInfo)))).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback(testState, testInfo));
}

/**
 * @tc.name: PrintCallbackProxyTest_0004
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0004, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    auto testState = static_cast<uint32_t>(PRINTER_ADDED);
    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);

    EXPECT_CALL(*service, OnCallback(testState,
        Matcher<const PrinterInfo&>(PrinterInfoMatcher(testInfo)))).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testState, testInfo));
}

/**
 * @tc.name: PrintCallbackProxyTest_0005
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0005, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    auto testState = static_cast<uint32_t>(PRINT_JOB_RUNNING);
    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_CALL(*service, OnCallback(testState,
        Matcher<const PrintJob&>(PrintJobMatcher(testJob)))).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback(testState, testJob));
}

/**
 * @tc.name: PrintCallbackProxyTest_0006
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0006, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    auto testState = static_cast<uint32_t>(PRINT_JOB_RUNNING);
    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_CALL(*service, OnCallback(testState,
        Matcher<const PrintJob&>(PrintJobMatcher(testJob)))).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testState, testJob));
}

/**
 * @tc.name: PrintCallbackProxyTest_0007
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0007, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string extensionId = "com.sample.ext";
    std::string extInfo = "custom extension info";

    EXPECT_CALL(*service, OnCallback(extensionId, extInfo)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback(extensionId, extInfo));
}

/**
 * @tc.name: PrintCallbackProxyTest_0007
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0008, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    std::string extensionId = "com.sample.ext";
    std::string extInfo = "custom extension info";

    EXPECT_CALL(*service, OnCallback(extensionId, extInfo)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(extensionId, extInfo));
}
} // namespace Print
} // namespace OHOS
