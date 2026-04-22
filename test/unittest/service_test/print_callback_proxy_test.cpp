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
#include "print_log.h"
#include "print_shared_host.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void PrintCallbackProxyTest::SetUpTestCase(void)
{}

void PrintCallbackProxyTest::TearDownTestCase(void)
{}

void PrintCallbackProxyTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCallbackProxyTest_%{public}d", ++testNo);
}

/**
 * @tc.name: PrintCallbackProxyTest_0001
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0001_NeedRename, TestSize.Level0)
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
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0002_NeedRename, TestSize.Level0)
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
    const PrinterInfo &op = (const PrinterInfo &)arg;
    return op.GetPrinterId() == oParam.GetPrinterId();
}

MATCHER_P(PrintJobMatcher, oParam, "Match Print Job")
{
    const PrintJob &op = (const PrintJob &)arg;
    return op.GetJobId() == oParam.GetJobId();
}

/**
 * @tc.name: PrintCallbackProxyTest_0003
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0003_NeedRename, TestSize.Level0)
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

    EXPECT_CALL(*service, OnCallback(testState, Matcher<const PrinterInfo &>(PrinterInfoMatcher(testInfo))))
        .Times(1)
        .WillOnce(Return(true));
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
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0004_NeedRename, TestSize.Level0)
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

    EXPECT_CALL(*service, OnCallback(testState, Matcher<const PrinterInfo &>(PrinterInfoMatcher(testInfo))))
        .Times(1)
        .WillOnce(Return(false));
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
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0005_NeedRename, TestSize.Level0)
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

    EXPECT_CALL(*service, OnCallback(testState, Matcher<const PrintJob &>(PrintJobMatcher(testJob))))
        .Times(1)
        .WillOnce(Return(true));
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
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0006_NeedRename, TestSize.Level0)
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

    EXPECT_CALL(*service, OnCallback(testState, Matcher<const PrintJob &>(PrintJobMatcher(testJob))))
        .Times(1)
        .WillOnce(Return(true));
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
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0007_NeedRename, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    uint32_t testState = 0;
    EXPECT_FALSE(proxy->OnCallbackAdapterGetFile(testState));
}

/**
 * @tc.name: PrintCallbackProxyTest_0008
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0008_NeedRename, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    uint32_t testState = 0;
    uint32_t testSubState = 0;
    std::string jobId = "job:1234";
    EXPECT_FALSE(proxy->OnCallbackAdapterJobStateChanged(jobId, testState, testSubState));
}

/**
 * @tc.name: PrintCallbackProxyTest_0009
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0009_NeedRename, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    uint32_t testState = 0;
    uint32_t testSubState = 0;
    std::string jobId = "job:1234";
    EXPECT_FALSE(proxy->OnCallbackAdapterJobStateChanged(jobId, testState, testSubState));
}

HWTEST_F(PrintCallbackProxyTest, PrintQueryInfoCallbackProxyTest_ReturnTure, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    PrinterInfo testInfo;
    std::string testId = "com.sample.ext:1";
    testInfo.SetPrinterId(testId);
    std::vector<PpdInfo> testVec;
    PpdInfo info;
    info.SetPpdInfo("testmanu", "testnick", "test.ppd");
    testVec.push_back(info);

    EXPECT_CALL(*service, OnCallback(Matcher<const PrinterInfo &>(PrinterInfoMatcher(testInfo)), testVec))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(Exactly(1));
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback(testInfo, testVec));
}

HWTEST_F(PrintCallbackProxyTest, PrintQueryInfoCallbackProxyTest_ReturnFalse, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);

    PrinterInfo testInfo;
    std::string testId = "com.sample.ext:1";
    testInfo.SetPrinterId(testId);
    std::vector<PpdInfo> testVec;
    PpdInfo info;
    info.SetPpdInfo("", "", "");
    testVec.push_back(info);

    EXPECT_CALL(*service, OnCallback(Matcher<const PrinterInfo &>(PrinterInfoMatcher(testInfo)), testVec))
        .Times(0);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(Exactly(1));
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_RPC_FAILURE;
        });
    EXPECT_FALSE(proxy->OnCallback(testInfo, testVec));
}

MATCHER_P(SharedHostsMatcher, oParam, "Match Shared Hosts")
{
    const std::vector<PrintSharedHost> &hosts = (const std::vector<PrintSharedHost> &)arg;
    if (hosts.size() != oParam.size()) {
        return false;
    }
    for (size_t i = 0; i < hosts.size(); i++) {
        if (hosts[i].GetIp() != oParam[i].GetIp()) {
            return false;
        }
    }
    return true;
}

/**
 * @tc.name: OnCallback_SharedHosts_Success
 * @tc.desc: Test successful shared host callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, OnCallback_SharedHosts_Success, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    
    std::vector<PrintSharedHost> testHosts;
    PrintSharedHost host1, host2;
    host1.SetIp("192.168.1.1");
    host1.SetShareName("Share1");
    host2.SetIp("192.168.1.2");
    host2.SetShareName("Share2");
    testHosts.push_back(host1);
    testHosts.push_back(host2);
    
    EXPECT_CALL(*service, OnCallback(Matcher<const std::vector<PrintSharedHost> &>(
        SharedHostsMatcher(testHosts))))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    EXPECT_TRUE(proxy->OnCallback(testHosts));
}

/**
 * @tc.name: OnCallback_SharedHosts_ExceedMaxCount
 * @tc.desc: Test exceeding maximum count validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, OnCallback_SharedHosts_ExceedMaxCount, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    
    std::vector<PrintSharedHost> testHosts;
    for (uint32_t i = 0; i < PRINT_MAX_PRINT_COUNT + 1; i++) {
        PrintSharedHost host;
        host.SetIp("192.168.1." + std::to_string(i));
        testHosts.push_back(host);
    }
    
    EXPECT_FALSE(proxy->OnCallback(testHosts));
}

/**
 * @tc.name: OnCallback_SharedHosts_RemoteNull
 * @tc.desc: Test null remote object scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, OnCallback_SharedHosts_RemoteNull, TestSize.Level0)
{
    auto proxy = std::make_shared<PrintCallbackProxy>(nullptr);
    EXPECT_NE(proxy, nullptr);
    
    std::vector<PrintSharedHost> testHosts;
    PrintSharedHost host;
    host.SetIp("192.168.1.1");
    testHosts.push_back(host);
    
    EXPECT_FALSE(proxy->OnCallback(testHosts));
}
}  // namespace Print
}  // namespace OHOS
