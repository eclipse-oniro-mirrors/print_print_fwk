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
#include <memory>
#include "print_service_proxy.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"
#include "mock_remote_object.h"
#include "mock_print_service.h"
#include "mock_print_callback_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceProxyTest::SetUpTestCase(void) {}

void PrintServiceProxyTest::TearDownTestCase(void) {}

void PrintServiceProxyTest::SetUp(void) {}

void PrintServiceProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintServiceProxyTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0001, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _)).Times(Exactly(1)).WillOnce(
        [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
            const std::vector<uint32_t> &fdList, std::string &taskId) {
            EXPECT_EQ(testFileList.size(), fileList.size());
            for (size_t index = 0; index < testFileList.size(); index++) {
                EXPECT_EQ(testFileList[index], fileList[index]);
            }
            EXPECT_EQ(testFdList.size(), fdList.size());
            for (size_t index = 0; index < testFdList.size(); index++) {
                EXPECT_NE(testFdList[index], fdList[index]);
            }
            EXPECT_NE(testTaskId, taskId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StartPrint(testFileList, testFdList, testTaskId);
}

/**
 * @tc.name: PrintServiceProxyTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0002, TestSize.Level1)
{
    std::vector<std::string> testFileList = {};
    std::vector<uint32_t> testFdList = {};
    std::string testTaskId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _)).Times(Exactly(1)).WillOnce(
        [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
            const std::vector<uint32_t> &fdList, std::string &taskId) {
            EXPECT_EQ(testFileList.size(), fileList.size());
            for (size_t index = 0; index < testFileList.size(); index++) {
                EXPECT_EQ(testFileList[index], fileList[index]);
            }
            EXPECT_EQ(testFdList.size(), fdList.size());
            for (size_t index = 0; index < testFdList.size(); index++) {
                EXPECT_EQ(testFdList[index], fdList[index]);
            }
            EXPECT_NE(testTaskId, taskId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StartPrint(testFileList, testFdList, testTaskId);
}

/**
 * @tc.name: PrintServiceProxyTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0003, TestSize.Level1)
{
    std::string testTaskId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopPrint(_)).Times(Exactly(1)).WillOnce(
        [&testTaskId](const std::string &taskId) {
            EXPECT_EQ(testTaskId, taskId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StopPrint(testTaskId);
}

/**
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0004, TestSize.Level1)
{
    std::string testPrintId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ConnectPrinter(_)).Times(Exactly(1)).WillOnce(
        [&testPrintId](const std::string &printId) {
            EXPECT_EQ(testPrintId, printId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->ConnectPrinter(testPrintId);
}

/**
 * @tc.name: PrintServiceProxyTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0005, TestSize.Level1)
{
    std::string testPrintId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DisconnectPrinter(_)).Times(Exactly(1)).WillOnce(
        [&testPrintId](const std::string &printId) {
            EXPECT_EQ(testPrintId, printId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->DisconnectPrinter(testPrintId);
}

/**
 * @tc.name: PrintServiceProxyTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0006, TestSize.Level1)
{
    PrintExtensionInfo info1, info2;
    info1.SetExtensionId("extensionId-1");
    info1.SetExtensionId("extensionId-2");
    std::vector<PrintExtensionInfo> testExtInfos = {info1, info2};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllExtension(_)).Times(Exactly(1)).WillOnce(
        [&testExtInfos](std::vector<PrintExtensionInfo> &extensionInfos) {
            extensionInfos.assign(testExtInfos.begin(), testExtInfos.end());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    std::vector<PrintExtensionInfo> result;
    proxy->QueryAllExtension(result);
    EXPECT_EQ(testExtInfos.size(), result.size());
}

/**
 * @tc.name: PrintServiceProxyTest_0007
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0007, TestSize.Level1)
{
    std::vector<std::string> testExtList = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartDiscoverPrinter(_)).Times(Exactly(1)).WillOnce(
        [&testExtList](const std::vector<std::string> &extensionList) {
            EXPECT_EQ(testExtList.size(), extensionList.size());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StartDiscoverPrinter(testExtList);
}

/**
 * @tc.name: PrintServiceProxyTest_0008
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0008, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopDiscoverPrinter()).Times(Exactly(1)).WillOnce(
        []() {
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StopDiscoverPrinter();
}

/**
 * @tc.name: PrintServiceProxyTest_0009
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintJob testJob;
    testJob.SetJobId("jobId-123");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrintJob(_)).Times(Exactly(1)).WillOnce(
        [&testJob](const PrintJob &jobinfo) {
            EXPECT_EQ(testJob.GetJobId(), jobinfo.GetJobId());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->StartPrintJob(testJob);
}

/**
 * @tc.name: PrintServiceProxyTest_0010
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0010, TestSize.Level1)
{
    std::string testJobId = "jobId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelPrintJob(_)).Times(Exactly(1)).WillOnce(
        [&testJobId](const std::string &jobId) {
            EXPECT_EQ(testJobId, jobId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->CancelPrintJob(testJobId);
}

/**
 * @tc.name: PrintServiceProxyTest_0011
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0011, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info1, info2;
    info1.SetOption("option-1");
    info2.SetOption("option-2");
    std::vector<PrinterInfo> testPrinterInfos = {info1, info2};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddPrinters(_)).Times(Exactly(1)).WillOnce(
        [&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
            EXPECT_EQ(testPrinterInfos.size(), printerInfos.size());
            for (size_t index = 0; index < testPrinterInfos.size(); index++) {
                EXPECT_EQ(testPrinterInfos[index].GetOption(), printerInfos[index].GetOption());
            }
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->AddPrinters(testPrinterInfos);
}

/**
 * @tc.name: PrintServiceProxyTest_0012
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0012, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RemovePrinters(_)).Times(Exactly(1)).WillOnce(
        [&testPrinterIds](const std::vector<std::string> &printerIds) {
            EXPECT_EQ(testPrinterIds.size(), printerIds.size());
            for (size_t index = 0; index < testPrinterIds.size(); index++) {
                EXPECT_EQ(testPrinterIds[index], testPrinterIds[index]);
            }
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->RemovePrinters(testPrinterIds);
}

/**
 * @tc.name: PrintServiceProxyTest_0013
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0013, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info1, info2;
    info1.SetOption("option-1");
    info2.SetOption("option-2");
    std::vector<PrinterInfo> testPrinterInfos = {info1, info2};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinters(_)).Times(Exactly(1)).WillOnce(
        [&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
            EXPECT_EQ(testPrinterInfos.size(), printerInfos.size());
            for (size_t index = 0; index < testPrinterInfos.size(); index++) {
                EXPECT_EQ(testPrinterInfos[index].GetOption(), printerInfos[index].GetOption());
            }
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdatePrinters(testPrinterInfos);
}

/**
 * @tc.name: PrintServiceProxyTest_0014
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0014, TestSize.Level1)
{
    std::string testPrinterId = "printId-123";
    uint32_t testState = 1;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterState(_, _)).Times(Exactly(1)).WillOnce(
        [&testPrinterId, &testState](const std::string &printerId, uint32_t state) {
            EXPECT_EQ(testPrinterId, printerId);
            EXPECT_EQ(testState, state);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdatePrinterState(testPrinterId, testState);
}

/**
 * @tc.name: PrintServiceProxyTest_0015
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0015, TestSize.Level1)
{
    std::string testJobId = "printId-123";
    uint32_t testState = 1;
    uint32_t testSubState = 1;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrintJobState(_, _, _)).Times(Exactly(1)).WillOnce(
        [&testJobId, &testState, &testSubState](const std::string &jobId,
            uint32_t state, uint32_t subState) {
            EXPECT_EQ(testJobId, jobId);
            EXPECT_EQ(testState, state);
            EXPECT_EQ(testSubState, subState);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdatePrintJobState(testJobId, testState, testSubState);
}

/**
 * @tc.name: PrintServiceProxyTest_0016
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0016, TestSize.Level1)
{
    std::string testExtInfo = "extInfo-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateExtensionInfo(_)).Times(Exactly(1)).WillOnce(
        [&testExtInfo](const std::string &extInfo) {
            EXPECT_EQ(testExtInfo, extInfo);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdateExtensionInfo(testExtInfo);
}

/**
 * @tc.name: PrintServiceProxyTest_0017
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0017, TestSize.Level1)
{
    PrintJob testJobInfo;
    std::string testPreviewResult = "extInfo-123";
    testJobInfo.SetPrinterId("printId-123");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RequestPreview(_, _)).Times(Exactly(1)).WillOnce(
        [&testJobInfo, &testPreviewResult](const PrintJob &jobinfo, std::string &previewResult) {
            EXPECT_EQ(testJobInfo.GetPrinterId(), jobinfo.GetPrinterId());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->RequestPreview(testJobInfo, testPreviewResult);
}

/**
 * @tc.name: PrintServiceProxyTest_0018
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0018, TestSize.Level1)
{
    std::string testPrintId = "printId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrinterCapability(_)).Times(Exactly(1)).WillOnce(
        [&testPrintId](const std::string &printerId) {
            EXPECT_EQ(testPrintId, printerId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->QueryPrinterCapability(testPrintId);
}

/**
 * @tc.name: PrintServiceProxyTest_0019
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0019, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllPrintJob(_)).Times(Exactly(1)).WillOnce(
        [&testPrintJobs](std::vector<PrintJob> &printJobs) {
            EXPECT_EQ(testPrintJobs.size(), printJobs.size());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->QueryAllPrintJob(testPrintJobs);
}

/**
 * @tc.name: PrintServiceProxyTest_0020
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0020, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    testPrintJob.SetJobId("jobId-123");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrintJobById(_, _)).Times(Exactly(1)).WillOnce(
        [&testPrintJobId, &testPrintJob](std::string &printJobId, PrintJob &printJob) {
            EXPECT_EQ(testPrintJobId, printJobId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->QueryPrintJobById(testPrintJobId, testPrintJob);
}

/**
 * @tc.name: PrintServiceProxyTest_0021
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0021, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Off(_, _)).Times(Exactly(1)).WillOnce(
        [&testTaskId, &testType](const std::string taskId, const std::string &type) {
            EXPECT_EQ(testTaskId, taskId);
            EXPECT_EQ(testType, type);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->Off(testTaskId, testType);
}

/**
 * @tc.name: PrintServiceProxyTest_0022
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0022, TestSize.Level1)
{
    std::string testExtId = "extId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnregisterAllExtCallback(_)).Times(Exactly(1)).WillOnce(
        [&testExtId](const std::string &extensionId) {
            EXPECT_EQ(testExtId, extensionId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UnregisterAllExtCallback(testExtId);
}

/**
 * @tc.name: PrintServiceProxyTest_0023
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0023, TestSize.Level1)
{
    std::string testExtId = "extId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, LoadExtSuccess(_)).Times(Exactly(1)).WillOnce(
        [&testExtId](const std::string &extensionId) {
            EXPECT_EQ(testExtId, extensionId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->LoadExtSuccess(testExtId);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0024, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<IRemoteObject> testToken;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    proxy->StartPrint(testFileList, testFdList, testTaskId, testToken);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0025, TestSize.Level1)
{
    std::vector<std::string> testFileList = {};
    std::vector<uint32_t> testFdList = {};
    std::string testTaskId = "2";
    sptr<IRemoteObject> testToken;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    proxy->StartPrint(testFileList, testFdList, testTaskId, testToken);
}
} // namespace Print
} // namespace OHOS