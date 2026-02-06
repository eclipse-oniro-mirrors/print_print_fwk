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
#include "mock_watermark_callback_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintServiceProxyTest::SetUpTestCase(void)
{}

void PrintServiceProxyTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PrintServiceProxyTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0001_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testFileList = {
        "file://data/print/a.png", "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&testFileList, &testFdList, &testTaskId](
                const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList, std::string &taskId) {
                EXPECT_EQ(testFileList.size(), fileList.size());
                for (size_t index = 0; index < testFileList.size(); index++) {
                    EXPECT_EQ(testFileList[index], fileList[index]);
                }
                EXPECT_EQ(testFdList.size(), fdList.size());
                for (size_t index = 0; index < testFdList.size(); index++) {
                    EXPECT_NE(testFdList[index], fdList[index]);
                }
                EXPECT_EQ(testTaskId, taskId);
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0002_NeedRename, TestSize.Level0)
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
    EXPECT_CALL(*service, StartPrint(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&testFileList, &testFdList, &testTaskId](
                const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList, std::string &taskId) {
                EXPECT_EQ(testFileList.size(), fileList.size());
                for (size_t index = 0; index < testFileList.size(); index++) {
                    EXPECT_EQ(testFileList[index], fileList[index]);
                }
                EXPECT_EQ(testFdList.size(), fdList.size());
                for (size_t index = 0; index < testFdList.size(); index++) {
                    EXPECT_EQ(testFdList[index], fdList[index]);
                }
                EXPECT_EQ(testTaskId, taskId);
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
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0004_NeedRename, TestSize.Level0)
{
    std::string testPrintId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ConnectPrinter(_)).Times(Exactly(1)).WillOnce([&testPrintId](const std::string &printId) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0005_NeedRename, TestSize.Level0)
{
    std::string testPrintId = "2";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DisconnectPrinter(_)).Times(Exactly(1)).WillOnce([&testPrintId](const std::string &printId) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0006_NeedRename, TestSize.Level0)
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
    EXPECT_CALL(*service, QueryAllExtension(_))
        .Times(Exactly(1))
        .WillOnce([&testExtInfos](std::vector<PrintExtensionInfo> &extensionInfos) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0007_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testExtList = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartDiscoverPrinter(_))
        .Times(Exactly(1))
        .WillOnce([&testExtList](const std::vector<std::string> &extensionList) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0008_NeedRename, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopDiscoverPrinter()).Times(Exactly(1)).WillOnce([]() { return E_PRINT_NONE; });
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0009_NeedRename, TestSize.Level0)
{
    OHOS::Print::PrintJob testJob;
    testJob.SetJobId("jobId-123");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrintJob(_)).Times(Exactly(1)).WillOnce([&testJob](const PrintJob &jobinfo) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0010_NeedRename, TestSize.Level0)
{
    std::string testJobId = "jobId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelPrintJob(_)).Times(Exactly(1)).WillOnce([&testJobId](const std::string &jobId) {
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
 * @tc.name: PrintServiceProxyTest_0010
 * @tc.desc: Verify the restart function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, RestartPrintJob_ShouldCallSA, TestSize.Level0)
{
    std::string testJobId = "jobId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RestartPrintJob(_)).Times(Exactly(1)).WillOnce([&testJobId](const std::string &jobId) {
        EXPECT_EQ(testJobId, jobId);
        return E_PRINT_NONE;
    });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->RestartPrintJob(testJobId);
}

/**
 * @tc.name: PrintServiceProxyTest_0011
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0011_NeedRename, TestSize.Level0)
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
    EXPECT_CALL(*service, AddPrinters(_))
        .Times(Exactly(1))
        .WillOnce([&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0012_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RemovePrinters(_))
        .Times(Exactly(1))
        .WillOnce([&testPrinterIds](const std::vector<std::string> &printerIds) {
            EXPECT_EQ(testPrinterIds.size(), printerIds.size());
            for (size_t index = 0; index < testPrinterIds.size(); index++) {
                EXPECT_EQ(testPrinterIds[index], printerIds[index]);
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0013_NeedRename, TestSize.Level0)
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
    EXPECT_CALL(*service, UpdatePrinters(_))
        .Times(Exactly(1))
        .WillOnce([&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0014_NeedRename, TestSize.Level0)
{
    std::string testPrinterId = "printId-123";
    uint32_t testState = 1;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterState(_, _))
        .Times(Exactly(1))
        .WillOnce([&testPrinterId, &testState](const std::string &printerId, uint32_t state) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0015_NeedRename, TestSize.Level1)
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
    EXPECT_CALL(*service, UpdatePrintJobStateOnlyForSystemApp(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testJobId, &testState, &testSubState](const std::string &jobId, uint32_t state, uint32_t subState) {
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
    proxy->UpdatePrintJobStateOnlyForSystemApp(testJobId, testState, testSubState);
}

/**
 * @tc.name: PrintServiceProxyTest_0016
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0016_NeedRename, TestSize.Level1)
{
    std::string testExtInfo = "extInfo-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateExtensionInfo(_))
        .Times(Exactly(1))
        .WillOnce([&testExtInfo](const std::string &extInfo) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0017_NeedRename, TestSize.Level1)
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
    EXPECT_CALL(*service, RequestPreview(_, _))
        .Times(Exactly(1))
        .WillOnce([&testJobInfo, &testPreviewResult](const PrintJob &jobinfo, std::string &previewResult) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0018_NeedRename, TestSize.Level1)
{
    std::string testPrintId = "printId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrinterCapability(_))
        .Times(Exactly(1))
        .WillOnce([&testPrintId](const std::string &printerId) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0019_NeedRename, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllActivePrintJob(_))
        .Times(Exactly(1))
        .WillOnce([&testPrintJobs](std::vector<PrintJob> &printJobs) {
            EXPECT_EQ(testPrintJobs.size(), printJobs.size());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->QueryAllActivePrintJob(testPrintJobs);
}

/**
 * @tc.name: PrintServiceProxyTest_0020
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0020_NeedRename, TestSize.Level1)
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
    EXPECT_CALL(*service, QueryPrintJobById(_, _))
        .Times(Exactly(1))
        .WillOnce([&testPrintJobId, &testPrintJob](std::string &printJobId, PrintJob &printJob) {
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
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0021_NeedRename, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Off(_, _))
        .Times(Exactly(1))
        .WillOnce([&testTaskId, &testType](const std::string taskId, const std::string &type) {
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
 * @tc.name: PrintServiceProxyTest_0023
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0023_NeedRename, TestSize.Level1)
{
    std::string testExtId = "extId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, LoadExtSuccess(_)).Times(Exactly(1)).WillOnce([&testExtId](const std::string &extensionId) {
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

/**
 * @tc.name: PrintServiceProxyTest_0024
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0024_NeedRename, TestSize.Level1)
{
    std::string testExtId = "extId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, proxy->RegisterExtCallback(testExtId, nullptr));
}

/**
 * @tc.name: PrintServiceProxyTest_0025
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0025_NeedRename, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, proxy->UnregisterPrinterCallback(""));
}

/**
 * @tc.name: PrintServiceProxyTest_0026
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0026_NeedRename, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintCallbackStub>();
    EXPECT_NE(service, nullptr);
    const int testRetCode = -259;
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return testRetCode;
        });
    std::string testJobId = "jobId-123";
    EXPECT_EQ(E_PRINT_RPC_FAILURE, proxy->NotifyPrintServiceEvent(testJobId, 0));
}

/**
 * @tc.name: PrintServiceProxyTest_0028
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0028_NeedRename, TestSize.Level1)
{
    std::string testType = "type";
    sptr<IPrintCallback> testListener = new (std::nothrow) DummyPrintCallbackStub();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_EQ(E_PRINT_NONE, proxy->RegisterPrinterCallback(testType, testListener));
}

/**
 * @tc.name: PrintServiceProxyTest_0029
 * @tc.desc: Verify the DiscoverUsbPrinters function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0029_NeedRename, TestSize.Level1)
{
    std::vector<PrinterInfo> testPrinters = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DiscoverUsbPrinters(_))
        .Times(Exactly(1))
        .WillOnce([&testPrinters](std::vector<PrinterInfo> &printers) {
            EXPECT_EQ(testPrinters.size(), printers.size());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->DiscoverUsbPrinters(testPrinters);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0030_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrinterInfo testInfo1;
    testInfo1.SetOption("option-1");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddPrinterToDiscovery(_))
        .Times(Exactly(1))
        .WillOnce([&testInfo1](const PrinterInfo &printerInfo) {
            EXPECT_EQ(testInfo1.GetOption(), printerInfo.GetOption());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->AddPrinterToDiscovery(testInfo1);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0031_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrinterInfo testInfo1;
    testInfo1.SetOption("option-1");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterInDiscovery(_))
        .Times(Exactly(1))
        .WillOnce([&testInfo1](const PrinterInfo &printerInfo) {
            EXPECT_EQ(testInfo1.GetOption(), printerInfo.GetOption());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdatePrinterInDiscovery(testInfo1);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0032_NeedRename, TestSize.Level1)
{
    std::string testPrinterId = "111";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RemovePrinterFromDiscovery(_))
        .Times(Exactly(1))
        .WillOnce([&testPrinterId](const std::string &printerId) {
            EXPECT_EQ(testPrinterId, printerId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->RemovePrinterFromDiscovery(testPrinterId);
}

HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0033_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrinterInfo testInfo1;
    testInfo1.SetOption("option-1");
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterInSystem(_))
        .Times(Exactly(1))
        .WillOnce([&testInfo1](const PrinterInfo &printerInfo) {
            EXPECT_EQ(testInfo1.GetOption(), printerInfo.GetOption());
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->UpdatePrinterInSystem(testInfo1);
}

/**
 * @tc.name: PrintServiceProxyTest_UpdatePrintJobStateForNormalApp
 * @tc.desc: Verify the UpdatePrintJobStateForNormalApp function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_UpdatePrintJobStateForNormalApp, TestSize.Level0)
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
    EXPECT_CALL(*service, UpdatePrintJobStateForNormalApp(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testJobId, &testState, &testSubState](const std::string &jobId, uint32_t state, uint32_t subState) {
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
    proxy->UpdatePrintJobStateForNormalApp(testJobId, testState, testSubState);
}

/**
 * @tc.name: PrintServiceProxyTest_QueryAllPrintJob
 * @tc.desc: Verify the QueryAllPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_QueryAllPrintJob, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs = {};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllPrintJob(_))
        .Times(Exactly(1))
        .WillOnce([&testPrintJobs](std::vector<PrintJob> &printJobs) {
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
 * @tc.name: PrintServiceProxyTest_PrintByAdapter
 * @tc.desc: Verify the PrintByAdapter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_PrintByAdapter, TestSize.Level1)
{
    std::string testPrintJobName = "printJobName-123";
    PrintAttributes testAttr;
    std::string testTaskId = "taskId-123";
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, PrintByAdapter(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testPrintJobName, &testTaskId]
        (const std::string printJobName, const PrintAttributes &printAttributes, std::string &taskId) {
            EXPECT_EQ(testPrintJobName, printJobName);
            EXPECT_EQ(testTaskId, taskId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->PrintByAdapter(testPrintJobName, testAttr, testTaskId);
}

/**
 * @tc.name: PrintServiceProxyTest_AuthPrintJob
 * @tc.desc: Verify the AuthPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_AuthPrintJob_with_nullptr, TestSize.Level1)
{
    std::string testJobId = "printId-123";
    std::string testUserName = "userName-123";
    char* testUserPasswd = nullptr;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    proxy->AuthPrintJob(testJobId, testUserName, testUserPasswd);
}

/**
 * @tc.name: PrintServiceProxyTest_SavePdfFileJob
 * @tc.desc: Verify the SavePdfFileJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_SavePdfFileJob, TestSize.Level1)
{
    std::string testJobId = "printId-123";
    uint32_t testFd = 1;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SavePdfFileJob(_, _))
        .Times(Exactly(1))
        .WillOnce([&testJobId, &testFd] (const std::string &jobId, uint32_t fd) {
            EXPECT_EQ(testJobId, jobId);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->SavePdfFileJob(testJobId, testFd);
}

HWTEST_F(PrintServiceProxyTest, QueryAllPrinterPpdsTest, TestSize.Level1)
{
    std::vector<PpdInfo> testPpds;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllPrinterPpds(_))
        .Times(Exactly(1))
        .WillOnce([&testPpds](const std::vector<PpdInfo> &ppds) {
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    proxy->QueryAllPrinterPpds(testPpds);
}

/**
 * @tc.name: PrintServiceProxyTest_AddRawPrinter_Success
 * @tc.desc: Verify the AddRawPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_AddRawPrinter_Success, TestSize.Level0)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("option");

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddRawPrinter(_))
        .Times(Exactly(1))
        .WillOnce([&info](OHOS::Print::PrinterInfo &printerInfo) {
            EXPECT_EQ(info.GetOption(), printerInfo.GetOption());
            return E_PRINT_NONE;
        });

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    int32_t ret = proxy->AddRawPrinter(info);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
+ * @tc.name: CheckPreferencesConflictsTest
+ * @tc.desc: Verify the CheckPreferencesConflicts function.
+ * @tc.type: FUNC
+ * @tc.require:
+ */
HWTEST_F(PrintServiceProxyTest, CheckPreferencesConflictsTest, TestSize.Level1)
{
    std::string testPrinterId = "111";
    std::string testChangedType = PRINT_PARAM_TYPE_PAGE_SIZE;
    OHOS::Print::PrinterPreferences testPreferences;
    testPreferences.SetDefaultDuplexMode(0);
    testPreferences.SetDefaultPrintQuality(4);
    testPreferences.SetDefaultMediaType("stationery");
    testPreferences.SetDefaultPageSizeId(PAGE_SIZE_ID_ISO_A4);
    testPreferences.SetDefaultOrientation(0);
    testPreferences.SetBorderless(true);
    testPreferences.SetDefaultColorMode(0);
    testPreferences.SetDefaultCollate(true);
    testPreferences.SetDefaultReverse(true);
    testPreferences.SetOption("test");
    std::vector<std::string> testConflictingOptions;

    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    ASSERT_NE(proxy, nullptr);
    int32_t ret = proxy->CheckPreferencesConflicts(
        testPrinterId, testChangedType, testPreferences, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    proxy.reset();

    sptr<MockRemoteObject> obj = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(obj, nullptr);
    proxy = std::make_shared<PrintServiceProxy>(obj);
    ASSERT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, CheckPreferencesConflicts(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testPrinterId, &testChangedType, &testPreferences]
                (const std::string &printerId, const std::string &changedType,
                const PrinterPreferences &printerPreference, std::vector<std::string> &conflictingOptions) {
            EXPECT_EQ(testPrinterId, printerId);
            EXPECT_EQ(testChangedType, changedType);
            conflictingOptions.emplace_back(PRINT_PARAM_TYPE_PAGE_SIZE);
            return E_PRINT_NONE;
    });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_TRANSACTION_FAILED))
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    ret = proxy->CheckPreferencesConflicts(testPrinterId, testChangedType, testPreferences, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);

    ret = proxy->CheckPreferencesConflicts(testPrinterId, testChangedType, testPreferences, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    ASSERT_FALSE(testConflictingOptions.empty());
    EXPECT_EQ(testConflictingOptions.front(), PRINT_PARAM_TYPE_PAGE_SIZE);
}

/**
 * @tc.name: CheckPrintJobConflictsTest
 * @tc.desc: Verify the CheckPrintJobConflicts function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, CheckPrintJobConflictsTest, TestSize.Level1)
{
    std::string testChangedType = PRINT_PARAM_TYPE_PAGE_SIZE;
    PrintJob testPrintJob;
    std::vector<std::string> testConflictingOptions;

    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    ASSERT_NE(proxy, nullptr);
    int32_t ret = proxy->CheckPrintJobConflicts(testChangedType, testPrintJob, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    proxy.reset();

    sptr<MockRemoteObject> obj = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(obj, nullptr);
    proxy = std::make_shared<PrintServiceProxy>(obj);
    ASSERT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    ASSERT_NE(service, nullptr);

    EXPECT_CALL(*service, CheckPrintJobConflicts(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testChangedType, &testPrintJob]
            (const std::string &changedType, const PrintJob &printJob, std::vector<std::string> &conflictingOptions) {
            EXPECT_EQ(testChangedType, changedType);
            conflictingOptions.emplace_back(PRINT_PARAM_TYPE_PAGE_SIZE);
            return E_PRINT_NONE;
    });

    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_TRANSACTION_FAILED))
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    ret = proxy->CheckPrintJobConflicts(testChangedType, testPrintJob, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);

    ret = proxy->CheckPrintJobConflicts(testChangedType, testPrintJob, testConflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    ASSERT_FALSE(testConflictingOptions.empty());
    EXPECT_EQ(testConflictingOptions.front(), PRINT_PARAM_TYPE_PAGE_SIZE);
}

/**
 * @tc.name: GetPrinterDefaultPreferencesTest
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, GetPrinterDefaultPreferencesTest, TestSize.Level1)
{
    std::string testPrinterId = "111";
    OHOS::Print::PrinterPreferences testDefaultPreferences;

    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    ASSERT_NE(proxy, nullptr);
    int32_t ret = proxy->GetPrinterDefaultPreferences(testPrinterId, testDefaultPreferences);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    proxy.reset();

    sptr<MockRemoteObject> obj = sptr<MockRemoteObject>::MakeSptr();
    ASSERT_NE(obj, nullptr);
    proxy = std::make_shared<PrintServiceProxy>(obj);
    ASSERT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, GetPrinterDefaultPreferences(_, _))
        .Times(Exactly(1))
        .WillOnce([&testPrinterId, &testDefaultPreferences]
            (const std::string &printerId, const PrinterPreferences &defaultPreferences) {
            EXPECT_EQ(testPrinterId, printerId);
            return E_PRINT_NONE;
    });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(Return(ERR_TRANSACTION_FAILED))
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    ret = proxy->GetPrinterDefaultPreferences(testPrinterId, testDefaultPreferences);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);

    ret = proxy->GetPrinterDefaultPreferences(testPrinterId, testDefaultPreferences);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: RegisterWatermarkCallback_NullCallback
 * @tc.desc: Verify RegisterWatermarkCallback returns error when callback is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, RegisterWatermarkCallback_NullCallback, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t ret = proxy->RegisterWatermarkCallback(nullptr);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: RegisterWatermarkCallback_RemoteNull
 * @tc.desc: Verify RegisterWatermarkCallback returns error when remote is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, RegisterWatermarkCallback_RemoteNull, TestSize.Level1)
{
    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    EXPECT_NE(proxy, nullptr);

    sptr<MockWatermarkCallbackStub> callback = new MockWatermarkCallbackStub();
    EXPECT_NE(callback, nullptr);

    int32_t ret = proxy->RegisterWatermarkCallback(callback);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: RegisterWatermarkCallback_Success
 * @tc.desc: Verify RegisterWatermarkCallback function works correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, RegisterWatermarkCallback_Success, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);

    sptr<MockWatermarkCallbackStub> callback = new MockWatermarkCallbackStub();
    EXPECT_NE(callback, nullptr);

    EXPECT_CALL(*service, RegisterWatermarkCallback(_))
        .Times(Exactly(1))
        .WillOnce([](const sptr<IWatermarkCallback> &cb) {
            EXPECT_NE(cb, nullptr);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    int32_t ret = proxy->RegisterWatermarkCallback(callback);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: RegisterWatermarkCallback_RpcFailure
 * @tc.desc: Verify RegisterWatermarkCallback returns RPC failure when SendRequest fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, RegisterWatermarkCallback_RpcFailure, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    sptr<MockWatermarkCallbackStub> callback = new MockWatermarkCallbackStub();
    EXPECT_NE(callback, nullptr);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_TRANSACTION_FAILED));

    int32_t ret = proxy->RegisterWatermarkCallback(callback);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: UnregisterWatermarkCallback_RemoteNull
 * @tc.desc: Verify UnregisterWatermarkCallback returns error when remote is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, UnregisterWatermarkCallback_RemoteNull, TestSize.Level1)
{
    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    EXPECT_NE(proxy, nullptr);

    int32_t ret = proxy->UnregisterWatermarkCallback();
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: UnregisterWatermarkCallback_Success
 * @tc.desc: Verify UnregisterWatermarkCallback function works correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, UnregisterWatermarkCallback_Success, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);

    EXPECT_CALL(*service, UnregisterWatermarkCallback())
        .Times(Exactly(1))
        .WillOnce([]() {
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    int32_t ret = proxy->UnregisterWatermarkCallback();
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: UnregisterWatermarkCallback_RpcFailure
 * @tc.desc: Verify UnregisterWatermarkCallback returns RPC failure when SendRequest fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, UnregisterWatermarkCallback_RpcFailure, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_TRANSACTION_FAILED));

    int32_t ret = proxy->UnregisterWatermarkCallback();
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: NotifyWatermarkComplete_RemoteNull
 * @tc.desc: Verify NotifyWatermarkComplete returns error when remote is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, NotifyWatermarkComplete_RemoteNull, TestSize.Level1)
{
    auto proxy = std::make_shared<PrintServiceProxy>(nullptr);
    EXPECT_NE(proxy, nullptr);

    int32_t ret = proxy->NotifyWatermarkComplete("jobId-123", 0);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: NotifyWatermarkComplete_Success
 * @tc.desc: Verify NotifyWatermarkComplete function works correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, NotifyWatermarkComplete_Success, TestSize.Level1)
{
    std::string testJobId = "jobId-123";
    int32_t testResult = 0;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);

    EXPECT_CALL(*service, NotifyWatermarkComplete(_, _))
        .Times(Exactly(1))
        .WillOnce([&testJobId, &testResult](const std::string &jobId, int32_t result) {
            EXPECT_EQ(testJobId, jobId);
            EXPECT_EQ(testResult, result);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    int32_t ret = proxy->NotifyWatermarkComplete(testJobId, testResult);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: NotifyWatermarkComplete_RpcFailure
 * @tc.desc: Verify NotifyWatermarkComplete returns RPC failure when SendRequest fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, NotifyWatermarkComplete_RpcFailure, TestSize.Level1)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_TRANSACTION_FAILED));

    int32_t ret = proxy->NotifyWatermarkComplete("jobId-123", 0);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: NotifyWatermarkComplete_WithFailureResult
 * @tc.desc: Verify NotifyWatermarkComplete with failure result works correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, NotifyWatermarkComplete_WithFailureResult, TestSize.Level1)
{
    std::string testJobId = "jobId-456";
    int32_t testResult = -1;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = std::make_shared<PrintServiceProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);

    EXPECT_CALL(*service, NotifyWatermarkComplete(_, _))
        .Times(Exactly(1))
        .WillOnce([&testJobId, &testResult](const std::string &jobId, int32_t result) {
            EXPECT_EQ(testJobId, jobId);
            EXPECT_EQ(testResult, result);
            return E_PRINT_NONE;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });

    int32_t ret = proxy->NotifyWatermarkComplete(testJobId, testResult);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

}  // namespace Print
}  // namespace OHOS