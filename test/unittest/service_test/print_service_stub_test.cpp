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
#include "mock_print_service.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_resolution.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceStubTest::SetUpTestCase(void)
{}

void PrintServiceStubTest::TearDownTestCase(void)
{}

void PrintServiceStubTest::SetUp(void)
{}

void PrintServiceStubTest::TearDown(void)
{}

/**
 * @tc.name: PrintServiceStubTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0001_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintServiceStubTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0002_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT + 100);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: PrintServiceStubTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0003_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteString("jobId"));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrint(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0004_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    std::vector<std::string> testFileList;
    testFileList.resize(1001);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(testFileList.size() > 0));
    EXPECT_TRUE(data.WriteStringVector(testFileList));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteString("jobId"));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrint(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0005_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    std::vector<std::string> testFileList = {
        "file://data/print/a.png", "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList;
    testFdList.resize(1001);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(testFileList.size() > 0));
    EXPECT_TRUE(data.WriteStringVector(testFileList));
    EXPECT_TRUE(data.WriteBool(testFdList.size() > 0));
    EXPECT_TRUE(data.WriteInt32(testFdList.size()));
    EXPECT_TRUE(data.WriteString("jobId"));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrint(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0006_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    std::vector<std::string> testFileList = {
        "file://data/print/a.png", "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(testFileList.size() > 0));
    EXPECT_TRUE(data.WriteStringVector(testFileList));
    EXPECT_TRUE(data.WriteBool(testFdList.size() > 0));
    EXPECT_TRUE(data.WriteInt32(testFdList.size()));
    for (auto fd : testFdList) {
        data.WriteFileDescriptor(fd);
    }
    EXPECT_TRUE(data.WriteString("jobId"));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrint(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0007
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0007_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STOP_PRINT);

    std::string testTaskId = "2";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testTaskId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StopPrint).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0008
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0008_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_CONNECTPRINTER);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, ConnectPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0009
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0009_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_DISCONNECTPRINTER);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, DisconnectPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0010
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0010_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STARTDISCOVERPRINTER);

    std::vector<std::string> testExtensionList;
    std::string extensionId = "com.sample.ext";
    testExtensionList.emplace_back(extensionId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteStringVector(testExtensionList));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartDiscoverPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0011
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0011_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STOPDISCOVERPRINTER);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StopDiscoverPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0012
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0012_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYALLEXTENSION);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAllExtension).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0013
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0013_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYALLEXTENSION);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAllExtension).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0014
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0014_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STARTPRINTJOB);

    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(testJob.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrintJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0015
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0015_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_CANCELPRINTJOB);

    std::string jobId = "job:1234";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, CancelPrintJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0016
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0016_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADDPRINTERS);

    uint32_t testSize = 1001;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testSize));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0017
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0017_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADDPRINTERS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(0));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0018
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0018_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADDPRINTERS);

    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(testInfo);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(printerInfos.size())));
    for (size_t index = 0; index < printerInfos.size(); index++) {
        printerInfos[index].Marshalling(data);
    }

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0019
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0019_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REMOVEPRINTERS);

    std::vector<std::string> printerIds;
    printerIds.resize(1001);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteStringVector(printerIds));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RemovePrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0020
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0020_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REMOVEPRINTERS);

    std::string testPrinterId = "com.sample.ext:1";
    std::vector<std::string> printerIds;
    printerIds.emplace_back(testPrinterId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteStringVector(printerIds));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RemovePrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0021
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0021_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERS);

    uint32_t testSize = 1001;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(testSize));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0022
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0022_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(0));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0023
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0023_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERS);

    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(testInfo);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(printerInfos.size())));
    for (size_t index = 0; index < printerInfos.size(); index++) {
        printerInfos[index].Marshalling(data);
    }

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0025
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0025_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERSTATE);

    std::string testPrinterId = "com.sample.ext:1";
    uint32_t testState = static_cast<uint32_t>(PRINTER_ADDED);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));
    EXPECT_TRUE(data.WriteUint32(testState));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinterState).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0026
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0026_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTJOBSTATE_FORNORMALAPP);

    std::string testJobId = "jodId:1234";
    uint32_t testState = static_cast<uint32_t>(PRINT_JOB_COMPLETED);
    uint32_t testSubState = static_cast<uint32_t>(PRINT_JOB_COMPLETED_SUCCESS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(data.WriteUint32(testSubState));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrintJobStateOnlyForSystemApp).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0027
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0027_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEEXTENSIONINFO);

    std::string testExtInfo = "extinformation";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testExtInfo));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdateExtensionInfo).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0028
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0028_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REQUESTPREVIEW);

    PrintJob testJob;
    std::string jobId = "job:1234";
    testJob.SetJobId(jobId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(testJob.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RequestPreview).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0029
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0029_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYPRINTERCAPABILITY);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrinterCapability).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0030
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0030_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYALLACTIVEPRINTJOB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAllActivePrintJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0065_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYALLPRINTJOB);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAllPrintJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}
/**
 * @tc.name: PrintServiceStubTest_0031
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0031_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYPRINTJOBBYID);

    std::string jobId = "job:1234";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrintJobById).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0032
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0032_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ON);

    std::string taskId = "1234";
    std::string testType = "";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(taskId));
    EXPECT_TRUE(data.WriteString(testType));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, On).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0033
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0033_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ON);

    std::string taskId = "1234";
    std::string testType = "block";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(taskId));
    EXPECT_TRUE(data.WriteString(testType));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, On).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0034
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0034_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ON);

    std::string taskId = "1234";
    std::string testType = "block";
    auto callback = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(taskId));
    EXPECT_TRUE(data.WriteString(testType));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, On).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0035
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0035_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ON);

    std::string taskId = "1234";
    std::string testType = "block";
    auto callback = std::make_shared<DummyPrintServiceStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(taskId));
    EXPECT_TRUE(data.WriteString(testType));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, On).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0036
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0036_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_OFF);

    std::string taskId = "1234";
    std::string testType = "block";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(taskId));
    EXPECT_TRUE(data.WriteString(testType));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, Off).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0037
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0037_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_EXT_CB);

    std::string extensionCid = "com.exmpale.ext:1234";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(extensionCid));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterExtCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0038
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0038_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_EXT_CB);

    std::string extensionCid = "com.exmpale.ext:1234";
    auto callback = std::make_shared<DummyPrintServiceStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(extensionCid));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterExtCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0039
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0039_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_EXT_CB);

    std::string extensionCid = "com.exmpale.ext:1";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(extensionCid));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UnregisterAllExtCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0040
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0040_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_EXT_CB);

    std::string extensionId = "com.exmpale.ext";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(extensionId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, LoadExtSuccess).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0041_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UNREG_EXT_CB);

    std::string extensionId = "com.exmpale.ext";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(extensionId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UnregisterAllExtCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0042_NeedRename, TestSize.Level0)
{
    MessageParcel addData;
    MessageParcel addReply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t addCode = static_cast<uint32_t>(CMD_ADDPRINTERTOCUPS);

    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    std::string printerName = "DIRECT-PixLab_V1-1620";
    std::string printerMake = "PixLab V1 - IPP Everywhere";
    EXPECT_TRUE(addData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(addData.WriteString(printerUri));
    EXPECT_TRUE(addData.WriteString(printerName));
    EXPECT_TRUE(addData.WriteString(printerMake));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinterToCups).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(addCode, addData, addReply, option)));

    MessageParcel delData;
    MessageParcel delReply;
    uint32_t delCode = static_cast<uint32_t>(CMD_DELETE_PRINTER_FROM_CUPS);

    EXPECT_TRUE(delData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(delData.WriteString(printerName));

    ON_CALL(*stub, DeletePrinterFromCups).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(delCode, delData, delReply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0043_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYPRINTERCAPABILITYBYURI);

    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerUri));
    EXPECT_TRUE(data.WriteString(printerId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrinterCapabilityByUri).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0044_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STARTPRINTJOB_BY_ADAPTER);

    std::string jobName = "com.exmpale.ext";
    PrintAttributes attr;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, PrintByAdapter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0045_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_GET_FILE);

    std::string jobId = "1";
    PrintAttributes attr;
    uint32_t fd = 56;
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobId));
    EXPECT_TRUE(data.WriteUint32(fd));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartGetPrintFile).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0046_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_NOTIFY_PRINT_SERVICE);

    std::string jobId = "";
    std::string type = "";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobId));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, NotifyPrintService).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0047_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_NATIVE_PRINT);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartPrint).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0048_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_SERVICE);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartService).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0049_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_PRINTER_CB);

    std::string type = "";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterPrinterCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0050_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UNREG_PRINTER_CB);

    std::string type = "";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UnregisterPrinterCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0051_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYPRINTERINFOBYPRINTERID);

    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrinterInfoByPrinterId).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0052_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYADDEDPRINTER);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAddedPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0053_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYPRINTERPROPERTIES);

    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::vector<std::string> keyList;
    keyList.resize(1001);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerId));
    EXPECT_TRUE(data.WriteStringVector(keyList));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrinterProperties).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0054_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_STARTNATIVEPRINTJOB);

    PrintJob testJob;
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(testJob.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, StartNativePrintJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0055
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0055_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_SERVICE);
    data.WriteString("nativePrint");
    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0056_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_LOAD_EXT);

    std::string extensionId = "com.sample.ext";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteStringVector(extensionId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, LoadExtSuccess).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0057_NeedRename, TestSize.Level0)
{
    MessageParcel setData;
    MessageParcel setReply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t setCode = static_cast<uint32_t>(CMD_SET_PRINTER_PREFERENCE);

    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::string printerSetting = R"({"pagesizeId":"","orientation":"","duplex":"","quality":""})";
    EXPECT_TRUE(setData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(setData.WriteString(printerId));
    EXPECT_TRUE(setData.WriteString(printerSetting));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SetPrinterPreference).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(setCode, setData, setReply, option)));

    MessageParcel getData;
    MessageParcel getReply;
    uint32_t getCode = static_cast<uint32_t>(CMD_GET_PRINTER_PREFERENCE);

    EXPECT_TRUE(getData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(getData.WriteString(printerId));

    ON_CALL(*stub, GetPrinterPreference).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(getCode, getData, getReply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0058_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SET_DEFAULT_PRINTERID);

    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    uint32_t type = 2;
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerId));
    EXPECT_TRUE(data.WriteUint32(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SetDefaultPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0059_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_DISCOVER_USB_PRINTERS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, DiscoverUsbPrinters).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0060
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0060_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADDPRINTERTODISCOVERY);

    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinterToDiscovery).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0061
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0061_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERINDISCOVERY);

    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinterInDiscovery).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0062
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0062_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REMOVEPRINTERFROMDISCOVERY);

    std::string testPrinterId = "com.sample.ext:1";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testPrinterId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RemovePrinterFromDiscovery).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0063
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0063_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTERINSYSTEM);

    PrinterInfo testInfo;
    std::string testPrinterId = "com.sample.ext:1";
    testInfo.SetPrinterId(testPrinterId);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinterInSystem).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_ShouldReturnTrue_When, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ANALYZEPRINTEVENTS);

    std::string testPrinterId = "com.sample.ext:1";
    std::string eventType = "testType";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    data.WriteString(testPrinterId);
    data.WriteString(eventType);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AnalyzePrintEvents).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}
}  // namespace Print
}  // namespace OHOS
