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

void PrintServiceStubTest::SetUpTestCase(void) {}

void PrintServiceStubTest::TearDownTestCase(void) {}

void PrintServiceStubTest::SetUp(void) {}

void PrintServiceStubTest::TearDown(void) {}

/**
 * @tc.name: PrintServiceStubTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0001, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0002, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteBool(false));

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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0004, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList;
    testFdList.resize(1001);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(testFileList.size() > 0));
    EXPECT_TRUE(data.WriteStringVector(testFileList));
    EXPECT_TRUE(data.WriteBool(testFdList.size() > 0));
    EXPECT_TRUE(data.WriteInt32(testFdList.size()));

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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_PRINT);

    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0007, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0008, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0009, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0010, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0011, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0012, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0013, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0014, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0015, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0016, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0017, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0018, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0019, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0020, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0021, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0022, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0023, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0025, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0026, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UPDATEPRINTJOBSTATE);

    std::string testJobId = "jodId:1234";
    uint32_t testState = static_cast<uint32_t>(PRINT_JOB_COMPLETED);
    uint32_t testSubState = static_cast<uint32_t>(PRINT_JOB_COMPLETED_SUCCESS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(data.WriteUint32(testSubState));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrintJobState).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_0027
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0027, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0028, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0029, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0030, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0031, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0032, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0033, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0034, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0035, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0036, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0037, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0038, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0039, TestSize.Level1)
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
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0040, TestSize.Level1)
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
} // namespace Print
} // namespace OHOS
