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
#include "printer_preferences.h"
#include "print_shared_host.h"
#include "mock_print_callback_stub.h"
#include "print_attributes.h"
#include "print_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintServiceStubTest::SetUpTestCase(void)
{}

void PrintServiceStubTest::TearDownTestCase(void)
{}

namespace {
const std::string TEST_PRINTER_ID = "com.sample.ext:1";
const std::string TEST_JOB_ID = "job:1234";
const std::string TEST_LONG_PRINTER_ID = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
const std::string TEST_EXTENSION_CID = "com.exmpale.ext:1234";
const std::string TEST_EXTENSION_ID = "com.sample.ext";
const std::string TEST_TASK_ID = "1234";
const std::string TEST_TYPE_BLOCK = "block";
const std::string TEST_PRINTER_URI = "ipp://192.168.186.1:631/ipp/print";
const std::string TEST_IP = "192.168.1.1";
const std::string TEST_PPD_NAME = "test.ppd";
const std::string TEST_PROTOCOL = "ipp";
const std::string TEST_USER_NAME = "testUser";
const uint32_t TEST_OVER_SIZE = 1001;
}

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
    testFileList.resize(TEST_OVER_SIZE);
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
    testFdList.resize(TEST_OVER_SIZE);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_PRINTER_ID));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_PRINTER_ID));

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
    testExtensionList.emplace_back(TEST_EXTENSION_ID);

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
    testJob.SetJobId(TEST_JOB_ID);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_JOB_ID));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(TEST_OVER_SIZE));

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
    testInfo.SetPrinterId(TEST_PRINTER_ID);
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
    printerIds.resize(TEST_OVER_SIZE);

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

    std::vector<std::string> printerIds;
    printerIds.emplace_back(TEST_PRINTER_ID);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(TEST_OVER_SIZE));

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
    testInfo.SetPrinterId(TEST_PRINTER_ID);
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

    uint32_t testState = static_cast<uint32_t>(PRINTER_ADDED);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_PRINTER_ID));
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
    uint32_t code = static_cast<uint32_t>(CMD_ADAPTERGETFILECALLBACK);

    std::string testJobId = "jodId:1234";
    uint32_t testState = static_cast<uint32_t>(PRINT_JOB_COMPLETED);
    uint32_t testSubState = static_cast<uint32_t>(PRINT_JOB_COMPLETED_SUCCESS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(testJobId));
    EXPECT_TRUE(data.WriteUint32(testState));
    EXPECT_TRUE(data.WriteUint32(testSubState));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AdapterGetFileCallBack(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
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
    testJob.SetJobId(TEST_JOB_ID);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_PRINTER_ID));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_JOB_ID));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_TASK_ID));
    EXPECT_TRUE(data.WriteString(std::string("")));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_TASK_ID));
    EXPECT_TRUE(data.WriteString(TEST_TYPE_BLOCK));

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

    auto callback = std::make_shared<PrintExtensionCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_TASK_ID));
    EXPECT_TRUE(data.WriteString(TEST_TYPE_BLOCK));
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

    auto callback = std::make_shared<DummyPrintServiceStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_TASK_ID));
    EXPECT_TRUE(data.WriteString(TEST_TYPE_BLOCK));
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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_TASK_ID));
    EXPECT_TRUE(data.WriteString(TEST_TYPE_BLOCK));

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_EXTENSION_CID));

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

    auto callback = std::make_shared<DummyPrintServiceStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_EXTENSION_CID));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterExtCallback).WillByDefault(Return(E_PRINT_NONE));
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

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0042_NeedRename, TestSize.Level0)
{
    MessageParcel addData;
    MessageParcel addReply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t addCode = static_cast<uint32_t>(CMD_ADDPRINTERTOCUPS);

    std::string printerUri = TEST_PRINTER_URI;
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

    std::string printerUri = TEST_PRINTER_URI;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerUri));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));

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
    uint32_t code = static_cast<uint32_t>(CMD_STARTNATIVEPRINTJOB);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));

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

    std::vector<std::string> keyList;
    keyList.resize(TEST_OVER_SIZE);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));
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

    std::vector<std::string> extensionIdList;
    extensionIdList.emplace_back(TEST_EXTENSION_ID);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteStringVector(extensionIdList));

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

    std::string printerSetting = R"({"pagesizeId":"","orientation":"","duplex":"","quality":""})";
    EXPECT_TRUE(setData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(setData.WriteString(TEST_LONG_PRINTER_ID));
    EXPECT_TRUE(setData.WriteString(printerSetting));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SetPrinterPreference).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(setCode, setData, setReply, option)));

    MessageParcel getData;
    MessageParcel getReply;
    uint32_t getCode = static_cast<uint32_t>(CMD_GETPRINTERDEFAULTPREFERENCES);

    EXPECT_TRUE(getData.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(getData.WriteString(TEST_LONG_PRINTER_ID));

    ON_CALL(*stub, GetPrinterDefaultPreferences).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(getCode, getData, getReply, option)));
}

HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0058_NeedRename, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SET_DEFAULT_PRINTERID);

    uint32_t type = 2;
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));
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
    testInfo.SetPrinterId(TEST_PRINTER_ID);

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
    testInfo.SetPrinterId(TEST_PRINTER_ID);

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

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_PRINTER_ID));

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
    testInfo.SetPrinterId(TEST_PRINTER_ID);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintCallback::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UpdatePrinterInSystem).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}

/**
 * @tc.name: PrintServiceStubTest_OnAddRawPrinter_Success
 * @tc.desc: Verify the OnAddRawPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_OnAddRawPrinter_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADD_RAW_PRINTER);

    PrinterInfo testInfo;
    testInfo.SetPrinterId("raw_printer");
    testInfo.SetOption("raw_option");
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddRawPrinter(_)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

/**
 * @tc.name: PrintServiceStubTest_OnQueryRawAddedPrinter_Success
 * @tc.desc: Verify the OnQueryRawAddedPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_OnQueryRawAddedPrinter_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYRAWADDEDPRINTER);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);

    ON_CALL(*stub, QueryRawAddedPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}
/**
 * @tc.name: PrintServiceStubTest_OnAddRawPrinter_InvalidInput
 * @tc.desc: Verify the OnAddRawPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_OnAddRawPrinter_InvalidInput, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADD_RAW_PRINTER);

    PrinterInfo testInfo;
    testInfo.SetPrinterId("");
    testInfo.SetOption("raw_option");
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    testInfo.Marshalling(data);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddRawPrinter(_)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, AnalyzePrintEvents_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ANALYZEPRINTEVENTS);

    std::string testPrinterId = TEST_PRINTER_ID;
    std::string eventType = "testType";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(testPrinterId);
    data.WriteString(eventType);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AnalyzePrintEvents).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnQueryAllPrinterPpds_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYALLPPDS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryAllPrinterPpds).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnQueryPrinterInfoByIp_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYIPINFO);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(TEST_IP);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryPrinterInfoByIp).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnConnectByIpAndPpd_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYIPINFO);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(TEST_IP);
    data.WriteString(TEST_PROTOCOL);
    data.WriteString(TEST_PPD_NAME);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, ConnectPrinterByIpAndPpd).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, SavePdfFileJob_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SAVEPDFFILEJOB);

    std::string jobId = "test_job";
    uint32_t fd = 1;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(jobId);
    data.WriteFileDescriptor(fd);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SavePdfFileJob).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnQueryRecommendDriversById_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYRECOMMENDDRVIERSBYID);

    std::string testId = "test";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(testId);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryRecommendDriversById).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnConnectPrinterByIdAndPpd_ShouldReturnTrue, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYRECOMMENDDRVIERSBYID);

    std::string testId = "test";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    data.WriteString(testId);
    data.WriteString(TEST_PROTOCOL);
    data.WriteString(TEST_PPD_NAME);

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, ConnectPrinterByIdAndPpd).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnGetSharedHostsTest, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_GET_SHAREDHOSTS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, GetSharedHosts).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDeviceTest, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    sharedHost.SetShareName("share");
    std::string userName = "";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthSmbDevice).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnAddPrinterTest, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_ADDPRINTER);

    std::string printerName = "test-printer";
    std::string uri = "ipp://192.168.1.1:631/printers/ipp/queue";
    std::string ppdName = DEFAULT_PPD_NAME;
    std::string options = "";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerName));
    EXPECT_TRUE(data.WriteString(uri));
    EXPECT_TRUE(data.WriteString(ppdName));
    EXPECT_TRUE(data.WriteString(options));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AddPrinter).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnSetPrinterPreference_UnmarshallingFail, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SET_PRINTER_PREFERENCE);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnSetPrinterPreference_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SET_PRINTER_PREFERENCE);

    PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(1);
    preferences.SetDefaultPageSizeId("iso_a4_210x297mm");

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));
    EXPECT_TRUE(preferences.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SetPrinterPreference).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnSetPrinterPreference_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_SET_PRINTER_PREFERENCE);

    PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(1);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_LONG_PRINTER_ID));
    EXPECT_TRUE(preferences.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, SetPrinterPreference).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnRegisterPrinterCallback_RemoteNull, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_PRINTER_CB);

    std::string type = "printer_type";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnRegisterPrinterCallback_ListenerNull, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_PRINTER_CB);

    std::string type = "printer_type";
    auto callback = std::make_shared<DummyPrintServiceStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnRegisterPrinterCallback_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_PRINTER_CB);

    std::string type = "printer_type";
    auto callback = std::make_shared<DummyPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterPrinterCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnRegisterPrinterCallback_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_REG_PRINTER_CB);

    std::string type = "printer_type";
    auto callback = std::make_shared<DummyPrintCallbackStub>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject().GetRefPtr()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, RegisterPrinterCallback).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnUnregisterPrinterCallback_ValidType_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UNREG_PRINTER_CB);

    std::string type = "printer_type";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UnregisterPrinterCallback).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnUnregisterPrinterCallback_ValidType_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_UNREG_PRINTER_CB);

    std::string type = "printer_type";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(type));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, UnregisterPrinterCallback).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnStartGetPrintFile_FdInvalid, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_START_GET_FILE);

    std::string jobId = "test_job";
    PrintAttributes attrs;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(jobId));
    EXPECT_TRUE(attrs.Marshalling(data));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnAuthPrintJob_NoBuffer, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTHPRINTJOB);

    std::string userName = TEST_USER_NAME;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_JOB_ID));
    EXPECT_TRUE(data.WriteString(userName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnAuthPrintJob_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTHPRINTJOB);

    std::string userName = TEST_USER_NAME;
    std::vector<uint8_t> passwordBuffer(MAX_AUTH_LENGTH_SIZE, 0);
    passwordBuffer[0] = 'p';
    passwordBuffer[1] = 'a';
    passwordBuffer[2] = 's';
    passwordBuffer[3] = 's';

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_JOB_ID));
    EXPECT_TRUE(data.WriteString(userName));
    EXPECT_TRUE(data.WriteBuffer(passwordBuffer.data(), MAX_AUTH_LENGTH_SIZE));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthPrintJob(_, _, _)).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnAuthPrintJob_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTHPRINTJOB);

    std::string userName = TEST_USER_NAME;
    std::vector<uint8_t> passwordBuffer(MAX_AUTH_LENGTH_SIZE, 0);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(TEST_JOB_ID));
    EXPECT_TRUE(data.WriteString(userName));
    EXPECT_TRUE(data.WriteBuffer(passwordBuffer.data(), MAX_AUTH_LENGTH_SIZE));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthPrintJob(_, _, _)).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnQueryRecommendDriversById_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_QUERYRECOMMENDDRVIERSBYID);

    std::string printerId = "test_printer";
    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(data.WriteString(printerId));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, QueryRecommendDriversById).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnGetSharedHosts_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_GET_SHAREDHOSTS);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, GetSharedHosts).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDevice_EmptyUserName_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    sharedHost.SetShareName("share");
    std::string userName = "";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthSmbDevice).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDevice_EmptyUserName_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    std::string userName = "";

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthSmbDevice).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDevice_WithUserName_NoBuffer, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    std::string userName = TEST_USER_NAME;

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDevice_WithUserName_Success, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    std::string userName = TEST_USER_NAME;
    std::vector<uint8_t> passwordBuffer(MAX_AUTH_LENGTH_SIZE, 0);
    passwordBuffer[0] = 'p';
    passwordBuffer[1] = 'a';
    passwordBuffer[2] = 's';
    passwordBuffer[3] = 's';

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));
    EXPECT_TRUE(data.WriteBuffer(passwordBuffer.data(), MAX_AUTH_LENGTH_SIZE));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthSmbDevice).WillByDefault(Return(E_PRINT_NONE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_NONE);
}

HWTEST_F(PrintServiceStubTest, OnAuthSmbDevice_WithUserName_Failure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(CMD_AUTH_SMB_DEVICE);

    PrintSharedHost sharedHost;
    sharedHost.SetIp(TEST_IP);
    std::string userName = TEST_USER_NAME;
    std::vector<uint8_t> passwordBuffer(MAX_AUTH_LENGTH_SIZE, 0);

    EXPECT_TRUE(data.WriteInterfaceToken(IPrintService::GetDescriptor()));
    EXPECT_TRUE(sharedHost.Marshalling(data));
    EXPECT_TRUE(data.WriteString(userName));
    EXPECT_TRUE(data.WriteBuffer(passwordBuffer.data(), MAX_AUTH_LENGTH_SIZE));

    auto stub = std::make_shared<MockPrintService>();
    EXPECT_NE(stub, nullptr);
    ON_CALL(*stub, AuthSmbDevice).WillByDefault(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), E_PRINT_GENERIC_FAILURE);
}
}  // namespace Print
}  // namespace OHOS
