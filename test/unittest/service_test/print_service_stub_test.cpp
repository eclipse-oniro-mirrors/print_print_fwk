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
 * @tc.name: PrintServiceProxyTest_0002
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
 * @tc.name: PrintServiceProxyTest_0003
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
    EXPECT_CALL(*stub, StartPrint(_, _, _)).Times(1);
    ON_CALL(*stub, StartPrint).WillByDefault(
            [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
                const std::vector<uint32_t> &fdList, std::string &taskId) {
                 // 比较：testFileList和fileList
                 // 比较：testFdList和fdList
                 // 比较：testTaskId和taskId
                return E_PRINT_NONE;
            });
    EXPECT_TRUE(static_cast<bool>(stub->OnRemoteRequest(code, data, reply, option)));
}














/**
* @tc.name: PrintServiceStubTest_0001
* @tc.desc: OnRemoteRequest
* @tc.type: FUNC
* @tc.require:
*/
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0001, TestSize.Level1)
// {
//     std::vector<std::string> testFileList = {"file://data/print/a.png",
//         "file://data/print/b.png", "file://data/print/c.png"};
//     std::vector<uint32_t> testFdList = {1, 2};
//     std::string testTaskId = "2";
//     sptr<MockRemoteObject> obj = new MockRemoteObject();
//     EXPECT_NE(obj, nullptr);
//     auto proxy = std::make_shared<PrintServiceProxy>(obj);
//     EXPECT_NE(proxy, nullptr);
//     auto service = std::make_shared<MockPrintService>();
//     EXPECT_NE(service, nullptr);
//     EXPECT_CALL(*service, StartPrint(_, _, _)).Times(Exactly(1)).WillOnce(
//         [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
//             const std::vector<uint32_t> &fdList, std::string &taskId) {
//             // 比较：testFileList和fileList
//             // 比较：testFdList和fdList
//             // 比较：testTaskId和taskId
//             return E_PRINT_NONE;
//         });
//     EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
//     ON_CALL(*obj, SendRequest)
//         .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
//             service->OnRemoteRequest(code, data, reply, option);
//             return E_PRINT_NONE;
//         });
//     proxy->StartPrint(testFileList, testFdList, testTaskId);


//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 0;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0002
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0002, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 1;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0003
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0003, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 2;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0004
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0004, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 3;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0005
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0005, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 4;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0006
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0006, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 5;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0007
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0007, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 6;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0008
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0008, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 7;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0009
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0009, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 8;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0010
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0010, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 9;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0011
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0011, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 10;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0012
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0012, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 11;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0013
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0013, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 12;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0014
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0014, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 13;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0002
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0015, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 14;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0016
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0016, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 15;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0017
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0017, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 16;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0018
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0018, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 17;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0019
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0019, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 18;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0020
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0020, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 19;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0021
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0021, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 20;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0022
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0022, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 21;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0023
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0023, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 22;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }

// /**
// * @tc.name: PrintServiceStubTest_0024
// * @tc.desc: OnRemoteRequest
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceStubTest, PrintServiceStubTest_0024, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceStub printServiceStub;
//     uint32_t code = 23;
//     MessageParcel data, reply;
//     MessageOption option;
//     const std::string printerId = "1";
//     uint32_t state = 0;
//     data.WriteString(printerId);
//     data.WriteUint32(state);
//     const OHOS::Print::PrintJob job;
//     OHOS::Print::PrinterCapability cap;
//     int32_t rq;
//     rq = printServiceStub.OnRemoteRequest(code, data, reply, option);
//     EXPECT_EQ((int32_t)0, rq);
// }
} // namespace Print
} // namespace OHOS