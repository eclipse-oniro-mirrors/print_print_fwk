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
#include "print_manager_client.h"

#include "iservice_registry.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"
#include "mock_print_service.h"
#include "mock_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CallRemoteObject(const std::shared_ptr<MockPrintService> service,
        const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr);
};

void PrintManagerClientTest::SetUpTestCase(void) {}

void PrintManagerClientTest::TearDownTestCase(void) {}

void PrintManagerClientTest::SetUp(void) {}

void PrintManagerClientTest::TearDown(void) {}

void PrintManagerClientTest::CallRemoteObject(const std::shared_ptr<MockPrintService> service,
    const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr)
{
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillRepeatedly(
            [&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
                dr = recipient;
                return true;
            });
    PrintManagerClient::GetInstance()->SetProxy(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
}

/**
 * @tc.name: PrintManagerClientTest_0001
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0001, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0002
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0002, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0003
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0003, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _)).Times(1);
    ON_CALL(*service, StartPrint).WillByDefault(
            [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
                const std::vector<uint32_t> &fdList, std::string &taskId) {
                // 比较：testFileList和fileList
                EXPECT_EQ(testFileList.size(), fileList.size());
                for (size_t index = 0; index < testFileList.size(); index++) {
                    EXPECT_EQ(testFileList[index], fileList[index]);
                }
                // 比较：testFdList和fdList
                EXPECT_EQ(testFdList.size(), fdList.size());
                for (size_t index = 0; index < testFdList.size(); index++) {
                    EXPECT_EQ(testFdList[index], fdList[index]);
                }
                // 比较：testTaskId和taskId
                EXPECT_EQ(testTaskId, taskId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0004
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0004, TestSize.Level1)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0005
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0005, TestSize.Level1)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0006
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0006, TestSize.Level1)
{
    std::string testTaskId = "2";
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopPrint(_)).Times(1);
    ON_CALL(*service, StopPrint).WillByDefault(
            [&testTaskId](const std::string &taskId) {
                EXPECT_EQ(testTaskId, taskId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0007
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0007, TestSize.Level1)
{
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> extensionInfos;
    extensionInfos.emplace_back(printExtensionInfo);

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0008
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0008, TestSize.Level1)
{
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> extensionInfos;
    extensionInfos.emplace_back(printExtensionInfo);

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0009
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0009, TestSize.Level1)
{
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> testExtensionInfos;
    testExtensionInfos.emplace_back(printExtensionInfo);

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllExtension(_)).Times(1);
    ON_CALL(*service, QueryAllExtension).WillByDefault(
            [&testExtensionInfos](const std::vector<PrintExtensionInfo> &extensionInfos) {
                EXPECT_EQ(testExtensionInfos.size(), extensionInfos.size());
                for (size_t index = 0; index < testExtensionInfos.size(); index++) {
                    EXPECT_EQ(testExtensionInfos[index].GetExtensionId(), extensionInfos[index].GetExtensionId());
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(testExtensionInfos);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0010
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0010, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0011
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0011, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0012
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0012, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartDiscoverPrinter(_)).Times(1);
    ON_CALL(*service, StartDiscoverPrinter).WillByDefault(
            [&testExtensionList](const std::vector<std::string> &extensionList) {
                EXPECT_EQ(testExtensionList.size(), extensionList.size());
                for (size_t index = 0; index < testExtensionList.size(); index++) {
                    EXPECT_EQ(testExtensionList[index], extensionList[index]);
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0013
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0013, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0014
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0014, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0015
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0015, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopDiscoverPrinter()).Times(1);
    ON_CALL(*service, StopDiscoverPrinter).WillByDefault(
            []() {
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0016
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0016, TestSize.Level1)
{
    PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0017
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0017, TestSize.Level1)
{
    PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0018
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0018, TestSize.Level1)
{
    OHOS::Print::PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> testPrinterInfos;
    testPrinterInfos.emplace_back(printerInfo);
	
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddPrinters(_)).Times(1);
    ON_CALL(*service, AddPrinters).WillByDefault(
            [&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
                EXPECT_EQ(testPrinterInfos.size(), printerInfos.size());
                for (size_t index = 0; index < testPrinterInfos.size(); index++) {
                    EXPECT_EQ(testPrinterInfos[index].GetOption(), printerInfos[index].GetOption());
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(testPrinterInfos);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0019
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0019, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0020
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0020, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0021
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0021, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RemovePrinters(_)).Times(1);
    ON_CALL(*service, RemovePrinters).WillByDefault(
            [&testPrinterIds](const std::vector<std::string> &printerIds) {
                EXPECT_EQ(testPrinterIds.size(), printerIds.size());
                for (size_t index = 0; index < testPrinterIds.size(); index++) {
                    EXPECT_EQ(testPrinterIds[index], testPrinterIds[index]);
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0022
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0022, TestSize.Level1)
{
    PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0023
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0023, TestSize.Level1)
{
    PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0024
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0024, TestSize.Level1)
{
    PrinterInfo printerInfo;
    std::string printerId = "printId-123";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> testPrinterInfos;
    testPrinterInfos.emplace_back(printerInfo);
	
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinters(_)).Times(1);
    ON_CALL(*service, UpdatePrinters).WillByDefault(
            [&testPrinterInfos](const std::vector<PrinterInfo> &printerInfos) {
                EXPECT_EQ(testPrinterInfos.size(), printerInfos.size());
                for (size_t index = 0; index < testPrinterInfos.size(); index++) {
                    EXPECT_EQ(testPrinterInfos[index].GetOption(), printerInfos[index].GetOption());
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(testPrinterInfos);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0025
 * @tc.desc: ConnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0025, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0026
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0026, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0027
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0027, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ConnectPrinter(_)).Times(1);
    ON_CALL(*service, ConnectPrinter).WillByDefault(
            [&testPrinterId](const std::string &printerId) {
                EXPECT_EQ(testPrinterId, printerId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(testPrinterId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0028
 * @tc.desc: DisconnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0028, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0029
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0029, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0030
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0030, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DisconnectPrinter(_)).Times(1);
    ON_CALL(*service, DisconnectPrinter).WillByDefault(
            [&testPrinterId](const std::string &printerId) {
                EXPECT_EQ(testPrinterId, printerId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(testPrinterId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0031
 * @tc.desc: StartPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0031, TestSize.Level1)
{
    PrintJob jobinfo;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0032
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0032, TestSize.Level1)
{
    PrintJob jobinfo;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0033
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0033, TestSize.Level1)
{
    OHOS::Print::PrintJob testJob;
    testJob.SetJobId("jobId-123");
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrintJob(_)).Times(1);
    ON_CALL(*service, StartPrintJob).WillByDefault(
            [&testJob](const PrintJob &jobinfo) {
               EXPECT_EQ(testJob.GetJobId(), jobinfo.GetJobId());
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(testJob);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0034
 * @tc.desc: CancelPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0034, TestSize.Level1)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0035
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0035, TestSize.Level1)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0036
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0036, TestSize.Level1)
{
    std::string testJobId = "jobId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelPrintJob(_)).Times(1);
    ON_CALL(*service, CancelPrintJob).WillByDefault(
            [&testJobId](const std::string &jobId) {
                EXPECT_EQ(testJobId, jobId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(testJobId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0037
 * @tc.desc: UpdatePrinterState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0037, TestSize.Level1)
{
    std::string printerId = "printerId-1";
	uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0038
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0038, TestSize.Level1)
{
    std::string printerId = "printerId-1";
	uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0039
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0039, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";
	uint32_t testState = 6;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterState(_,_)).Times(1);
    ON_CALL(*service, UpdatePrinterState).WillByDefault(
            [&testPrinterId, &testState](const std::string &printerId, const uint32_t &state) {
                EXPECT_EQ(testPrinterId, printerId);
				EXPECT_EQ(testState, state);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(testPrinterId, testState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0040
 * @tc.desc: UpdatePrintJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0040, TestSize.Level1)
{
    std::string printerId = "printerId-1";
	uint32_t state = 6;
	uint32_t subState = 6;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0041
* @tc.desc: UpdatePrintJobState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0041, TestSize.Level1)
{
    std::string printerId = "printerId-1";
	uint32_t state = 6;
	uint32_t subState = 6;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0042
* @tc.desc: UpdatePrintJobState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0042, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";
	uint32_t testState = 6;
	uint32_t testSubState = 6;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrintJobState(_,_,_)).Times(1);
    ON_CALL(*service, UpdatePrintJobState).WillByDefault(
            [&testPrinterId, &testState, &testSubState](const std::string &printerId, const uint32_t &state,
                const uint32_t &subState) {
                EXPECT_EQ(testPrinterId, printerId);
                EXPECT_EQ(testState, state);
                EXPECT_EQ(testSubState, subState);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(testPrinterId, testState, testSubState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0043
 * @tc.desc: UpdateExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0043, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0044
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0044, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";


    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0045
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0045, TestSize.Level1)
{
    std::string testExtensionId = "extensionId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateExtensionInfo(_)).Times(1);
    ON_CALL(*service, UpdateExtensionInfo).WillByDefault(
            [&testExtensionId](const std::string &extensionId) {
                EXPECT_EQ(testExtensionId, extensionId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0046
 * @tc.desc: RequestPreview
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0046, TestSize.Level1)
{
    PrintJob jobinfo;
	std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0047
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0047, TestSize.Level1)
{
    PrintJob jobinfo;
	std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0048
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0048, TestSize.Level1)
{
    PrintJob testJobinfo;
    testJobinfo.SetJobId("jobId-123");
	std::string testPrinterId = "printerId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RequestPreview(_,_)).Times(1);
    ON_CALL(*service, RequestPreview).WillByDefault(
            [&testJobinfo, &testPrinterId](const PrintJob &jobinfo, const std::string &printerId) {
                EXPECT_EQ(testJobinfo.GetJobId(), jobinfo.GetJobId());
				EXPECT_EQ(testPrinterId, printerId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(testJobinfo, testPrinterId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0049
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0049, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0050
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0050, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0051
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0051, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrinterCapability(_)).Times(1);
    ON_CALL(*service, QueryPrinterCapability).WillByDefault(
        [&testPrintId](const std::string &printerId) {
            EXPECT_EQ(testPrintId, printerId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0052
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0052, TestSize.Level1)
{
    PrintJob job1, job2;
    job1.SetJobId("jobId-123");
    job2.SetJobId("jobId-123");
    std::vector<PrintJob> testPrintJobs = {job1, job2};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0053
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0053, TestSize.Level1)
{
    PrintJob job1, job2;
    job1.SetJobId("jobId-123");
    job2.SetJobId("jobId-123");
    std::vector<PrintJob> testPrintJobs = {job1, job2};

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0054
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0054, TestSize.Level1)
{
    PrintJob job1, job2;
    job1.SetJobId("jobId-123");
    job2.SetJobId("jobId-123");
    std::vector<PrintJob> testPrintJobs = {job1, job2};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _)).Times(1);
    ON_CALL(*service, QueryAllPrintJob).WillByDefault(
            [&testPrintJobs](std::vector<PrintJob> &printJobs) {
                EXPECT_EQ(testPrintJobs.size(), printJobs.size());
                for (size_t index = 0; index < testPrintJobs.size(); index++) {
                    EXPECT_EQ(testPrintJobs[index].GetJobId(), printJobs[index].GetJobId());
                }
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0055
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0055, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    testPrintJob.SetJobId("jobId-123");

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0056
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0056, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    testPrintJob.SetJobId("jobId-123");

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0057
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0057, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    testPrintJob.SetJobId("jobId-123");

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryPrintJobById(_, _)).Times(1);
    ON_CALL(*service, QueryPrintJobById).WillByDefault(
            [&testPrintJobId, &testPrintJob](std::string &printJobId, PrintJob &printJob) {
                EXPECT_EQ(testPrintJobId, printJobId);
                EXPECT_EQ(testPrintJob.GetJobId(), printJob.GetJobId());
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0058
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0058, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0059
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0059, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0060
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0060, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, On(_, _, _)).Times(1);
    ON_CALL(*service, On).WillByDefault(
        [&testTaskId, &testType, &testListener](const std::string taskId, const std::string &type,
        const sptr<IPrintCallback> &listener) {
            EXPECT_EQ(testTaskId, taskId);
            EXPECT_EQ(testType, type);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0061
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0061, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0062
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0062, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0063
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0063, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Off(_, _)).Times(1);
    ON_CALL(*service, Off).WillByDefault(
        [&testTaskId, &testType](const std::string taskId, const std::string &type) {
            EXPECT_EQ(testTaskId, taskId);
            EXPECT_EQ(testType, type);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0064
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0064, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0065
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0065, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0066
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0066, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Off(_, _)).Times(1);
    ON_CALL(*service, Off).WillByDefault(
        [&testTaskId, &testType](const std::string taskId, const std::string &type) {
            EXPECT_EQ(testTaskId, taskId);
            EXPECT_EQ(testType, type);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0067
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0067, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintManagerClientTest_0068
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0068, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintManagerClientTest_0069
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0069, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
 * @tc.name: PrintManagerClientTest_0070
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0070, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0071
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0071, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0072
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0072, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0073
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0073, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0074
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0074, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0075
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0075, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintExtCallback testCb = nullptr;
    sptr<IPrintExtensionCallback> testListener;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1);
    ON_CALL(*service, RegisterExtCallback).WillByDefault(
        [&testExtCID, &testListener](const std::string &extensionId, 
            const sptr<IPrintExtensionCallback> listener) {
            EXPECT_EQ(testExtCID, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0075
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0076, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrintJobCallback testCb = nullptr;
    sptr<IPrintExtensionCallback> testListener;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1);
    ON_CALL(*service, RegisterExtCallback).WillByDefault(
        [&testExtCID, &testListener](const std::string &extensionId, 
            const sptr<IPrintExtensionCallback> listener) {
            EXPECT_EQ(testExtCID, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0075
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0077, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCallback testCb = nullptr;
    sptr<IPrintExtensionCallback> testListener;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1);
    ON_CALL(*service, RegisterExtCallback).WillByDefault(
        [&testExtCID, &testListener](const std::string &extensionId, 
            const sptr<IPrintExtensionCallback> listener) {
            EXPECT_EQ(testExtCID, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0075
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0078, TestSize.Level1)
{
    std::string testExtCID = "extId-123";
    uint32_t testCallbackId = 111;
    PrinterCapabilityCallback testCb = nullptr;
    sptr<IPrintExtensionCallback> testListener;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1);
    ON_CALL(*service, RegisterExtCallback).WillByDefault(
        [&testExtCID, &testListener](const std::string &extensionId, 
            const sptr<IPrintExtensionCallback> listener) {
            EXPECT_EQ(testExtCID, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtCID, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}


/**
 * @tc.name: PrintManagerClientTest_0079
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0079, TestSize.Level1)
{
    std::string testExtCID = "extId-123";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtCID);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0080
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0080, TestSize.Level1)
{
    std::string testExtCID = "extId-123";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtCID);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0081
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0081, TestSize.Level1)
{
    std::string testExtCID = "extId-123";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnregisterAllExtCallback(_)).Times(1);
    ON_CALL(*service, UnregisterAllExtCallback).WillByDefault(
        [&testExtCID](const std::string &extensionId) {
            EXPECT_EQ(testExtCID, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtCID);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0001
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0082, TestSize.Level1)
{
    std::string testExtId = "extId-123";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0002
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0083, TestSize.Level1)
{
    std::string testExtId = "extId-123";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0003
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0084, TestSize.Level1)
{
    std::string testExtId = "extId-123";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, LoadExtSuccess(_)).Times(1);
    ON_CALL(*service, LoadExtSuccess).WillByDefault(
        [&testExtId](const std::string &extensionId) {
            EXPECT_EQ(testExtId, extensionId);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}
} // namespace Print
} // namespace OHOS
