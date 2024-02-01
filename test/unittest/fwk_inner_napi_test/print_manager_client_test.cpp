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
#include "mock_print_callback_stub.h"

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
 * @tc.desc: StartPrint failed case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0001, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
}

/**
* @tc.name: PrintManagerClientTest_0002
* @tc.desc: StartPrint failed case.
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
    PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId);
}

/**
* @tc.name: PrintManagerClientTest_0003
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0003, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
}


/**
* @tc.name: PrintManagerClientTest_0004
* @tc.desc: StartPrint success case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0004, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartPrint(_, _, _)).Times(1);
    ON_CALL(*service, StartPrint(_, _, _)).WillByDefault(
            [&testFileList, &testFdList, &testTaskId](const std::vector<std::string> &fileList,
                const std::vector<uint32_t> &fdList, std::string &taskId) {
                EXPECT_EQ(testFileList.size(), fileList.size());
                for (size_t index = 0; index < testFileList.size(); index++) {
                    EXPECT_EQ(testFileList[index], fileList[index]);
                }
                EXPECT_EQ(testFdList.size(), fdList.size());
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0005
 * @tc.desc: StopPrint failed case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0005, TestSize.Level1)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0006
* @tc.desc: StopPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0006, TestSize.Level1)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0007
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0007, TestSize.Level1)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0008
* @tc.desc: StopPrint succedd case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0008, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0009
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0009, TestSize.Level1)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_00010
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_00010, TestSize.Level1)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0011
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0011, TestSize.Level1)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}


/**
* @tc.name: PrintManagerClientTest_0012
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0012, TestSize.Level1)
{
    PrintExtensionInfo info1, info2;
    info1.SetExtensionId("ext-123");
    info2.SetExtensionId("ext-123");
    std::vector<PrintExtensionInfo> testExtensionInfos = {info1, info2};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllExtension(_)).Times(1);
    ON_CALL(*service, QueryAllExtension).WillByDefault(
            [&testExtensionInfos](std::vector<PrintExtensionInfo> &extensionInfos) {
                extensionInfos.assign(testExtensionInfos.begin(), testExtensionInfos.end());
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::vector<PrintExtensionInfo> result;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(result);
    EXPECT_EQ(testExtensionInfos.size(), result.size());
    for (size_t index = 0; index < testExtensionInfos.size(); index++) {
        EXPECT_EQ(testExtensionInfos[index].GetExtensionId(), result[index].GetExtensionId());
    }
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
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0014
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0014, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0015
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0015, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0016
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0016, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StartDiscoverPrinter(_)).Times(1);
    ON_CALL(*service, StartDiscoverPrinter).WillByDefault(
            [&testExtensionList](const std::vector<std::string> &extensionList) {
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0017
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0017, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0018
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0018, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0019
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0019, TestSize.Level1)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0020
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0020, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, StopDiscoverPrinter()).Times(1);
    ON_CALL(*service, StopDiscoverPrinter).WillByDefault(
            []() {
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0021
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0021, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0022
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0022, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0023
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0023, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(testPrinterInfos);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0025
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0025, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0026
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0026, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0027
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0027, TestSize.Level1)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0028
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0028, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0029
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0029, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0030
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0030, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0031
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0031, TestSize.Level1)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0032
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0032, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(testPrinterInfos);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0033
 * @tc.desc: ConnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0033, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0034
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0034, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0035
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0035, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0036
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0036, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(testPrinterId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0037
 * @tc.desc: DisconnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0037, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0038
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0038, TestSize.Level1)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0039
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0039, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}


/**
* @tc.name: PrintManagerClientTest_0040
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0040, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(testPrinterId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0041
 * @tc.desc: StartPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0041, TestSize.Level1)
{
    PrintJob jobinfo;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0042
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0042, TestSize.Level1)
{
    PrintJob jobinfo;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0043
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0043, TestSize.Level1)
{
    PrintJob jobinfo;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0044
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0044, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(testJob);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0045
 * @tc.desc: CancelPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0045, TestSize.Level1)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0046
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0046, TestSize.Level1)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0047
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0047, TestSize.Level1)
{
    std::string jobId = "jobId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0048
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0048, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(testJobId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0049
 * @tc.desc: UpdatePrinterState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0049, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0050
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0050, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0051
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0051, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0052
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0052, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";
    uint32_t testState = 6;
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrinterState(_, _)).Times(1);
    ON_CALL(*service, UpdatePrinterState).WillByDefault(
            [&testPrinterId, &testState](const std::string &printerId, const uint32_t &state) {
                EXPECT_EQ(testPrinterId, printerId);
                EXPECT_EQ(testState, state);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(testPrinterId, testState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0053
 * @tc.desc: UpdatePrintJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0053, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0054
* @tc.desc: UpdatePrintJobState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0054, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0055
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0055, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0056
* @tc.desc: UpdatePrintJobState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0056, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";
    uint32_t testState = 6;
    uint32_t testSubState = 6;
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrintJobState(_, _, _)).Times(1);
    ON_CALL(*service, UpdatePrintJobState).WillByDefault(
            [&testPrinterId, &testState, &testSubState](const std::string &printerId, const uint32_t &state,
                const uint32_t &subState) {
                EXPECT_EQ(testPrinterId, printerId);
                EXPECT_EQ(testState, state);
                EXPECT_EQ(testSubState, subState);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(testPrinterId, testState, testSubState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0057
 * @tc.desc: UpdateExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0057, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0058
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0058, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0059
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0059, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0060
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0060, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0061
 * @tc.desc: RequestPreview
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0061, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0062
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0062, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0063
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0063, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0064
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0064, TestSize.Level1)
{
    PrintJob testJobinfo;
    testJobinfo.SetJobId("jobId-123");
    std::string testPreviewFilePath = "/data/temp/preview.png";
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RequestPreview(_, _)).Times(1);
    ON_CALL(*service, RequestPreview).WillByDefault(
            [&testJobinfo, &testPreviewFilePath](const PrintJob &jobinfo, std::string &previewResult) {
                EXPECT_EQ(testJobinfo.GetJobId(), jobinfo.GetJobId());
                previewResult = testPreviewFilePath;
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::string result;
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(testJobinfo, result);
    EXPECT_EQ(testPreviewFilePath, result);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0065
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0065, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0066
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0066, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0067
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0067, TestSize.Level1)
{
    std::string testPrintId = "printId-123";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0068
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0068, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0069
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0069, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0070
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0070, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0071
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0071, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0072
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0072, TestSize.Level1)
{
    PrintJob job1, job2;
    job1.SetJobId("1");
    job2.SetJobId("2");
    std::vector<PrintJob> testPrintJobs = {job1, job2};

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, QueryAllPrintJob(_)).Times(1);
    ON_CALL(*service, QueryAllPrintJob).WillByDefault(
            [&testPrintJobs](std::vector<PrintJob> &printJobs) {
                printJobs.assign(testPrintJobs.begin(), testPrintJobs.end());
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::vector<PrintJob> result;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(result);
    EXPECT_EQ(testPrintJobs.size(), result.size());
    for (size_t index = 0; index < testPrintJobs.size(); index++)
    {
        EXPECT_EQ(testPrintJobs[index].GetJobId(), result[index].GetJobId());
    }
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0073
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0073, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0074
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0074, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0075
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0075, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0076
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0076, TestSize.Level1)
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
                printJob = testPrintJob;
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintJob result;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, result);
    EXPECT_EQ(testPrintJob.GetJobId(), result.GetJobId());
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0077
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0077, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0078
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0078, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0079
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0079, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0080
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0080, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener = new (std::nothrow) DummyPrintCallbackStub();

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, On(_, _, _)).Times(1);
    ON_CALL(*service, On).WillByDefault(
        [&testTaskId, &testType, &testListener](const std::string taskId, const std::string &type,
        const sptr<IPrintCallback> &listener) {
            EXPECT_EQ(testTaskId, taskId);
            EXPECT_EQ(testType, type);
            EXPECT_TRUE(testListener == listener);
            return E_PRINT_NONE;
        });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0081
 * @tc.desc: Off failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0081, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0082
* @tc.desc: Off failed2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0082, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0083
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0083, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0084
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0084, TestSize.Level1)
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
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0085
 * @tc.desc: RegisterExtCallback: invalid callback id of ext cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0085, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrintExtCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0086
 * @tc.desc: RegisterExtCallback: invalid callback id of job cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0086, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrintJobCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0087
 * @tc.desc: RegisterExtCallback: invalid callback id of printer cap cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0087, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrinterCapabilityCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0088
 * @tc.desc: RegisterExtCallback: invalid callback id of printer cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0088, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrinterCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0089
* @tc.desc: RegisterExtCallback: load serve failed for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0089, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0090
* @tc.desc: RegisterExtCallback: load serve failed for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0090, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0091
* @tc.desc: RegisterExtCallback: load serve failed for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0091, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0092
* @tc.desc: RegisterExtCallback: load serve failed for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0092, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0093
* @tc.desc: RegisterExtCallback: without proxy for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0093, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0094
* @tc.desc: RegisterExtCallback: without proxy for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0094, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0095
* @tc.desc: RegisterExtCallback: without proxy for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0095, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0096
* @tc.desc: RegisterExtCallback: without proxy for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0096, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
}

/**
* @tc.name: PrintManagerClientTest_0097
* @tc.desc: RegisterExtCallback: ok for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0097, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintExtCallback testCb = nullptr;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0098
* @tc.desc: RegisterExtCallback: ok for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0098, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintJobCallback testCb = nullptr;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0099
* @tc.desc: RegisterExtCallback: ok for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0099, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCallback testCb = nullptr;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0100
* @tc.desc: RegisterExtCallback: ok for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0100, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0101
 * @tc.desc: UnregisterAllExtCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0101, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0102
* @tc.desc: UnregisterAllExtCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0102, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0103
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0103, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    PrintManagerClient::GetInstance()->LoadServerFail();
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnregisterAllExtCallback(_)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
* @tc.name: PrintManagerClientTest_0104
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0104, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnregisterAllExtCallback(_)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0105
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0105, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0106
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0106, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0107
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0107, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    PrintManagerClient::GetInstance()->LoadServerFail();
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, LoadExtSuccess(_)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
* @tc.name: PrintManagerClientTest_0108
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0108, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, LoadExtSuccess(_)).Times(1).WillOnce(Return(E_PRINT_NONE));
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
* @tc.name: PrintManagerClientTest_0109
* @tc.desc: LoadServerFail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0109, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<IRemoteObject> testToken;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId, testToken);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0110, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<IRemoteObject> testToken;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId, testToken);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0111, TestSize.Level1)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    sptr<IRemoteObject> testToken;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId, testToken);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0112, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0113, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0114, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0115, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0116, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0117, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0118, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0119, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}
} // namespace Print
} // namespace OHOS
