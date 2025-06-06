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
#define private public
#include "print_manager_client.h"
#undef private

#include "iservice_registry.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"
#include "mock_print_service.h"
#include "mock_remote_object.h"
#include "mock_print_callback_stub.h"
#include "mock_print_manager_client.h"

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
 * @tc.name: PrintManagerClientTest_0001_NeedRename
 * @tc.desc: StartPrint failed case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0001_NeedRename, TestSize.Level0)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    EXPECT_EQ(PrintManagerClient::GetInstance()->ready_, false);
}

/**
* @tc.name: PrintManagerClientTest_0002_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0002_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    EXPECT_EQ(PrintManagerClient::GetInstance()->StartPrint(testFileList, testFdList, testTaskId),
        E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0003_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0003_NeedRename, TestSize.Level0)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    EXPECT_EQ(PrintManagerClient::GetInstance()->ready_, false);

    PrintManagerClient::GetInstance()->ResetProxy();
    EXPECT_EQ(PrintManagerClient::GetInstance()->printServiceProxy_, nullptr);
}


/**
* @tc.name: PrintManagerClientTest_0004_NeedRename
* @tc.desc: StartPrint success case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0004_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0005_NeedRename
 * @tc.desc: StopPrint failed case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0005_NeedRename, TestSize.Level0)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0006_NeedRename
* @tc.desc: StopPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0006_NeedRename, TestSize.Level0)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0007_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0007_NeedRename, TestSize.Level0)
{
    std::string testTaskId = "2";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0008_NeedRename
* @tc.desc: StopPrint succedd case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0008_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0009_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0009_NeedRename, TestSize.Level0)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_00010_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_00010_NeedRename, TestSize.Level0)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0011_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0011_NeedRename, TestSize.Level0)
{
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}


/**
* @tc.name: PrintManagerClientTest_0012_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0012_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0013_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0013_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0014_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0014_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0015_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0015_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0016_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0016_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0017_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0017_NeedRename, TestSize.Level0)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0018_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0018_NeedRename, TestSize.Level0)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0019_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0019_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};
    std::vector<PrintExtensionInfo> extensionInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0020_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0020_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0021_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0021_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0022_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0022_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0023_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0023_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0024_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0024_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0025_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0025_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0026_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0026_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0027_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0027_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(testPrinterIds);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0028_NeedRename
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0028_NeedRename, TestSize.Level0)
{
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RemovePrinters(_)).Times(1);
    ON_CALL(*service, RemovePrinters).WillByDefault(
            [&testPrinterIds](const std::vector<std::string> &printerIds) {
                EXPECT_EQ(testPrinterIds.size(), printerIds.size());
                for (size_t index = 0; index < testPrinterIds.size(); index++) {
                    EXPECT_EQ(testPrinterIds[index], printerIds[index]);
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
 * @tc.name: PrintManagerClientTest_0029_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0029_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0030_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0030_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0031_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0031_NeedRename, TestSize.Level0)
{
    std::vector<PrinterInfo> printerInfos;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

/**
* @tc.name: PrintManagerClientTest_0032_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0032_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0033_NeedRename
 * @tc.desc: ConnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0033_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0034_NeedRename
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0034_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0035_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0035_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0036_NeedRename
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0036_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0037_NeedRename
 * @tc.desc: DisconnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0037_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0038_NeedRename
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0038_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0039_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0039_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}


/**
* @tc.name: PrintManagerClientTest_0040_NeedRename
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0040_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0041_NeedRename
 * @tc.desc: StartPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0041_NeedRename, TestSize.Level0)
{
    PrintJob jobinfo;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0042_NeedRename
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0042_NeedRename, TestSize.Level0)
{
    PrintJob jobinfo;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0043_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0043_NeedRename, TestSize.Level0)
{
    PrintJob jobinfo;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(jobinfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0044_NeedRename
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0044_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0045_NeedRename
 * @tc.desc: CancelPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0045_NeedRename, TestSize.Level0)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0046_NeedRename
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0046_NeedRename, TestSize.Level0)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0047_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0047_NeedRename, TestSize.Level0)
{
    std::string jobId = "jobId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0048_NeedRename
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0048_NeedRename, TestSize.Level0)
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
 * @tc.name: RestartPrintJob_WhenLoadSAFail_ShouldNopermission
 * @tc.desc: RestartPrintJob failed case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, RestartPrintJob_WhenLoadSAFail_ShouldNopermission, TestSize.Level2)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RestartPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: RestartPrintJob_WhenResetProxy_ShouldNopermission
* @tc.desc: RestartPrintJob failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, RestartPrintJob_WhenResetProxy_ShouldNopermission, TestSize.Level2)
{
    std::string jobId = "jobId-1";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RestartPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: RestartPrintJob_WhenLoadSAFailAndResetProxy_ShouldNopermission
* @tc.desc: RestartPrintJob failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, RestartPrintJob_WhenLoadSAFailAndResetProxy_ShouldNopermission, TestSize.Level2)
{
    std::string jobId = "jobId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RestartPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: RestartPrintJob_WhenLoadSASecc_ShouldSecc
* @tc.desc: RestartPrintJob succeed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, RestartPrintJob_WhenLoadSASucc_ShouldSucc, TestSize.Level0)
{
    std::string testJobId = "jobId-1";

    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RestartPrintJob(_)).Times(1);
    ON_CALL(*service, RestartPrintJob).WillByDefault(
            [&testJobId](const std::string &jobId) {
                EXPECT_EQ(testJobId, jobId);
                return E_PRINT_NONE;
            });
    sptr<MockRemoteObject> obj = new (std::nothrow) MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr = nullptr;
    CallRemoteObject(service, obj, dr);
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->RestartPrintJob(testJobId);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0049_NeedRename
 * @tc.desc: UpdatePrinterState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0049_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0050_NeedRename
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0050_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0051_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0051_NeedRename, TestSize.Level0)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(printerId, state);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0052_NeedRename
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0052_NeedRename, TestSize.Level0)
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
 * @tc.name: PrintManagerClientTest_0053_NeedRename
 * @tc.desc: UpdatePrintJobStateOnlyForSystemApp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0053_NeedRename, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0054_NeedRename
* @tc.desc: UpdatePrintJobStateOnlyForSystemApp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0054_NeedRename, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0055_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0055_NeedRename, TestSize.Level1)
{
    std::string printerId = "printerId-1";
    uint32_t state = 6;
    uint32_t subState = 6;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(printerId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0056_NeedRename
* @tc.desc: UpdatePrintJobStateOnlyForSystemApp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0056_NeedRename, TestSize.Level1)
{
    std::string testPrinterId = "printerId-1";
    uint32_t testState = 6;
    uint32_t testSubState = 6;
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdatePrintJobStateOnlyForSystemApp(_, _, _)).Times(1);
    ON_CALL(*service, UpdatePrintJobStateOnlyForSystemApp).WillByDefault(
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
    int32_t ret =
        PrintManagerClient::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(testPrinterId, testState, testSubState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
}

/**
 * @tc.name: PrintManagerClientTest_0057_NeedRename
 * @tc.desc: UpdateExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0057_NeedRename, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0058_NeedRename
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0058_NeedRename, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0059_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0059_NeedRename, TestSize.Level1)
{
    std::string extensionId = "extensionId-1";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0060_NeedRename
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0060_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0061_NeedRename
 * @tc.desc: RequestPreview
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0061_NeedRename, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0062_NeedRename
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0062_NeedRename, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0063_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0063_NeedRename, TestSize.Level1)
{
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(jobinfo, previewFilePath);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0064_NeedRename
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0064_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0065_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0065_NeedRename, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0066_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0066_NeedRename, TestSize.Level1)
{
    std::string testPrintId = "printId-123";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0067_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0067_NeedRename, TestSize.Level1)
{
    std::string testPrintId = "printId-123";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(testPrintId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0068_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0068_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0069_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0069_NeedRename, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0070_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0070_NeedRename, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0071_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0071_NeedRename, TestSize.Level1)
{
    std::vector<PrintJob> testPrintJobs;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(testPrintJobs);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0072_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0072_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0073_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0073_NeedRename, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0074_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0074_NeedRename, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0075_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0075_NeedRename, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(testPrintJobId, testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0076_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0076_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0077_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0077_NeedRename, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->On(testTaskId, testType, testListener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0078_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0078_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0079_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0079_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0080_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0080_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0081_NeedRename
 * @tc.desc: Off failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0081_NeedRename, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0082_NeedRename
* @tc.desc: Off failed2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0082_NeedRename, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0083_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0083_NeedRename, TestSize.Level1)
{
    std::string testTaskId = "taskId-123";
    std::string testType = "type";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->Off(testTaskId, testType);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0084_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0084_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0085_NeedRename
 * @tc.desc: RegisterExtCallback: invalid callback id of ext cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0085_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrintExtCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0086_NeedRename
 * @tc.desc: RegisterExtCallback: invalid callback id of job cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0086_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrintJobCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0087_NeedRename
 * @tc.desc: RegisterExtCallback: invalid callback id of printer cap cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0087_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrinterCapabilityCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: PrintManagerClientTest_0088_NeedRename
 * @tc.desc: RegisterExtCallback: invalid callback id of printer cb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0088_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_MAX + 100;
    PrinterCallback testCb = nullptr;

    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintManagerClientTest_0089_NeedRename
* @tc.desc: RegisterExtCallback: load serve failed for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0089_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0090_NeedRename
* @tc.desc: RegisterExtCallback: load serve failed for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0090_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0091_NeedRename
* @tc.desc: RegisterExtCallback: load serve failed for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0091_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0092_NeedRename
* @tc.desc: RegisterExtCallback: load serve failed for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0092_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0093_NeedRename
* @tc.desc: RegisterExtCallback: without proxy for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0093_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintExtCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0094_NeedRename
* @tc.desc: RegisterExtCallback: without proxy for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0094_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrintJobCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0095_NeedRename
* @tc.desc: RegisterExtCallback: without proxy for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0095_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0096_NeedRename
* @tc.desc: RegisterExtCallback: without proxy for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0096_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0097_NeedRename
* @tc.desc: RegisterExtCallback: ok for ext cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0097_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0098_NeedRename
* @tc.desc: RegisterExtCallback: ok for job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0098_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0099_NeedRename
* @tc.desc: RegisterExtCallback: ok for printer cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0099_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0100_NeedRename
* @tc.desc: RegisterExtCallback: ok for printer cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0100_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0101_NeedRename
 * @tc.desc: UnregisterAllExtCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0101_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0102_NeedRename
* @tc.desc: UnregisterAllExtCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0102_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UnregisterAllExtCallback(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0103_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0103_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0104_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0104_NeedRename, TestSize.Level1)
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
 * @tc.name: PrintManagerClientTest_0105_NeedRename
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0105_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0106_NeedRename
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0106_NeedRename, TestSize.Level1)
{
    std::string testExtensionId = "com.example.ext";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0107_NeedRename
* @tc.desc: StartPrint failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0107_NeedRename, TestSize.Level1)
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
* @tc.name: PrintManagerClientTest_0108_NeedRename
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0108_NeedRename, TestSize.Level1)
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

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0112_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0113_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0114_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0115_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0116_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0117_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0118_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0119_NeedRename, TestSize.Level1)
{
    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0121_NeedRename, TestSize.Level1)
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
	
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(printerId, printerInfo);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0122_NeedRename, TestSize.Level1)
{
    std::vector<std::string> printerNameList;
    printerNameList.push_back("1");
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryAddedPrinter(printerNameList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0123_NeedRename, TestSize.Level1)
{
    std::string printerId = "printId-123";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    keyList.push_back("1");
    valueList.push_back("1");
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterProperties(printerId, keyList, valueList);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0124_NeedRename, TestSize.Level1)
{
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    testPrintJob.SetJobId("jobId-123");
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartNativePrintJob(testPrintJob);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0125_NeedRename, TestSize.Level1)
{
    std::string printJobName = "jobName-123";
    sptr<IPrintCallback> testListener;
    PrintAttributes testPrintAttributes;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->Print(printJobName, testListener, testPrintAttributes);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0126_NeedRename, TestSize.Level1)
{
    std::string printJobName = "jobName-123";
    sptr<IPrintCallback> testListener;
    PrintAttributes testPrintAttributes;
    void* contextToken = nullptr;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->
        Print(printJobName, testListener, testPrintAttributes, contextToken);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0127_NeedRename, TestSize.Level1)
{
    std::string printJobName = "jobName-123";
    sptr<IPrintCallback> testListener;
    PrintAttributes testPrintAttributes;
    std::string taskId = "1";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->
        Print(printJobName, testListener, testPrintAttributes, taskId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0128_NeedRename, TestSize.Level1)
{
    std::string printJobName = "jobName-123";
    sptr<IPrintCallback> testListener;
    PrintAttributes testPrintAttributes;
    std::string taskId = "1";
    void* contextToken = nullptr;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->
        Print(printJobName, testListener, testPrintAttributes, taskId, contextToken);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0129_NeedRename, TestSize.Level1)
{
    std::string jobId = "1";
    PrintAttributes testPrintAttributes;
    uint32_t fd = 0;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->StartGetPrintFile(jobId, testPrintAttributes, fd);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0130_NeedRename, TestSize.Level1)
{
    std::string jobId = "1";
    std::string type = "";
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintService(jobId, type);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0131_NeedRename, TestSize.Level1)
{
    char callerFunN[] = "testName";
    char* callerFunName = callerFunN;
    std::function<int32_t(sptr<IPrintService>)> func = [](sptr<IPrintService>) -> int32_t {
        return 0;
    };
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->runBase(callerFunName, func);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0132_NeedRename, TestSize.Level1)
{
    std::string type = "test";
    NativePrinterChangeCallback cb = nullptr;
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(type, cb);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0133_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    int32_t ret = PrintManagerClient::GetInstance()->Init();
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0134_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    int32_t ret = mockPrintManagerClient.Init();
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0135_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::vector<std::string> testFileList = {"file://data/print/a.png",
        "file://data/print/b.png", "file://data/print/c.png"};
    std::vector<uint32_t> testFdList = {1, 2};
    std::string testTaskId = "2";
    int32_t ret = mockPrintManagerClient.StartPrint(testFileList, testFdList, testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0137_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::string testTaskId = "2";
    int32_t ret = mockPrintManagerClient.StopPrint(testTaskId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0138_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::string printerId = "2";
    int32_t ret = mockPrintManagerClient.ConnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0139_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::string printerId = "2";
    int32_t ret = mockPrintManagerClient.DisconnectPrinter(printerId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0140_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::vector<PrintExtensionInfo> extensionInfos;
    int32_t ret = mockPrintManagerClient.QueryAllExtension(extensionInfos);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0141_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    std::vector<std::string> testExtensionList = {"extensionId-1", "extensionId-2"};
    int32_t ret = mockPrintManagerClient.StartDiscoverPrinter(testExtensionList);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0142_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    int32_t ret = E_PRINT_NONE;
    mockPrintManagerClient.StopDiscoverPrinter();
    PrintJob jobinfo;
    mockPrintManagerClient.StartPrintJob(jobinfo);
    std::string testJobId = "jobId-1";
    mockPrintManagerClient.CancelPrintJob(testJobId);
    std::vector<PrinterInfo> printerInfos;
    mockPrintManagerClient.AddPrinters(printerInfos);
    std::vector<std::string> testPrinterIds = {"printerId-1", "printerId-2"};
    mockPrintManagerClient.RemovePrinters(testPrinterIds);
    mockPrintManagerClient.UpdatePrinters(printerInfos);
    std::string printerId = "2";
    uint32_t testState = 6;
    ret = mockPrintManagerClient.UpdatePrinterState(printerId, testState);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    std::string jobId = "jobId-1";
    uint32_t testSubState = 6;
    ret = mockPrintManagerClient.UpdatePrintJobStateOnlyForSystemApp(jobId, testState, testSubState);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0143_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    int32_t ret = E_PRINT_NONE;
    std::string extensionId = "extensionId-1";
    mockPrintManagerClient.UpdateExtensionInfo(extensionId);
    PrintJob jobinfo;
    std::string previewFilePath = "/data/temp/preview.png";
    mockPrintManagerClient.RequestPreview(jobinfo, previewFilePath);
    std::string printerId = "2";
    mockPrintManagerClient.QueryPrinterCapability(printerId);
    PrinterInfo printerInfo;
    mockPrintManagerClient.QueryPrinterInfoByPrinterId(printerId, printerInfo);
    std::vector<std::string> printerNameList;
    printerNameList.push_back("1");
    mockPrintManagerClient.QueryAddedPrinter(printerNameList);
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    keyList.push_back("1");
    valueList.push_back("1");
    mockPrintManagerClient.QueryPrinterProperties(printerId, keyList, valueList);
    mockPrintManagerClient.StartNativePrintJob(jobinfo);
    std::vector<PrintJob> printJobs;
    ret = mockPrintManagerClient.QueryAllPrintJob(printJobs);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    std::vector<PrinterInfo> printers;
    ret = mockPrintManagerClient.DiscoverUsbPrinters(printers);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0144_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    uint32_t event = 0;
    std::string jobId = "jobId";
    int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintServiceEvent(jobId, event);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0145_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    uint32_t event = 0;
    std::string jobId = "jobId";
    int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintServiceEvent(jobId, event);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0146_NeedRename, TestSize.Level1)
{
    MockPrintManagerClient mockPrintManagerClient;
    uint32_t event = 0;
    std::string jobId = "jobId";
    int32_t ret = E_PRINT_NONE;
    mockPrintManagerClient.NotifyPrintServiceEvent(jobId, event);
    std::string testPrintJobId = "jobId-123";
    PrintJob testPrintJob;
    mockPrintManagerClient.QueryPrintJobById(testPrintJobId, testPrintJob);
    std::string printerUri;
    std::string printerName;
    std::string printerMake;
    mockPrintManagerClient.AddPrinterToCups(printerUri, printerName, printerMake);
    std::string printerId;
    PrinterCapability printerCaps;
    mockPrintManagerClient.QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    std::string testTaskId = "taskId-123";
    std::string testType = "type";
    sptr<IPrintCallback> testListener;
    mockPrintManagerClient.On(testTaskId, testType, testListener);
    mockPrintManagerClient.Off(testTaskId, testType);
    std::string type = "";
    mockPrintManagerClient.NotifyPrintService(jobId, type);
    char callerFunN[] = "testName";
    char* callerFunName = callerFunN;
    std::function<int32_t(sptr<IPrintService>)> func = [](sptr<IPrintService>) -> int32_t {
        return 0;
    };
    mockPrintManagerClient.runBase(callerFunName, func);
    std::string testExtensionId = "com.example.ext";
    uint32_t testCallbackId = PRINT_EXTCB_START_DISCOVERY;
    PrinterCapabilityCallback testCb = nullptr;
    mockPrintManagerClient.RegisterExtCallback(testExtensionId, testCallbackId, testCb);
    PrintJobCallback jobCb = nullptr;
    mockPrintManagerClient.RegisterExtCallback(testExtensionId, testCallbackId, jobCb);
    PrinterCapabilityCallback capCb = nullptr;
    mockPrintManagerClient.RegisterExtCallback(testExtensionId, testCallbackId, capCb);
    PrinterCallback printerCb = nullptr;
    mockPrintManagerClient.RegisterExtCallback(testExtensionId, testCallbackId, printerCb);
    mockPrintManagerClient.UnregisterAllExtCallback(testExtensionId);
    NativePrinterChangeCallback cb = nullptr;
    ret = mockPrintManagerClient.SetNativePrinterChangeCallback(type, cb);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
    ret = mockPrintManagerClient.LoadExtSuccess(testExtensionId);
    EXPECT_EQ(ret, E_PRINT_RPC_FAILURE);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0147_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::string printerId = "printId-123";
    uint32_t type = 1;
    int32_t ret = PrintManagerClient::GetInstance()->SetDefaultPrinter(printerId, type);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0148_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    std::string printerId = "printId-123";
    uint32_t type = 1;
    int32_t ret = PrintManagerClient::GetInstance()->SetDefaultPrinter(printerId, type);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0149_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::string printerName;
    int32_t ret = PrintManagerClient::GetInstance()->DeletePrinterFromCups(printerName);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0150_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    std::string printerName;
    int32_t ret = PrintManagerClient::GetInstance()->DeletePrinterFromCups(printerName);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0153_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerSuccess();
    std::string printerId = "printId-123";
    PrinterPreferences printPreference;
    int32_t ret = PrintManagerClient::GetInstance()->SetPrinterPreference(printerId, printPreference);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0154_NeedRename, TestSize.Level1)
{
    PrintManagerClient::GetInstance()->LoadServerFail();
    std::string printerId = "printId-123";
    PrinterPreferences printPreference;
    int32_t ret = PrintManagerClient::GetInstance()->SetPrinterPreference(printerId, printPreference);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0155_NeedRename, TestSize.Level1)
{
    std::vector<PrinterInfo> testPrinters;

    PrintManagerClient::GetInstance()->LoadServerFail();
    int32_t ret = PrintManagerClient::GetInstance()->DiscoverUsbPrinters(testPrinters);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0156_NeedRename, TestSize.Level1)
{
    std::vector<PrinterInfo> testPrinters;

    PrintManagerClient::GetInstance()->LoadServerSuccess();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DiscoverUsbPrinters(testPrinters);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0157_NeedRename, TestSize.Level1)
{
    std::vector<PrinterInfo> testPrinters;

    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->DiscoverUsbPrinters(testPrinters);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0158_NeedRename
* @tc.desc: AddPrinterToDiscovery failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0158_NeedRename, TestSize.Level1)
{
    PrinterInfo info;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToDiscovery(info);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0159_NeedRename
* @tc.desc: UpdatePrinterInDiscovery failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0159_NeedRename, TestSize.Level1)
{
    PrinterInfo info;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterInDiscovery(info);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0160_NeedRename
* @tc.desc: RemovePrinterFromDiscovery failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0160_NeedRename, TestSize.Level1)
{
    std::string printerId = "test";
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinterFromDiscovery(printerId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintManagerClientTest_0161_NeedRename
* @tc.desc: UpdatePrinterInSystem failed case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0161_NeedRename, TestSize.Level1)
{
    PrinterInfo info;
    PrintManagerClient::GetInstance()->LoadServerFail();
    PrintManagerClient::GetInstance()->ResetProxy();
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterInSystem(info);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

} // namespace Print
} // namespace OHOS
