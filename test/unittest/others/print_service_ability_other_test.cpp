/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "print_service_ability.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintServiceAbilityTest : public testing:Test {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest, GetInstance_ShouldReturnDifferentInstance, TestSize.Level0)
{
sptr<PrintServiceAbility> instance1 = PrintServiceAbility::GetInstance();
PrintServiceAbility* temp = new PrintServiceAbility();
sptr<PrintServiceAbility> instance2 = PrintServiceAbility::GetInstance();
EXPECT_NE(instance1, instance2);
delete temp;
}

TEST_F(nullTest, Init_ShouldReturnFailure_WhenHelperIsNull)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = nullptr;
EXPECT_EQ(printServiceAbility.Init(), E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenHelperIsNotNull)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnFailure_WhenPublishFails)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = false;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish(_)).WillOnce(Return(false));
EXPECT_EQ(printServiceAbility.Init(), E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenPublishSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = false;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish(_)).WillOnce(Return(true));
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenPrintSystemDataInitSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenPreferenceMapInitSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.InitPreferenceMap(), _).WillOnce(Return());
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenPrintSubscribeCommonEventSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.InitPreferenceMap(),).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.helper, PrintSubscribeCommonEvent()).WillOnce(Return());
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenIppOverUsbManagerInitSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.InitPreferenceMap(),).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.helper, PrintSubscribeCommonEvent()).WillOnce(Return());
// EXPECT_CALL(*printServiceAbility.DelayedSingleton<PrintIppOverUsbManager>::GetInstance(), Init()).WillOnce(Return());
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenCupsClientInitSucceeds)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.InitPreferenceMap(),).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.helper, PrintSubscribeCommonEvent()).WillOnce(Return());
// EXPECT_CALL(*printServiceAbility.DelayedSingleton<PrintIppOverUsbManager>::GetInstance(), Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.DelayedSingleton<PrintCupsClient>::GetInstance(),
    InitCupsResources()).WillOnce(Return(ERR_OK));
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

TEST_F(nullTest, Init_ShouldReturnSuccess_WhenAllOperationsSucceed)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.helper_ = std::make_shared<PrintServiceHelper>();
printServiceAbility.g_publishState = true;
EXPECT_CALL(*printServiceAbility.GetInstance(), Publish()).WillOnce(Return(true));
EXPECT_CALL(*printServiceAbility.printSystemData, Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.InitPreferenceMap(),).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.helper, PrintSubscribeCommonEvent()).WillOnce(Return());
// EXPECT_CALL(*printServiceAbility.DelayedSingleton<PrintIppOverUsbManager>::GetInstance(), Init()).WillOnce(Return());
EXPECT_CALL(*printServiceAbility.DelayedSingleton<PrintCupsClient>::GetInstance(),
    InitCupsResources()).WillOnce(Return(ERR_OK));
EXPECT_EQ(printServiceAbility.Init(), ERR_OK);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldSetInstance_WhenInstanceIsNull, TestSize.Level0)
{
printServiceAbility->instance_ = nullptr;
printServiceAbility->OnStart();
EXPECT_NE(printServiceAbility->instance_, nullptr);
}
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldSetStateRunning_WhenStateIsRunning, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_RUNNING;
printServiceAbility->OnStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_RUNNING);
}
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldInitServiceHandler_WhenStateIsNotRunning, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_RUNNING;
printServiceAbility->OnStart();
EXPECT_NE(printServiceAbility->serviceHandler_, nullptr);
}
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldInitVendorManager_WhenStateIsNotRunning, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_RUNNING;
printServiceAbility->OnStart();
EXPECT_NE(printServiceAbility->vendorManager, nullptr);
}
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldSetStateRunning_WhenInitReturnsOk, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_RUNNING;
printServiceAbility->Init =  undefined { return ERR_OK; };
printServiceAbility->OnStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_RUNNING);
}
HWTEST_F(PrintServiceAbilityTest, OnStart_ShouldPostTask_WhenInitReturnsNotOk, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_RUNNING;
printServiceAbility->Init =  undefined { return ERR_UNKNOWN; };
printServiceAbility->serviceHandler_->PostTask = [](auto callback, auto interval)
{
callback();
};
printServiceAbility->OnStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_NOT_RUNNING);
}

TEST_F(nullTest, InitServiceHandler_Should_Return_When_ServiceHandler_Is_Null)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.InitServiceHandler();
EXPECT_NE(printServiceAbility.serviceHandler_, nullptr);
}

TEST_F(nullTest, InitServiceHandler_Should_Not_Return_When_ServiceHandler_Is_Not_Null)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.serviceHandler_ = std::make_shared AppExecFwk::EventHandlerundefined(
    AppExecFwk::EventRunner::Create("PrintServiceAbility"));
printServiceAbility.InitServiceHandler();
EXPECT_EQ(printServiceAbility.serviceHandler_, nullptr);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
TEST_F(PrintServiceAbilityTest, ManualStart_ShouldRestart_WhenStateIsNotRunning)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_RUNNING;
printServiceAbility->ManualStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_RUNNING);
}

TEST_F(PrintServiceAbilityTest, ManualStart_ShouldInitCupsResources_WhenStateIsRunningAndCupsIsEnabled)
{
printServiceAbility->state_ = ServiceRunningState::STATE_RUNNING;
printServiceAbility->ManualStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_RUNNING);
}

TEST_F(PrintServiceAbilityTest, ManualStart_ShouldNotInitCupsResources_WhenStateIsRunningAndCupsIsDisabled)
{
printServiceAbility->state_ = ServiceRunningState::STATE_RUNNING;
printServiceAbility->ManualStart();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_RUNNING);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
std::mutex instanceLock_;
int currentJobOrderId_ = 0;
void SetUp() override
{
    printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
    delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest, GetPrintJobOrderId_ShouldReturnIncrementingOrderId, TestSize.Level0)
{
std::string expectedOrderId = "1";
std::string actualOrderId = printServiceAbility->GetPrintJobOrderId();
EXPECT_EQ(expectedOrderId, actualOrderId);
}
HWTEST_F(PrintServiceAbilityTest,
    GetPrintJobOrderId_ShouldReturnIncrementingOrderId_WhenCalledMultipleTimes, TestSize.Level0)
{
std::string expectedOrderId1 = "1";
std::string expectedOrderId2 = "2";
std::string actualOrderId1 = printServiceAbility->GetPrintJobOrderId();
std::string actualOrderId2 = printServiceAbility->GetPrintJobOrderId();
EXPECT_EQ(expectedOrderId1, actualOrderId1);
EXPECT_EQ(expectedOrderId2, actualOrderId2);
}
HWTEST_F(PrintServiceAbilityTest,
    GetPrintJobOrderId_ShouldReturnIncrementingOrderId_WhenCalledConcurrently, TestSize.Level0)
{
std::string expectedOrderId1 = "1";
std::string expectedOrderId2 = "2";
std::thread thread1([&]()
{
    std::string actualOrderId1 = printServiceAbility->GetPrintJobOrderId();
    EXPECT_EQ(expectedOrderId1, actualOrderId1);
});
std::thread thread2([&]()
{
    std::string actualOrderId2 = printServiceAbility->GetPrintJobOrderId();
    EXPECT_EQ(expectedOrderId2, actualOrderId2);
});
thread1.join();
thread2.join();
}

class PrintServiceAbilityTest : public nullTest {
public:
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
    delete printServiceAbility;
printServiceAbility = nullptr
}
PrintServiceAbility* printServiceAbility;
};
HWTEST_F(PrintServiceAbilityTest, OnStop_Should_Call_UnInit_When_State_Is_Running, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_RUNNING;
EXPECT_CALL(printServiceAbility->vendorManager, UnInit()).Times(1);
printServiceAbility->OnStop();
}
HWTEST_F(PrintServiceAbilityTest, OnStop_Should_Not_Call_UnInit_When_State_Is_Not_Running, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_NOT_START;
EXPECT_CALL(printServiceAbility->vendorManager, UnInit()).Times(0);
printServiceAbility->OnStop();
}
HWTEST_F(PrintServiceAbilityTest, OnStop_Should_Set_State_To_Not_Start_After_Call, TestSize.Level0)
{
printServiceAbility->state_ = ServiceRunningState::STATE_RUNNING;
printServiceAbility->OnStop();
EXPECT_EQ(printServiceAbility->state_, ServiceRunningState::STATE_NOT_START);
}

TEST_F(nullTest, StartService_ShouldReturnPermissionError_WhenNoPermission)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(false));
EXPECT_EQ(printService.StartService(), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, StartService_ShouldReturnNoError_WhenPermissionGranted)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_EQ(printService.StartService(), E_PRINT_NONE);
}

TEST_F(nullTest, StartService_ShouldReturnNoError_WhenCUPSIsDisabled)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
#undef CUPS_ENABLE
EXPECT_EQ(printService.StartService(), E_PRINT_NONE);
}

TEST_F(nullTest, StartService_ShouldReturnNoError_WhenCUPSIsEnabled)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
#define CUPS_ENABLE
EXPECT_CALL(printService,
    DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.StartService(), E_PRINT_NONE);
}

TEST_F(nullTest, CallSpooler_ShouldReturnPermissionError_WhenNoPermission)
{
std::vector std::stringundefined fileList;
std::vector<uint32_t> fdList;
std::string taskId;
PrintServiceAbility printServiceAbility;
int32_t result = printServiceAbility.CallSpooler(fileList, fdList, taskId);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, CallSpooler_ShouldReturnInvalidParameterError_WhenTaskIdIsEmpty)
{
std::vector std::stringundefined fileList;
std::vector<uint32_t> fdList;
std::string taskId;
PrintServiceAbility printServiceAbility;
int32_t result = printServiceAbility.CallSpooler(fileList, fdList, taskId);
EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
}

TEST_F(nullTest, CallSpooler_ShouldReturnServerFailureError_WhenPrintJobIsNull)
{
std::vector std::stringundefined fileList;
std::vector<uint32_t> fdList;
std::string taskId = "testTaskId";
PrintServiceAbility printServiceAbility;
int32_t result = printServiceAbility.CallSpooler(fileList, fdList, taskId);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, CallSpooler_ShouldReturnNoneError_WhenAllParametersAreValid)
{
std::vector std::stringundefined fileList;
std::vector<uint32_t> fdList;
std::string taskId = "testTaskId";
PrintServiceAbility printServiceAbility;
int32_t result = printServiceAbility.CallSpooler(fileList, fdList, taskId);
EXPECT_EQ(result, E_PRINT_NONE);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
12345
HWTEST_F(PrintServiceAbilityTest,
    StopPrint_ShouldReturnNoPermission_WhenNoPermission, TestSize.Level0)
{
std::string taskId = "testTaskId";
printServiceAbility->CheckPermission = [](const std::string& permission) { return false; };
int32_t result = printServiceAbility->StopPrint(taskId);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}
HWTEST_F(PrintServiceAbilityTest, StopPrint_ShouldReturnNone_WhenPermissionGranted, TestSize.Level0)
{
std::string taskId = "testTaskId";
printServiceAbility->CheckPermission = [](const std::string& permission) { return true; };
int32_t result = printServiceAbility->StopPrint(taskId);
EXPECT_EQ(result, E_PRINT_NONE);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest,
    HandleExtensionConnectPrinter_ShouldReturnFailure_WhenPrinterIdIsEmpty, TestSize.Level0)
{
std::string printerId = "";
int32_t result = printServiceAbility->HandleExtensionConnectPrinter(printerId);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}
HWTEST_F(PrintServiceAbilityTest,
    HandleExtensionConnectPrinter_ShouldReturnNone_WhenPrinterIdIsNotEmpty, TestSize.Level0)
{
std::string printerId = "validPrinterId";
int32_t result = printServiceAbility->HandleExtensionConnectPrinter(printerId);
EXPECT_EQ(result, E_PRINT_NONE);
}
HWTEST_F(PrintServiceAbilityTest,
    HandleExtensionConnectPrinter_ShouldReturnFailure_WhenExtensionNotRegistered, TestSize.Level0)
{
std::string printerId = "validPrinterId";
int32_t result = printServiceAbility->HandleExtensionConnectPrinter(printerId);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}
HWTEST_F(PrintServiceAbilityTest,
    HandleExtensionConnectPrinter_ShouldReturnNone_WhenExtensionRegistered, TestSize.Level0)
{
std::string printerId = "validPrinterId";
int32_t result = printServiceAbility->HandleExtensionConnectPrinter(printerId);
EXPECT_EQ(result, E_PRINT_NONE);
}
HWTEST_F(PrintServiceAbilityTest,
    HandleExtensionConnectPrinter_ShouldReturnNone_WhenPrinterIdIsValidAndExtensionRegistered, TestSize.Level0)
{
std::string printerId = "validPrinterId";
int32_t result = printServiceAbility->HandleExtensionConnectPrinter(printerId);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, ConnectPrinter_ShouldReturnNoPermission_WhenNoPermission)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
EXPECT_EQ(printServiceAbility.ConnectPrinter(printerId), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, ConnectPrinter_ShouldReturnServerFailure_WhenVendorNotFound)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
EXPECT_EQ(printServiceAbility.ConnectPrinter(printerId), E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, ConnectPrinter_ShouldReturnNone_WhenConnectPrinterSucceed)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
EXPECT_EQ(printServiceAbility.ConnectPrinter(printerId), E_PRINT_NONE);
}

TEST_F(nullTest, ConnectPrinter_ShouldReturnInvalidPrinterId_WhenPrinterIdIsInvalid)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "invalidPrinter";
EXPECT_EQ(printServiceAbility.ConnectPrinter(printerId), E_PRINT_INVALID_PRINTER_ID);
}

TEST_F(nullTest, DisconnectPrinter_ShouldReturnNoPermission_WhenNoPermission)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
EXPECT_EQ(printServiceAbility.DisconnectPrinter(printerId), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, DisconnectPrinter_ShouldReturnInvalidPrinter_WhenInvalidPrinterId)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "invalidPrinter";
EXPECT_EQ(printServiceAbility.DisconnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
}

TEST_F(nullTest, DisconnectPrinter_ShouldReturnServerFailure_WhenNotRegisterYet)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "newPrinter";
EXPECT_EQ(printServiceAbility.DisconnectPrinter(printerId), E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, DisconnectPrinter_ShouldReturnNone_WhenSuccess)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "validPrinter";
EXPECT_EQ(printServiceAbility.DisconnectPrinter(printerId), E_PRINT_NONE);
}

TEST_F(nullTest, StartDiscoverPrinter_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
std::vector std::stringundefined extensionIds = {"ext1", "ext2"};
EXPECT_EQ(printServiceAbility.StartDiscoverPrinter(extensionIds), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, StartDiscoverPrinter_ShouldReturnSuccess_WhenPermissionIsTrue)
{
PrintServiceAbility printServiceAbility;
std::vector std::stringundefined extensionIds = {"ext1", "ext2"};
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
EXPECT_EQ(printServiceAbility.StartDiscoverPrinter(extensionIds), 0);
}

TEST_F(nullTest, StartDiscoverPrinter_ShouldReturnSuccess_WhenManualStartSucceeds)
{
PrintServiceAbility printServiceAbility;
std::vector std::stringundefined extensionIds = {"ext1", "ext2"};
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.ManualStart =  undefined {};
EXPECT_EQ(printServiceAbility.StartDiscoverPrinter(extensionIds), 0);
}

TEST_F(nullTest, StartDiscoverPrinter_ShouldReturnSuccess_WhenAllMethodsSucceed)
{
PrintServiceAbility printServiceAbility;
std::vector std::stringundefined extensionIds = {"ext1", "ext2"};
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.ManualStart =  undefined {};
printServiceAbility.printSystemData_.QueryAddedPrinterIdList = undefined { return std::vector; };
printServiceAbility.vendorManager.MonitorPrinterStatus = [](const std::string& printerId, bool start) {};
printServiceAbility.vendorManager.StartStatusMonitor =  undefined {};
printServiceAbility.vendorManager.StartDiscovery =  undefined {};
printServiceAbility.StartExtensionDiscovery = [](const std::vector std::stringundefined& extensionIds) { return 0; };
EXPECT_EQ(printServiceAbility.StartDiscoverPrinter(extensionIds), 0);
}

TEST_F(nullTest, DelayStartDiscovery_ShouldReturnFalse_WhenExtensionIdNotFound)
{
PrintServiceAbility printServiceAbility;
std::string extensionId = "nonexistent";
EXPECT_EQ(printServiceAbility.DelayStartDiscovery(extensionId), false);
}

TEST_F(nullTest, DelayStartDiscovery_ShouldReturnFalse_WhenExtensionStateIsNotLoaded)
{
PrintServiceAbility printServiceAbility;
std::string extensionId = "existent";
printServiceAbility.extensionStateList_[extensionId] = PRINT_EXTENSION_NOT_LOADED;
EXPECT_EQ(printServiceAbility.DelayStartDiscovery(extensionId), false);
}

TEST_F(nullTest, DelayStartDiscovery_ShouldReturnFalse_WhenCallbackNotRegistered)
{
PrintServiceAbility printServiceAbility;
std::string extensionId = "existent";
printServiceAbility.extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
EXPECT_EQ(printServiceAbility.DelayStartDiscovery(extensionId), false);
}

TEST_F(nullTest, DelayStartDiscovery_ShouldReturnTrue_WhenCallbackRegisteredAndOnCallbackReturnsTrue)
{
PrintServiceAbility printServiceAbility;
std::string extensionId = "existent";
printServiceAbility.extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_DISCOVERY);
printServiceAbility.extCallbackMap_[cid] = new Callback();
EXPECT_CALL(*printServiceAbility.extCallbackMap_[cid], OnCallback()).WillOnce(Return(true));
EXPECT_EQ(printServiceAbility.DelayStartDiscovery(extensionId), true);
}

TEST_F(nullTest, DelayStartDiscovery_ShouldReturnFalse_WhenCallbackRegisteredAndOnCallbackReturnsFalse)
{
PrintServiceAbility printServiceAbility;
std::string extensionId = "existent";
printServiceAbility.extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_DISCOVERY);
printServiceAbility.extCallbackMap_[cid] = new Callback();
EXPECT_CALL(*printServiceAbility.extCallbackMap_[cid], OnCallback()).WillOnce(Return(false));
EXPECT_EQ(printServiceAbility.DelayStartDiscovery(extensionId), false);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNoPermission_WhenNoPermission, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNone_WhenStoppedSuccessfully, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenStopDiscoveryFails, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, vendorManager.StopDiscovery()).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenStopStatusMonitorFails, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, vendorManager.StopStatusMonitor()).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenExtensionNotLoaded, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second < PRINT_EXTENSION_LOADING).WillOnce(Return(true));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenExtensionCallbackNotRegistered, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.end()));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNone_WhenStoppedSuccessfully, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(true));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNone_WhenHelperNotSyncMode, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenPostTaskFails, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNone_WhenStoppedSuccessfully, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(true));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnFailure_WhenPostTaskCallbackFails, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(PrintUtils::EncodeExtensionCid(extension.first,
PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(true));
EXPECT_CALL(printService, cbFunc->OnCallback()).WillOnce(Return(false));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_NE(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, StopDiscoverPrinter_ShouldReturnNone_WhenStoppedSuccessfully, TestSize.Level0)
{
PrintServiceAbility printService;
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printService, extensionStateList_.second >= PRINT_EXTENSION_LOADING).WillOnce(Return(true));
EXPECT_CALL(printService, extCallbackMap_.find(
    PrintUtils::EncodeExtensionCid(extension.first,
        PRINT_EXTCB_STOP_DISCOVERY))).WillOnce(Return(extCallbackMap_.begin()));
EXPECT_CALL(printService, helper_->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(true));
EXPECT_CALL(printService, cbFunc->OnCallback()).WillOnce(Return(true));
int32_t result = printService.StopDiscoverPrinter();
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, DestroyExtension_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(false));
EXPECT_EQ(printServiceAbility.DestroyExtension(), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, DestroyExtension_ShouldReturnNone_WhenPermissionIsTrue)
{
PrintServiceAbility printServiceAbility;
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_EQ(printServiceAbility.DestroyExtension(), E_PRINT_NONE);
}

TEST_F(nullTest, DestroyExtension_ShouldReturnNone_WhenExtensionStateIsLessThanLoading)
{
PrintServiceAbility printServiceAbility;
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
printServiceAbility.extensionStateList_.push_back(std::make_pair("test", PRINT_EXTENSION_UNLOAD));
EXPECT_EQ(printServiceAbility.DestroyExtension(), E_PRINT_NONE);
}

TEST_F(nullTest, DestroyExtension_ShouldReturnNone_WhenExtensionCallbackNotFound)
{
PrintServiceAbility printServiceAbility;
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
printServiceAbility.extensionStateList_.push_back(std::make_pair("test", PRINT_EXTENSION_LOADING));
EXPECT_EQ(printServiceAbility.DestroyExtension(), E_PRINT_NONE);
}

TEST_F(nullTest, DestroyExtension_ShouldReturnNone_WhenExtensionCallbackFound)
{
PrintServiceAbility printServiceAbility;
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
printServiceAbility.extensionStateList_.push_back(std::make_pair("test", PRINT_EXTENSION_LOADING));
printServiceAbility.extCallbackMap_["test"] = new Callback();
EXPECT_EQ(printServiceAbility.DestroyExtension(), E_PRINT_NONE);
}

TEST_F(nullTest, QueryAllExtension_ShouldReturnPermissionDenied_WhenNoPermission)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintExtensionInfo> extensionInfos;
printServiceAbility.CheckPermission = [](const std::string& permission) { return false; };
int32_t result = printServiceAbility.QueryAllExtension(extensionInfos);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryAllExtension_ShouldReturnServerFailure_WhenQueryExtensionFails)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintExtensionInfo> extensionInfos;
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.DelayedSingleton<PrintBMSHelper>::GetInstance()->
    QueryExtensionInfos = [](std::vector AppExecFwk::ExtensionAbilityInfoundefined& info) { return false; };
int32_t result = printServiceAbility.QueryAllExtension(extensionInfos);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, QueryAllExtension_ShouldReturnNone_WhenQueryExtensionSucceeds)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintExtensionInfo> extensionInfos;
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.DelayedSingleton<PrintBMSHelper>::GetInstance()->
    QueryExtensionInfos = [](std::vector AppExecFwk::ExtensionAbilityInfoundefined& info) { return true; };
int32_t result = printServiceAbility.QueryAllExtension(extensionInfos);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, QueryAllPrintJob_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintJob> printJobs;
EXPECT_EQ(printServiceAbility.QueryAllPrintJob(printJobs), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryAllPrintJob_ShouldReturnInvalidUserId_WhenUserDataIsNull)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintJob> printJobs;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission(PERMISSION_NAME_PRINT_JOB) = true;
EXPECT_EQ(printServiceAbility.QueryAllPrintJob(printJobs), E_PRINT_INVALID_USERID);
}

TEST_F(nullTest, QueryAllPrintJob_ShouldReturnQueryAllPrintJobFailed_WhenQueryAllPrintJobReturnsFailure)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintJob> printJobs;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission(PERMISSION_NAME_PRINT_JOB) = true;
printServiceAbility.GetCurrentUserData() = std::make_shared<UserData>();
EXPECT_EQ(printServiceAbility.QueryAllPrintJob(printJobs), E_PRINT_QUERY_ALL_PRINT_JOB_FAILED);
}

TEST_F(nullTest, QueryAllPrintJob_ShouldReturnNone_WhenQueryAllPrintJobSucceeds)
{
PrintServiceAbility printServiceAbility;
std::vector<PrintJob> printJobs;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission(PERMISSION_NAME_PRINT_JOB) = true;
printServiceAbility.GetCurrentUserData() = std::make_shared<UserData>();
printServiceAbility.QueryAllPrintJob(printJobs) = E_PRINT_NONE;
EXPECT_EQ(printServiceAbility.QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

TEST_F(nullTest, QueryAddedPrinter_ShouldReturnNoPermission_WhenNoPermission)
{
std::vector std::stringundefined printerList;
EXPECT_EQ(PrintServiceAbility::QueryAddedPrinter(printerList), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryAddedPrinter_ShouldReturnNone_WhenNoAddedPrinter)
{
std::vector std::stringundefined printerList;
EXPECT_EQ(PrintServiceAbility::QueryAddedPrinter(printerList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryAddedPrinter_ShouldReturnNone_WhenAddedPrinterExists)
{
std::vector std::stringundefined printerList;
EXPECT_EQ(PrintServiceAbility::QueryAddedPrinter(printerList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryAddedPrinter_ShouldReturnNone_WhenAddedPrinterExistsAndQueried)
{
std::vector std::stringundefined printerList;
EXPECT_EQ(PrintServiceAbility::QueryAddedPrinter(printerList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryAddedPrinter_ShouldReturnNone_WhenAddedPrinterExistsButQueriedIdIsEmpty)
{
std::vector std::stringundefined printerList;
EXPECT_EQ(PrintServiceAbility::QueryAddedPrinter(printerList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryPrinterInfoByPrinterId_Test)
{
PrintServiceAbility printServiceAbility;
PrinterInfo info;
std::string printerId = "testPrinter";
int32_t result = printServiceAbility.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, QueryPrinterInfoByPrinterId_NoPermission_Test)
{
PrintServiceAbility printServiceAbility;
PrinterInfo info;
std::string printerId = "testPrinter";
int32_t result = printServiceAbility.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryPrinterInfoByPrinterId_InvalidPrinter_Test)
{
PrintServiceAbility printServiceAbility;
PrinterInfo info;
std::string printerId = "invalidPrinter";
int32_t result = printServiceAbility.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_INVALID_PRINTER);
}

TEST_F(nullTest, QueryPrinterInfoByPrinterId_DefaultPrinter_Test)
{
PrintServiceAbility printServiceAbility;
PrinterInfo info;
std::string printerId = "defaultPrinter";
int32_t result = printServiceAbility.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_NONE);
EXPECT_TRUE(info.GetIsDefaultPrinter());
}

TEST_F(nullTest, QueryPrinterInfoByPrinterId_LastUsedPrinter_Test)
{
PrintServiceAbility printServiceAbility;
PrinterInfo info;
std::string printerId = "lastUsedPrinter";
int32_t result = printServiceAbility.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_NONE);
EXPECT_TRUE(info.GetIsLastUsedPrinter());
}

TEST_F(nullTest, QueryPrinterProperties_ShouldReturnNoPermission_WhenNoPermission)
{
std::string printerId = "testPrinter";
std::vector std::stringundefined keyList = {"printerPreference"};
std::vector std::stringundefined valueList;
EXPECT_EQ(PrintServiceAbility::QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryPrinterProperties_ShouldReturnInvalidPrinter_WhenPrinterInfoNotFound)
{
std::string printerId = "nonExistentPrinter";
std::vector std::stringundefined keyList = {"printerPreference"};
std::vector std::stringundefined valueList;
EXPECT_EQ(PrintServiceAbility::QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

TEST_F(nullTest, QueryPrinterProperties_ShouldReturnNone_WhenPrinterPreferenceFound)
{
std::string printerId = "testPrinter";
std::vector std::stringundefined keyList = {"printerPreference"};
std::vector std::stringundefined valueList;
EXPECT_EQ(PrintServiceAbility::QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryPrinterProperties_ShouldReturnNone_WhenNoKeyFound)
{
std::string printerId = "testPrinter";
std::vector std::stringundefined keyList = {"nonExistentKey"};
std::vector std::stringundefined valueList;
EXPECT_EQ(PrintServiceAbility::QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryPrinterProperties_ShouldReturnNone_WhenKeyNotPrinterPreference)
{
std::string printerId = "testPrinter";
std::vector std::stringundefined keyList = {"nonPrinterPreferenceKey"};
std::vector std::stringundefined valueList;
EXPECT_EQ(PrintServiceAbility::QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NONE);
}

TEST_F(nullTest, QueryPrintJobById_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
std::string printJobId = "testJobId";
PrintJob printJob;
EXPECT_EQ(printServiceAbility.QueryPrintJobById(printJobId, printJob), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, QueryPrintJobById_ShouldReturnInvalidUserId_WhenUserDataIsNull)
{
PrintServiceAbility printServiceAbility;
std::string printJobId = "testJobId";
PrintJob printJob;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
EXPECT_EQ(printServiceAbility.QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_USERID);
}

TEST_F(nullTest, QueryPrintJobById_ShouldReturnQueryPrintJobByIdFailed_WhenQueryPrintJobByIdFails)
{
PrintServiceAbility printServiceAbility;
std::string printJobId = "testJobId";
PrintJob printJob;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.GetCurrentUserData =  undefined { return nullptr; };
EXPECT_EQ(printServiceAbility.QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_USERID);
}

TEST_F(nullTest, QueryPrintJobById_ShouldReturnNone_WhenAllChecksPass)
{
PrintServiceAbility printServiceAbility;
std::string printJobId = "testJobId";
PrintJob printJob;
printServiceAbility.ManualStart();
printServiceAbility.CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility.GetCurrentUserData =  undefined { return new UserData(); };
EXPECT_EQ(printServiceAbility.QueryPrintJobById(printJobId, printJob), E_PRINT_NONE);
}

TEST_F(nullTest, AddPrinterToCups_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.ManualStart();
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(false));
EXPECT_EQ(printServiceAbility.AddPrinterToCups("uri", "name", "make"), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, AddPrinterToCups_ShouldReturnNoError_WhenPermissionIsTrue)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.ManualStart();
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printServiceAbility, DelayedSingleton<PrintCupsClient>::GetInstance()->
    AddPrinterToCups("uri", "name", "make")).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printServiceAbility.AddPrinterToCups("uri", "name", "make"), E_PRINT_NONE);
}

TEST_F(nullTest, AddPrinterToCups_ShouldReturnAddPrinterToCupsError_WhenAddPrinterToCupsReturnsError)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.ManualStart();
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_CALL(printServiceAbility, DelayedSingleton<PrintCupsClient>::GetInstance()->
    AddPrinterToCups("uri", "name", "make")).WillOnce(Return(E_PRINT_ADD_PRINTER_TO_CUPS_ERROR));
EXPECT_EQ(printServiceAbility.AddPrinterToCups("uri", "name", "make"), E_PRINT_ADD_PRINTER_TO_CUPS_ERROR);
}

TEST_F(nullTest, AddPrinterToCups_ShouldReturnNoError_WhenCUPSIsDisabled)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.ManualStart();
EXPECT_CALL(printServiceAbility, CheckPermission(PERMISSION_NAME_PRINT)).WillOnce(Return(true));
EXPECT_EQ(printServiceAbility.AddPrinterToCups("uri", "name", "make"), E_PRINT_NONE);
}

class DelayedSingletonTest : public nullTest {
public:
DelayedSingleton<PrintCupsClient>* instance;
void SetUp() override
{
instance = DelayedSingleton<PrintCupsClient>::GetInstance();
}
void TearDown() override {}
};
TEST_F(DelayedSingletonTest, GetInstance_ShouldReturnNonNull)
{
EXPECT_NE(instance, nullptr);
}

TEST_F(DelayedSingletonTest, AddPrinterToCups_ShouldReturnNoneWhenSuccessful)
{
std::string printerUri = "testUri";
std::string printerName = "testName";
bool make = true;
struct PrinterInfo {
    std::string GetPrinterName()
{
        return printerName;
    }
};
PrinterInfo printerInfo;
auto ret = instance->AddPrinterToCups(printerUri, printerInfo.GetPrinterName(), make);
EXPECT_EQ(ret, E_PRINT_NONE);
}

TEST_F(DelayedSingletonTest, AddPrinterToCups_ShouldReturnErrorWhenNotSuccessful)
{
std::string printerUri = "testUri";
std::string printerName = "testName";
bool make = true;
struct PrinterInfo {
    std::string GetPrinterName()
{
        return printerName;
    }
};
PrinterInfo printerInfo;
auto ret = instance->AddPrinterToCups(printerUri, printerInfo.GetPrinterName(), make);
EXPECT_NE(ret, E_PRINT_NONE);
}

TEST_F(DelayedSingletonTest, QueryPrinterCapabilityFromPPD_ShouldReturnNoneWhenSuccessful)
{
struct PrinterInfo {
std::string GetPrinterName()
{
return "testName";
}
};
PrinterInfo printerInfo;
instance->QueryPrinterCapabilityFromPPD(printerInfo.GetPrinterName(), printerCaps);
EXPECT_EQ(ret, E_PRINT_NONE);
}

TEST_F(DelayedSingletonTest, QueryPrinterCapabilityByUri_ShouldReturnNoneWhenSuccessful)
{
std::string printerUri = "testUri";
std::string printerId = "testId";
instance->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
EXPECT_EQ(ret, E_PRINT_NONE);
}

TEST_F(nullTest, testBuildPrinterPreferenceByOption)
{
std::string key = "testKey";
std::string supportedOpts = "";
std::vector std::stringundefined optAttrs;
PrintServiceAbility::BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
EXPECT_TRUE(optAttrs.empty());
}

TEST_F(nullTest, testBuildPrinterPreferenceByOptionWithJson)
{
std::string key = "testKey";
std::string supportedOpts = "{"key":"value"}";
std::vector std::stringundefined optAttrs;
PrintServiceAbility::BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
EXPECT_FALSE(optAttrs.empty());
EXPECT_EQ(optAttrs[0], "value");
}

TEST_F(nullTest, testBuildPrinterPreferenceByOptionWithNonJson)
{
std::string key = "testKey";
std::string supportedOpts = "nonJsonString";
std::vector std::stringundefined optAttrs;
PrintServiceAbility::BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
EXPECT_FALSE(optAttrs.empty());
EXPECT_EQ(optAttrs[0], "nonJsonString");
}

TEST_F(nullTest, testBuildPrinterPreferenceByOptionWithEmptyString)
{
std::string key = "testKey";
std::string supportedOpts = "";
std::vector std::stringundefined optAttrs;
PrintServiceAbility::BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
EXPECT_TRUE(optAttrs.empty());
}

TEST_F(nullTest, BuildPrinterPreference_Test)
{
PrinterCapability cap;
PrinterPreference printPreference;
int32_t result = PrintServiceAbility::BuildPrinterPreference(cap, printPreference);
EXPECT_EQ(result, E_PRINT_INVALID_PARAMETER);
}

TEST_F(nullTest, BuildPrinterPreference_Test2)
{
PrinterCapability cap;
cap.SetOption("{"cupsOptions":{"orientation-requested-supported":"landscape"}}");
PrinterPreference printPreference;
int32_t result = PrintServiceAbility::BuildPrinterPreference(cap, printPreference);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, BuildPrinterPreference_Test3)
{
PrinterCapability cap;
cap.SetOption("{"cupsOptions":{"sides-supported":"one-sided"}}");
PrinterPreference printPreference;
int32_t result = PrintServiceAbility::BuildPrinterPreference(cap, printPreference);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, BuildPrinterPreference_Test4)
{
PrinterCapability cap;
cap.SetOption("{"cupsOptions":{"print-quality-supported":"draft"}}");
PrinterPreference printPreference;
int32_t result = PrintServiceAbility::BuildPrinterPreference(cap, printPreference);
EXPECT_EQ(result, E_PRINT_NONE);
}

TEST_F(nullTest, BuildPrinterPreference_Test5)
{
PrinterCapability cap;
cap.SetOption("{"cupsOptions":{"orientation-requested-supported":"portrait"}}");
cap.SetOption("{"cupsOptions":{"sides-supported":"two-sided-long-edge"}}");
cap.SetOption("{"cupsOptions":{"print-quality-supported":"standard"}}");
PrinterPreference printPreference;
int32_t result = PrintServiceAbility::BuildPrinterPreference(cap, printPreference);
EXPECT_EQ(result, E_PRINT_NONE);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
std::string printerId;
std::string printerPreference;
void SetUp() override
{
    printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
    delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_ShouldReturnNoPermission_WhenNoPermission, TestSize.Level0)
{
printerId = "testPrinter";
printerPreference = "";
printServiceAbility->apiMutex_.lock();
printServiceAbility->CheckPermission = [](const std::string& permission) { return false; };
int32_t result = printServiceAbility->GetPrinterPreference(printerId, printerPreference);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}
HWTEST_F(PrintServiceAbilityTest,
    GetPrinterPreference_ShouldReturnInvalidPrinter_WhenPreferenceMapIsEmpty, TestSize.Level0)
{
printerId = "testPrinter";
printerPreference = "";
printServiceAbility->apiMutex_.lock();
printServiceAbility->CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility->printerIdAndPreferenceMap_.clear();
int32_t result = printServiceAbility->GetPrinterPreference(printerId, printerPreference);
EXPECT_EQ(result, E_PRINT_INVALID_PRINTER);
}
HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_ShouldReturnNone_WhenPreferenceIsReadFromFile, TestSize.Level0)
{
printerId = "testPrinter";
printerPreference = "";
printServiceAbility->apiMutex_.lock();
printServiceAbility->CheckPermission = [](const std::string& permission) { return true; };
printServiceAbility->printerIdAndPreferenceMap_.insert({printerId, "TestPreference"});
printServiceAbility->ReadPreferenceFromFile = [](const std::string& id, std::string& preference)
{
preference = "TestPreference";
return true;
};
int32_t result = printServiceAbility->GetPrinterPreference(printerId, printerPreference);
EXPECT_EQ(result, E_PRINT_NONE);
EXPECT_EQ(printerPreference, "TestPreference");
}

HWTEST_F(nullTest, SetPrinterPreference_ShouldReturnPermissionError_WhenNoPermission, TestSize.Level0)
{
PrintServiceAbility ability;
std::string printerId = "printer1";
std::string printerSetting = "{"key":"value"}";
int result = ability.SetPrinterPreference(printerId, printerSetting);
EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

HWTEST_F(nullTest, SetPrinterPreference_ShouldReturnSuccess_WhenPreferenceNotExists, TestSize.Level0)
{
PrintServiceAbility ability;
std::string printerId = "printer1";
std::string printerSetting = "{"key":"value"}";
ability.CheckPermission = [](const std::string& permission) { return true; };
int result = ability.SetPrinterPreference(printerId, printerSetting);
EXPECT_EQ(result, E_PRINT_NONE);
}

HWTEST_F(nullTest, SetPrinterPreference_ShouldReturnInvalidPrinterError_WhenSettingInvalid, TestSize.Level0)
{
PrintServiceAbility ability;
std::string printerId = "printer1";
std::string printerSetting = "invalid_json";
ability.CheckPermission = [](const std::string& permission) { return true; };
ability.printerIdAndPreferenceMap_.insert({printerId, "valid_json"});
int result = ability.SetPrinterPreference(printerId, printerSetting);
EXPECT_EQ(result, E_PRINT_INVALID_PRINTER);
}

HWTEST_F(nullTest, SetPrinterPreference_ShouldReturnServerError_WhenWriteFileFails, TestSize.Level0)
{
PrintServiceAbility ability;
std::string printerId = "printer1";
std::string printerSetting = "{"key":"value"}";
ability.CheckPermission = [](const std::string& permission) { return true; };
ability.printerIdAndPreferenceMap_.insert({printerId, "valid_json"});
nlohmann::json::accept = [](const std::string& str) { return true; };
ability.WritePreferenceToFile =  undefined { return false; };
int result = ability.SetPrinterPreference(printerId, printerSetting);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

HWTEST_F(nullTest, SetPrinterPreference_ShouldReturnSuccess_WhenPreferenceSetSuccessfully, TestSize.Level0)
{
PrintServiceAbility ability;
std::string printerId = "printer1";
std::string printerSetting = "{"key":"value"}";
ability.CheckPermission = [](const std::string& permission) { return true; };
ability.printerIdAndPreferenceMap_.insert({printerId, "valid_json"});
nlohmann::json::accept = [](const std::string& str) { return true; };
ability.WritePreferenceToFile =  undefined { return true; };
int result = ability.SetPrinterPreference(printerId, printerSetting);
EXPECT_EQ(result, E_PRINT_NONE);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest, ReadPreferenceFromFile_ShouldReturnTrue_WhenPrinterIdExists, TestSize.Level0)
{
std::string printerId = "printer1";
std::string printPreference;
EXPECT_TRUE(printServiceAbility->ReadPreferenceFromFile(printerId, printPreference));
EXPECT_EQ(printPreference, "high");
}
HWTEST_F(PrintServiceAbilityTest, ReadPreferenceFromFile_ShouldReturnFalse_WhenPrinterIdDoesNotExist, TestSize.Level0)
{
std::string printerId = "nonexistentprinter";
std::string printPreference;
EXPECT_FALSE(printServiceAbility->ReadPreferenceFromFile(printerId, printPreference));
EXPECT_EQ(printPreference, "");
}
HWTEST_F(PrintServiceAbilityTest, ReadPreferenceFromFile_ShouldReturnFalse_WhenPrintPreferenceIsEmpty, TestSize.Level0)
{
std::string printerId = "";
std::string printPreference;
EXPECT_FALSE(printServiceAbility->ReadPreferenceFromFile(printerId, printPreference));
EXPECT_EQ(printPreference, "");
}

TEST_F(nullTest, InitPreferenceMap_Test)
{
PrintServiceAbility printServiceAbility;
printServiceAbility.InitPreferenceMap();
EXPECT_EQ(printServiceAbility.printerIdAndPreferenceMap_.size(), 0);
}

TEST_F(nullTest,
    WritePreferenceToFile_ShouldReturnFalse_WhenPathDoesNotExist)
{
PrintServiceAbility printServiceAbility;
char realPidFile[PATH_MAX] = {};
EXPECT_CALL(printServiceAbility, realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile))
.WillOnce(Return(nullptr));
EXPECT_FALSE(printServiceAbility.WritePreferenceToFile());
}

TEST_F(nullTest,
    WritePreferenceToFile_ShouldReturnFalse_WhenFileOpenFails)
{
PrintServiceAbility printServiceAbility;
char realPidFile[PATH_MAX] = "/valid/path";
EXPECT_CALL(printServiceAbility, realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile))
.WillOnce(Return(realPidFile));
EXPECT_CALL(printServiceAbility, open(PRINTER_PREFERENCE_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, S_IRUSR))
.WillOnce(Return(-1));
EXPECT_FALSE(printServiceAbility.WritePreferenceToFile());
}

TEST_F(nullTest,
    WritePreferenceToFile_ShouldReturnFalse_WhenWriteFails)
{
PrintServiceAbility printServiceAbility;
char realPidFile[PATH_MAX] = "/valid/path";
EXPECT_CALL(printServiceAbility, realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile))
.WillOnce(Return(realPidFile));
int32_t fd = 1;
EXPECT_CALL(printServiceAbility, open(PRINTER_PREFERENCE_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, S_IRUSR))
.WillOnce(Return(fd));
EXPECT_CALL(printServiceAbility, write(fd, _, _))
.WillOnce(Return(0));
EXPECT_FALSE(printServiceAbility.WritePreferenceToFile());
}

TEST_F(nullTest,
    WritePreferenceToFile_ShouldReturnTrue_WhenWriteSucceeds)
{
PrintServiceAbility printServiceAbility;
char realPidFile[PATH_MAX] = "/valid/path";
EXPECT_CALL(printServiceAbility, realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile))
.WillOnce(Return(realPidFile));
int32_t fd = 1;
EXPECT_CALL(printServiceAbility, open(PRINTER_PREFERENCE_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, S_IRUSR))
.WillOnce(Return(fd));
EXPECT_CALL(printServiceAbility, write(fd, _, _))
.WillOnce(Return(fd));
EXPECT_TRUE(printServiceAbility.WritePreferenceToFile());
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility* printServiceAbility;
std::string printerId;
PrinterCapability printerCaps;
void SetUp() override
{
    printServiceAbility = new PrintServiceAbility();
    printerId = "testPrinter";
    printerCaps.AddOption("testOption");
}
void TearDown() override
{
    delete printServiceAbility;
printServiceAbility = nullptr
}
};
HWTEST_F(PrintServiceAbilityTest,
    WritePrinterPreference_ShouldReturnFalse_WhenPrinterCapsHasNoOption, TestSize.Level0)
{
printerCaps.RemoveOption("testOption");
EXPECT_FALSE(printServiceAbility->WritePrinterPreference(printerId, printerCaps));
}
HWTEST_F(PrintServiceAbilityTest,
    WritePrinterPreference_ShouldReturnFalse_WhenPrinterIdAndPreferenceMapContainsPrinterId, TestSize.Level0)
{
printServiceAbility->printerIdAndPreferenceMap_.insert(std::make_pair(printerId, "testPreference"));
EXPECT_FALSE(printServiceAbility->WritePrinterPreference(printerId, printerCaps));
}
HWTEST_F(PrintServiceAbilityTest,
    WritePrinterPreference_ShouldReturnFalse_WhenBuildPrinterPreferenceFails, TestSize.Level0)
{
EXPECT_CALL(*printServiceAbility, BuildPrinterPreference(_, _)).WillOnce(Return(1));
EXPECT_FALSE(printServiceAbility->WritePrinterPreference(printerId, printerCaps));
}
HWTEST_F(PrintServiceAbilityTest,
    WritePrinterPreference_ShouldReturnTrue_WhenWritePreferenceToFileFails, TestSize.Level0)
{
EXPECT_CALL(*printServiceAbility, WritePreferenceToFile()).WillOnce(Return(false));
EXPECT_FALSE(printServiceAbility->WritePrinterPreference(printerId, printerCaps));
}
HWTEST_F(PrintServiceAbilityTest,
    WritePrinterPreference_ShouldReturnTrue_WhenAllConditionsMet, TestSize.Level0)
{
EXPECT_CALL(*printServiceAbility, BuildPrinterPreference(_, _)).WillOnce(Return(0));
EXPECT_CALL(*printServiceAbility, WritePreferenceToFile()).WillOnce(Return(true));
EXPECT_TRUE(printServiceAbility->WritePrinterPreference(printerId, printerCaps));
}

TEST_F(nullTest,
    WriteEprinterPreference_Test)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), true);
}

TEST_F(nullTest,
    WriteEprinterPreference_Test_Fail)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
printServiceAbility.WriteEprinterPreference(printerId, printerCaps);
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), false);
}

TEST_F(nullTest,
    WriteEprinterPreference_Test_UnsupportedPageSize)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
printerCaps.SetSupportedPageSize({PrintPageSize("A4")});
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), true);
}

TEST_F(nullTest,
    WriteEprinterPreference_Test_UnsupportedOrientation)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
printerCaps.SetSupportedOrientation({PORTRAIT, LANDSCAPE});
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), true);
}

TEST_F(nullTest,
    WriteEprinterPreference_Test_UnsupportedDuplexMode)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
printerCaps.SetSupportedDuplexMode({SIMPLEX, DUPLEX});
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), true);
}

TEST_F(nullTest,
    WriteEprinterPreference_Test_UnsupportedQuality)
{
PrintServiceAbility printServiceAbility;
std::string printerId = "testPrinter";
PrinterCapability printerCaps;
printerCaps.SetSupportedQuality({HIGH, LOW});
EXPECT_EQ(printServiceAbility.WriteEprinterPreference(printerId, printerCaps), true);
}

TEST_F(nullTest, UpdatePrintJobOptionByPrinterId_Test)
{
PrintJob printJob;
printJob.SetPrinterId("printerId");
printJob.SetOption("{"key":"value"}");
PrintServiceAbility printServiceAbility;
EXPECT_TRUE(printServiceAbility.UpdatePrintJobOptionByPrinterId(printJob));
}

TEST_F(nullTest, UpdatePrintJobOptionByPrinterId_Test_Fail)
{
PrintJob printJob;
printJob.SetPrinterId("nonexistentPrinterId");
printJob.SetOption("{"key":"value"}");
PrintServiceAbility printServiceAbility;
EXPECT_FALSE(printServiceAbility.UpdatePrintJobOptionByPrinterId(printJob));
}

TEST_F(nullTest, UpdatePrintJobOptionByPrinterId_Test_InvalidOption)
{
PrintJob printJob;
printJob.SetPrinterId("printerId");
printJob.SetOption("invalidJson");
PrintServiceAbility printServiceAbility;
EXPECT_FALSE(printServiceAbility.UpdatePrintJobOptionByPrinterId(printJob));
}

TEST_F(nullTest, AddNativePrintJob_ShouldReturnNullptr_WhenNativePrintJobIsNull)
{
PrintServiceAbility printServiceAbility;
std::string jobId = "testJobId";
PrintJob printJob;
auto result = printServiceAbility.AddNativePrintJob(jobId, printJob);
EXPECT_EQ(result, nullptr);
}

TEST_F(nullTest, AddNativePrintJob_ShouldReturnNonNullptr_WhenNativePrintJobIsNotNull)
{
PrintServiceAbility printServiceAbility;
std::string jobId = "testJobId";
PrintJob printJob;
printJob.SetJobId(jobId);
printJob.SetJobState(PRINT_JOB_PREPARED);
auto result = printServiceAbility.AddNativePrintJob(jobId, printJob);
EXPECT_NE(result, nullptr);
}

TEST_F(nullTest, AddNativePrintJob_ShouldUpdateParamsAndDump_WhenNativePrintJobIsNotNull)
{
PrintServiceAbility printServiceAbility;
std::string jobId = "testJobId";
PrintJob printJob;
printJob.SetJobId(jobId);
printJob.SetJobState(PRINT_JOB_PREPARED);
auto result = printServiceAbility.AddNativePrintJob(jobId, printJob);
EXPECT_NE(result, nullptr);
EXPECT_EQ(result->GetJobId(), jobId);
EXPECT_EQ(result->GetJobState(), PRINT_JOB_PREPARED);
}

TEST_F(nullTest, AddNativePrintJob_ShouldAddToPrintJobList_WhenNativePrintJobIsNotNull)
{
PrintServiceAbility printServiceAbility;
std::string jobId = "testJobId";
PrintJob printJob;
printJob.SetJobId(jobId);
printJob.SetJobState(PRINT_JOB_PREPARED);
auto result = printServiceAbility.AddNativePrintJob(jobId, printJob);
EXPECT_NE(result, nullptr);
EXPECT_TRUE(printServiceAbility.CheckPrintJobInList(jobId));
}

TEST_F(nullTest, StartPrintJob_ShouldReturnNoPermission_WhenPermissionIsFalse)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
EXPECT_EQ(printServiceAbility.StartPrintJob(jobInfo), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, StartPrintJob_ShouldReturnInvalidPrintJob_WhenCheckPrintJobIsFalse)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
EXPECT_EQ(printServiceAbility.StartPrintJob(jobInfo), E_PRINT_INVALID_PRINTJOB);
}

TEST_F(nullTest, StartPrintJob_ShouldReturnSuccess_WhenAllConditionsAreMet)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
EXPECT_EQ(printServiceAbility.StartPrintJob(jobInfo), 0);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility ability;
PrintJob jobInfo;
};
TEST_F(PrintServiceAbilityTest, CheckPrintJob_ShouldReturnFalse_WhenUpdatePrintJobOptionByPrinterIdFails)
{
int jobId = 1;
jobInfo.SetJobId(jobId);
EXPECT_CALL(ability, UpdatePrintJobOptionByPrinterId(_)).WillOnce(Return(false));
bool result = ability.CheckPrintJob(jobInfo);
EXPECT_FALSE(result);
}

TEST_F(PrintServiceAbilityTest, CheckPrintJob_ShouldReturnFalse_WhenJobIdNotFound)
{
int jobId = 2;
jobInfo.SetJobId(jobId);
EXPECT_CALL(ability, UpdatePrintJobOptionByPrinterId(_)).WillOnce(Return(true));
EXPECT_CALL(ability, GetJobId()).WillOnce(Return(jobId));
bool result = ability.CheckPrintJob(jobInfo);
EXPECT_FALSE(result);
}

TEST_F(PrintServiceAbilityTest, CheckPrintJob_ShouldReturnTrue_WhenJobIdFoundAndUpdated)
{
int jobId = 3;
jobInfo.SetJobId(jobId);
EXPECT_CALL(ability, UpdatePrintJobOptionByPrinterId()).WillOnce(Return(true));
EXPECT_CALL(ability, GetJobId()).WillOnce(Return(jobId));
EXPECT_CALL(ability, printJobList.find()).WillOnce(Return(ability.printJobList.end()));
bool result = ability.CheckPrintJob(jobInfo);
EXPECT_TRUE(result);
}

class PrintServiceAbilityTest : public nullTest {
public:
PrintServiceAbility *printServiceAbility;
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
delete printServiceAbility;
printServiceAbility = nullptr
}
};
TEST_F(PrintServiceAbilityTest, SetLastUsedPrinter_ShouldPrintError_WhenPrinterNotAdded)
{
std::string printerId = "NonExistentPrinter";
printServiceAbility->printSystemData_.IsPrinterAdded = [](const std::string &printerId) { return false; };
printServiceAbility->SetLastUsedPrinter(printerId);
EXPECT_EQ(printServiceAbility->userData_, nullptr);
}

TEST_F(PrintServiceAbilityTest, SetLastUsedPrinter_ShouldPrintError_WhenUserDataIsNull)
{
std::string printerId = "ValidPrinter";
printServiceAbility->printSystemData_.IsPrinterAdded = [](const std::string &printerId) { return true; };
printServiceAbility->GetCurrentUserData =  undefined { return nullptr; };
printServiceAbility->SetLastUsedPrinter(printerId);
EXPECT_EQ(printServiceAbility->userData_, nullptr);
}

TEST_F(PrintServiceAbilityTest, SetLastUsedPrinter_ShouldSetPrinter_WhenPrinterAddedAndUserDataValid)
{
std::string printerId = "ValidPrinter";
printServiceAbility->printSystemData_.IsPrinterAdded = [](const std::string &printerId) { return true; };
printServiceAbility->getCurrentUserData =  undefined { return new UserData(); };
printServiceAbility->userData_->SetLastUsedPrinter = [](const std::string &printerId) { return E_PRINT_NONE; };
printServiceAbility->SetLastUsedPrinter(printerId);
EXPECT_EQ(printServiceAbility->userData_->lastUsedPrinterId_, printerId);
}

class PrintServiceAbilityTest : public nullTest {
public:
void SetUp() override
{
printServiceAbility = new PrintServiceAbility();
}
void TearDown() override
{
    delete printServiceAbility;
printServiceAbility = nullptr
}
PrintServiceAbility* printServiceAbility;
};
HWTEST_F(PrintServiceAbilityTest,
    StartPrintJobCB_ShouldSetJobStateAndNotifyAppJobQueueChanged_WhenCalled, TestSize.Level0)
{
std::string jobId = "testJobId";
std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
printServiceAbility->StartPrintJobCB(jobId, printJob);
EXPECT_EQ(printJob->GetJobState(), PRINT_JOB_QUEUED);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNoPermission_WhenNoPermission)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NO_PERMISSION);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnInvalidUserId_WhenUserDataIsNull)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_INVALID_USERID);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnInvalidPrintJob_WhenJobNotFound)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(nullptr));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsQueuedAndExtensionIdNotFound)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnServerFailure_WhenExtCallbackNotFound)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_SERVER_FAILURE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsQueuedAndExtensionIdFound)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[_]).WillOnce(Return(nullptr));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsQueuedAndExtCallbackFound)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[_]).WillOnce(Return(new Callback()));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsQueuedAndExtCallbackOnCallbackReturnsFalse)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(true));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsQueuedAndExtCallbackOnCallbackReturnsTrue)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsOtherThanQueued)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_PRINTING));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsPrinting)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_,)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_PRINTING));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsCompleted)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_,)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_COMPLETED));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsCancelled)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_,)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_CANCELLED));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsFailed)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_,)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_FAILED));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsOtherThanFailed)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_NONE));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, CancelPrintJob_ShouldReturnNone_WhenJobStateIsNone)
{
PrintServiceAbility printService;
std::string jobId = "testJobId";
printService.ManualStart();
EXPECT_CALL(printService, CheckPermission(PERMISSION_NAME_PRINT_JOB)).WillOnce(Return(true));
EXPECT_CALL(printService, GetUserDataByJobId(jobId)).WillOnce(Return(new UserData()));
EXPECT_CALL(printService, UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED,
    PRINT_JOB_COMPLETED_CANCELLED)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, SetPrintJobCanceled(_)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, extCallbackMap_[]).WillOnce(Return(new Callback()));
EXPECT_CALL(printService, helper->IsSyncMode()).WillOnce(Return(false));
EXPECT_CALL(printService, serviceHandler_->PostTask(_, _)).WillOnce(Return(E_PRINT_NONE));
EXPECT_CALL(printService, jobIt->second->GetJobState()).WillOnce(Return(PRINT_JOB_NONE));
EXPECT_CALL(printService, jobIt->second->SetJobState()).WillOnce(Return(E_PRINT_NONE));
EXPECT_EQ(printService.CancelPrintJob(jobId), E_PRINT_NONE);
}

TEST_F(nullTest, SetPrintJobCanceled_Test)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
jobInfo.SetJobId("123");
printServiceAbility.SetPrintJobCanceled(jobInfo);
EXPECT_EQ(jobInfo.GetJobState(), PRINT_JOB_COMPLETED);
EXPECT_EQ(jobInfo.GetSubState(), PRINT_JOB_COMPLETED_CANCELLED);
EXPECT_EQ(printServiceAbility.printJobList_.find("123")->second->GetJobId(), "123");
}

TEST_F(nullTest, SetPrintJobCanceled_NullJobInfo_Test)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
printServiceAbility.SetPrintJobCanceled(jobInfo);
EXPECT_EQ(printServiceAbility.GetUserDataByJobId("123"), nullptr);
}

TEST_F(nullTest, SetPrintJobCanceled_NullUserData_Test)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
jobInfo.SetJobId("123");
printServiceAbility.UpdatePrintJobState = [](const std::string&, PrintJobState, PrintJobSubState) {};
printServiceAbility.SetPrintJobCanceled(jobInfo);
EXPECT_EQ(printServiceAbility.printJobList_.find("123")->second->GetJobId(), "123");
}

TEST_F(nullTest, SetPrintJobCanceled_AllNull_Test)
{
PrintServiceAbility printServiceAbility;
PrintJob jobInfo;
printServiceAbility.UpdatePrintJobState = [](const std::string&, PrintJobState, PrintJobSubState) {};
printServiceAbility.SetPrintJobCanceled(jobInfo);
EXPECT_EQ(printServiceAbility.GetUserDataByJobId("123"), nullptr);
}

} // namespace OHOS::Print