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
#include "print_service_mock_permission.h"
#include "mock_remote_object.h"
#define private public
#define protected public
#include "print_service_ability.h"
#include "print_bms_helper.h"
#undef protected
#undef private
#ifdef CUPS_ENABLE
#include "print_cups_client.h"
#endif // CUPS_ENABLE
#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "print_utils.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "print_security_guard_manager.h"
#include "hisys_event_util.h"
#include <json/json.h>
#include "mock_print_callback_proxy.h"
#include "mock_print_extension_callback_proxy.h"


using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
static constexpr const char *DEFAULT_EXTENSION_ID = "com.example.ext";
static constexpr const char *UNLOAD_EXTENSION_ID = "com.example.ext.unload";
static constexpr const char *NONEXIST_EXTENSION_ID = "com.example.ext.nonexist";
static constexpr const char *DEFAULT_EXT_PRINTER_ID = "https://10.10.10.10/FE8083DCD35F";
static constexpr const char *DEFAULT_EXT_PRINTER_ID2 = "https://10.10.10.10/0FDA6E208473";
static constexpr const char *DEFAULT_PRINT_FILE_A = "file://data/print/a.png";
static constexpr const char *DEFAULT_PRINT_FILE_B = "file://data/print/b.png";
static constexpr const char *DEFAULT_PRINT_FILE_C = "file://data/print/c.png";
static const std::string PRINT_GET_FILE_EVENT_TYPE = "getPrintFileCallback_adapter";
static const std::string PRINTER_EVENT_TYPE = "printerStateChange";
static const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
static const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
static const std::string PRINT_ADAPTER_EVENT_TYPE = "printCallback_adapter";
static const std::string EVENT_CANCEL = "cancel";
const uint32_t MAX_JOBQUEUE_NUM = 512;

enum EXTENSION_ID_TYPE {
    TYPE_DEFAULT,
    TYPE_UNLOAD,
    TYPE_NON_EXIST,
};
REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);
class PrintServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string GetExtensionId(EXTENSION_ID_TYPE type);
    std::string GetDefaultTaskId();
    std::string GetDefaultJobId();
    std::string GetDefaultPrinterId();
    std::string GetInvalidPrinterId();
    void InitExtPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitExtPrinterIdList(std::vector<std::string> &idList, size_t count);
    void InitFileList(std::vector<std::string> &fileList);
    void InitExtensionList(std::vector<AppExecFwk::ExtensionAbilityInfo>& extList);
};

void PrintServiceAbilityTest::SetUpTestCase(void) {}

void PrintServiceAbilityTest::TearDownTestCase(void) {}

void PrintServiceAbilityTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGE("PrintServiceAbilityTest_%{public}d", ++testNo);
}

void PrintServiceAbilityTest::TearDown(void) {}

std::string PrintServiceAbilityTest::GetExtensionId(EXTENSION_ID_TYPE type)
{
    switch (type) {
        case TYPE_DEFAULT:
            return DEFAULT_EXTENSION_ID;

        case TYPE_UNLOAD:
            return UNLOAD_EXTENSION_ID;

        case TYPE_NON_EXIST:
            return NONEXIST_EXTENSION_ID;

        default:
            break;
    }
    return DEFAULT_EXTENSION_ID;
}

std::string PrintServiceAbilityTest::GetDefaultTaskId()
{
    return std::to_string(0);
}

std::string PrintServiceAbilityTest::GetDefaultJobId()
{
    return std::to_string(0);
}

std::string PrintServiceAbilityTest::GetDefaultPrinterId()
{
    return PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID);
}

std::string PrintServiceAbilityTest::GetInvalidPrinterId()
{
    return PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, "wrong printer id");
}

void PrintServiceAbilityTest::InitExtPrinterList(std::vector<PrinterInfo> &printerList, size_t count)
{
    printerList.clear();
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    printerList.emplace_back(info);
    if (printerList.size() < count) {
        info.SetPrinterId(DEFAULT_EXT_PRINTER_ID2);
        printerList.emplace_back(info);
    }
}

void PrintServiceAbilityTest::InitPrinterList(std::vector<PrinterInfo> &printerList, size_t count)
{
    printerList.clear();
    PrinterInfo info;
    info.SetPrinterId(PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID));
    printerList.emplace_back(info);
    if (printerList.size() < count) {
        info.SetPrinterId(PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID2));
        printerList.emplace_back(info);
    }
}

void PrintServiceAbilityTest::InitExtPrinterIdList(std::vector<std::string> &idList, size_t count)
{
    idList.clear();
    idList.emplace_back(DEFAULT_EXT_PRINTER_ID);
    if (idList.size() < count) {
        idList.emplace_back(DEFAULT_EXT_PRINTER_ID2);
    }
}

void PrintServiceAbilityTest::InitFileList(std::vector<std::string> &fileList)
{
    fileList.emplace_back(DEFAULT_PRINT_FILE_A);
    fileList.emplace_back(DEFAULT_PRINT_FILE_B);
    fileList.emplace_back(DEFAULT_PRINT_FILE_C);
}

void PrintServiceAbilityTest::InitExtensionList(std::vector<AppExecFwk::ExtensionAbilityInfo>& extList)
{
    std::vector<std::string> nameList = {DEFAULT_EXTENSION_ID, UNLOAD_EXTENSION_ID};
    AppExecFwk::ExtensionAbilityInfo loadInfo;
    for (size_t index = 0; index < nameList.size(); index++) {
        loadInfo.bundleName = nameList[index];
        loadInfo.moduleName = nameList[index];
        loadInfo.name = nameList[index];
        extList.emplace_back(loadInfo);
    }
}
/**
* @tc.name: PrintServiceAbilityTest_0001
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ~PrintServiceAbility()
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001_NeedRename, TestSize.Level0)
{
    PrintServiceAbility* print_service = new PrintServiceAbility(PRINT_SERVICE_ID, true);
    if (print_service != nullptr) {
        delete print_service;
        print_service = nullptr;
    }
    PrintServiceAbility* new_print_service = new PrintServiceAbility(PRINT_SERVICE_ID, false);
    if (new_print_service != nullptr) {
        delete new_print_service;
        new_print_service = nullptr;
    }
    EXPECT_EQ(PrintServiceAbility::GetInstance()->Init(), E_PRINT_SERVER_FAILURE);
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    service->SetHelper(helper);
    EXPECT_EQ(PrintServiceAbility::GetInstance()->Init(), E_PRINT_SERVER_FAILURE);
}
/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ManualStart()
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002_NeedRename, TestSize.Level0)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int state = static_cast<int>(service->state_);
    service->ManualStart();
    EXPECT_EQ(state, 0);
}
/**
* @tc.name: PrintServiceAbilityTest_0003
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC GetPrintJobOrderId()
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003_NeedRename, TestSize.Level0)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->GetPrintJobOrderId();
    EXPECT_NE(service->currentJobOrderId_, 0);
}
/**
* @tc.name: PrintServiceAbilityTest_0004
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC
* @tc.require: return E_PRINT_NO_PERMISSION
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0004_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_EQ(service->StartService(), E_PRINT_NO_PERMISSION);
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->CallSpooler(fileList, fdList, taskId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->StopPrint(taskId), E_PRINT_NO_PERMISSION);
    std::string printerId = "1234";
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_NO_PERMISSION);
    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NO_PERMISSION);
    std::vector<PrintExtensionInfo> extensionInfos;
    EXPECT_EQ(service->QueryAllExtension(extensionInfos), E_PRINT_NO_PERMISSION);
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NO_PERMISSION);
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NO_PERMISSION);
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NO_PERMISSION);
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NO_PERMISSION);
    std::string printJobId = "1";
    PrintJob printJob;
    EXPECT_EQ(service->QueryPrintJobById(printJobId, printJob), E_PRINT_NO_PERMISSION);
    std::string printerUri = "111.222.333";
    std::string printerName = "pixlab_0759";
    std::string printerMake = "pixlab b5";
    EXPECT_EQ(service->AddPrinterToCups(printerUri, printerName, printerMake), E_PRINT_NO_PERMISSION);
    PrinterCapability printerCaps;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->StartNativePrintJob(printJob), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->StartPrintJob(printJob), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->CancelPrintJob(printJobId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->RestartPrintJob(printJobId), E_PRINT_NO_PERMISSION);
    std::vector<PrinterInfo> printerInfos;
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NO_PERMISSION);
    std::vector<std::string> printerIds;
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NO_PERMISSION);
    uint32_t state = PrinterState::PRINTER_ADDED;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_NO_PERMISSION);
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobStateOnlyForSystemApp(printJobId, state, subState), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->AdapterGetFileCallBack(printJobId, state, subState), E_PRINT_NONE);
    state = PrintJobState::PRINT_JOB_CREATE_FILE_COMPLETED;
    EXPECT_EQ(service->AdapterGetFileCallBack(printJobId, state, subState), E_PRINT_NO_PERMISSION);
    std::string extInfo = "";
    EXPECT_EQ(service->UpdateExtensionInfo(extInfo), E_PRINT_NO_PERMISSION);
    std::string previewResult = "";
    EXPECT_EQ(service->RequestPreview(printJob, previewResult), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->QueryPrinterCapability(printerId), E_PRINT_NO_PERMISSION);
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterPrinterCallback(type, listener), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UnregisterPrinterCallback(type), E_PRINT_NO_PERMISSION);
    std::string extensionCID = "";
    sptr<IPrintExtensionCallback> listenerCB = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCID, listenerCB), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UnregisterAllExtCallback(extensionCID), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->LoadExtSuccess(extensionCID), E_PRINT_NO_PERMISSION);
    std::string jobName = "a.jpeg";
    PrintAttributes printAttributes;
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId), E_PRINT_NO_PERMISSION);
    uint32_t fd = 46;
    EXPECT_EQ(service->StartGetPrintFile(printJobId, printAttributes, fd), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->NotifyPrintService(printJobId, type), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->CallStatusBar(), E_PRINT_NO_PERMISSION);
    uint32_t event = 0;
    std::string jobId = GetDefaultJobId();
    EXPECT_EQ(service->NotifyPrintServiceEvent(jobId, event), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NO_PERMISSION);
    PrinterPreferences printerPreference;
    EXPECT_EQ(service->SetPrinterPreference(printerId, printerPreference), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->SetDefaultPrinter(printerId, 0), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NO_PERMISSION);
    std::vector<PrinterInfo> printers;
    EXPECT_EQ(service->DiscoverUsbPrinters(printers), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_NO_PERMISSION);

    PrintServiceMockPermission::MockPermission();
    EXPECT_EQ(service->StartService(), E_PRINT_NONE);
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_INVALID_PARAMETER);

    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    EXPECT_EQ(service->StopPrint(taskId), E_PRINT_NONE);
}
/**
* @tc.name: PrintServiceAbilityTest_0006
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC CallSpooler
* @tc.require: has token
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006_NeedRename, TestSize.Level0)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string jobId = "";
    EXPECT_EQ(service->CallSpooler(fileList, fdList, jobId), E_PRINT_INVALID_PARAMETER);
    jobId = "jobId";
    EXPECT_EQ(service->CallSpooler(fileList, fdList, jobId), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0007
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC SetHelper
* @tc.require: has token
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0007_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    service->SetHelper(helper);
    EXPECT_EQ(service->helper_, helper);
    helper = make_shared<PrintServiceHelper>();
    if (helper != nullptr) {
        service->SetHelper(helper);
        EXPECT_EQ(service->helper_, helper);
    }
}

/**
* @tc.name: PrintServiceAbilityTest_0008
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ConnectPrinter
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId ="1234";
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    service->ConnectPrinter(printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_NONE);
    extCb = new MockPrintExtensionCallbackProxy();
    EXPECT_NE(extCb, nullptr);
    if (extCb != nullptr) {
        service->extCallbackMap_.clear();
        service->extCallbackMap_[cid] = extCb;
    }
    service->ConnectPrinter(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId ="1234";
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    service->DisconnectPrinter(printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_SERVER_FAILURE);
    extCb = new MockPrintExtensionCallbackProxy();
    EXPECT_NE(extCb, nullptr);
    if (extCb != nullptr) {
        service->extCallbackMap_.clear();
        service->extCallbackMap_[cid] = extCb;
    }
    service->DisconnectPrinter(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_PARAMETER);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_NON_EXIST), PRINT_EXTCB_START_DISCOVERY);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_UNLOAD), PRINT_EXTCB_START_DISCOVERY);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_MAX);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_NON_EXIST)), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_UNLOAD)), E_PRINT_INVALID_EXTENSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string taskId = "";
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_INVALID_PARAMETER);
    taskId = "1";
    type = "printCallback_adapter";
    service->On(taskId, type, listener);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
    listener = new MockPrintCallbackProxy();
    if (listener != nullptr) {
        service->On(taskId, type, listener);
    }
    service->registeredListeners_[type] = listener;
    taskId = "";
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0013_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NONE);
    std::vector<std::string> printerIds;
    InitExtPrinterIdList(printerIds, 1);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerIds[0]);
    std::string printerId = printerIds[0];
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NONE);
    std::vector<std::string> newPrinterIds;
    newPrinterIds.push_back("1234");
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    service->RemovePrinters(newPrinterIds);
    printerInfos.clear();
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0014_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob testJob;
    std::string jobId = GetDefaultJobId();
    testJob.SetJobId(jobId);
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> job = std::make_shared<PrintJob>();
    service->printJobList_["1"] = job;
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_INVALID_PRINTJOB);
    service->printJobList_["0"] = job;
    std::string extensionId = PrintUtils::GetExtensionId(GetDefaultPrinterId());
    sptr<IPrintExtensionCallback> listener = nullptr;
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    service->extCallbackMap_[cid] = listener;
    service->StartPrintJob(testJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0018_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId ="1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    service->notifyAdapterJobChanged(jobId, state, subState);
    auto attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
    PrintAttributes attr;
    service->printAttributesList_[jobId] = attr;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_NE(attrIt, service->printAttributesList_.end());
    sptr<IPrintCallback> listener = nullptr;
    service->adapterListenersByJobId_[jobId] = listener;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_NE(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0019_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId ="1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;

    state = PRINT_JOB_BLOCKED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    auto attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0020_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobName = "a.jpeg";
    PrintAttributes printAttributes;
    std::string taskId ="1";
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0021_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "1";
    PrintAttributes printAttributes;
    uint32_t fd = 46;
    sptr<IPrintCallback> listener = nullptr;
    service->adapterListenersByJobId_[jobId] = listener;
    EXPECT_EQ(service->StartGetPrintFile(jobId, printAttributes, fd), E_PRINT_NONE);
    service->adapterListenersByJobId_.clear();

    EXPECT_EQ(service->StartGetPrintFile(jobId, printAttributes, fd), E_PRINT_NONE);
    service->printAttributesList_[jobId] = printAttributes;
    EXPECT_EQ(service->StartGetPrintFile(jobId, printAttributes, fd), E_PRINT_NONE);
    std::string newJobId = "2";
    EXPECT_EQ(service->StartGetPrintFile(newJobId, printAttributes, fd), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0022_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "1234";
    std::shared_ptr<PrinterInfo> info =std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    EXPECT_EQ(service->printSystemData_.QueryDiscoveredPrinterInfoById(printerId), info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "com.ohos.spooler:0";
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_STOP_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
    cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_DISCOVERY);
    service->extCallbackMap_.clear();
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->DelayStartDiscovery(extensionId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->OnStop();
    EXPECT_EQ(service->state_, ServiceRunningState::STATE_NOT_START);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->OnStop();
    EXPECT_EQ(service->state_, ServiceRunningState::STATE_NOT_START);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "com.ohos.spooler:0";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_STOP_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0029_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_.insert(std::make_pair(userId, userData));
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0030_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    service->QueryAllPrintJob(printJobs);
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->QueryAllPrintJob(printJobs);
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0031_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0032_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    keyList.push_back("printerId");
    keyList.push_back("printerName");
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0033_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    printerInfo->SetAlias("testAlias");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0034_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printJobId = "1";
    PrintJob printJob;
    EXPECT_EQ(service->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0035_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerUri = "testPrinterUri";
    std::string printerName = "testPrinterName";
    std::string printerMake = "testPrinterMake";
    EXPECT_EQ(service->AddPrinterToCups(printerUri, printerName, printerMake), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0036_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob1;
    printJob1.SetOption("test");
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob1), false);

    PrintJob printJob2;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    printJob2.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob2), false);

    Json::Value infoJson;
    infoJson["printerName"] = "testPrinterName";
    printJob2.SetOption(PrintJsonUtil::WriteString(infoJson));
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob2), true);
    service->StartNativePrintJob(printJob2);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->StartNativePrintJob(printJob2);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0037_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string jobId = GetDefaultJobId();
    auto nativePrintJob = std::make_shared<PrintJob>();
    nativePrintJob->UpdateParams(printJob);
    nativePrintJob->Dump();
    service->AddToPrintJobList(jobId, nativePrintJob);
    EXPECT_NE(service->AddNativePrintJob(jobId, printJob), nativePrintJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0038_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    printJob.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    printJob.SetOption("test");
    EXPECT_EQ(service->StartNativePrintJob(printJob), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0040_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    std::string jobId = GetDefaultJobId();
    service->UpdateQueuedJobList(jobId, printJob);
    service->UpdateQueuedJobList("0", printJob);
    for (int i = 0; i < MAX_JOBQUEUE_NUM + 1; i++) {
        service->queuedJobList_.insert(std::make_pair(std::to_string(i), printJob));
    }
    service->UpdateQueuedJobList("515", printJob);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->UpdateQueuedJobList("515", printJob);
    service->printAppCount_ = 3;
    std::string type ="0";
    EXPECT_EQ(service->NotifyPrintService(jobId, type), E_PRINT_NONE);
    type = "spooler_closed_for_started";
    EXPECT_EQ(service->NotifyPrintService(jobId, type), E_PRINT_NONE);
    type = "spooler_closed_for_cancelled";
    EXPECT_EQ(service->NotifyPrintService(jobId, type), E_PRINT_NONE);
    type = "";
    EXPECT_EQ(service->NotifyPrintService(jobId, type), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, CancelPrintJob_WhenInvalidUserData_ShoudFailed, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = GetDefaultJobId();
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_USERID);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintServiceAbilityTest, RestartPrintJob_WhenInvalidUserData_ShoudFailed, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = GetDefaultJobId();
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, RestartPrintJob_WhenBedfd_ShoudFailed, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_FILE_IO);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0042_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    printJob.SetJobId(GetDefaultJobId());
    service->SetPrintJobCanceled(printJob);
    auto testPrintJob = std::make_shared<PrintJob>(printJob);
    std::string testJobId = testPrintJob->GetJobId();
    auto attrIt = service->printAttributesList_.find(testJobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
    std::string jobId = "123";
    printJob.SetJobId(jobId);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->SetPrintJobCanceled(printJob);
    testPrintJob = std::make_shared<PrintJob>(printJob);
    testJobId = testPrintJob->GetJobId();
    attrIt = service->printAttributesList_.find(testJobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0043_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    int32_t userId = 100;
    service->CancelUserPrintJobs(userId);
    auto userIt = service->printUserMap_.find(userId);
    EXPECT_EQ(userIt, service->printUserMap_.end());

    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->CancelUserPrintJobs(userId);
    userIt = service->printUserMap_.find(userId);
    EXPECT_NE(userIt, service->printUserMap_.end());

    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->CancelUserPrintJobs(userId);
    userIt = service->printUserMap_.find(userId);
    EXPECT_EQ(userIt, service->printUserMap_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0044_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);

    std::string jobId = GetDefaultJobId();
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0045_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerUri = "111.222.333";
    std::string printerId = "pixlab_0759";
    PrinterCapability printerCaps;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0046_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    service->StartPrintJobCB(jobId, printJob);
    EXPECT_EQ(printJob->jobState_, PRINT_JOB_QUEUED);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0048_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINTER_UNKNOWN + 1;
    std::string printerId ="1234";
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PARAMETER);
    state = PrinterState::PRINTER_ADDED;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0049_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    uint32_t state = PRINTER_UNKNOWN + 1;
    uint32_t subState = 0;
    EXPECT_EQ(service->checkJobState(state, subState), true);
    service->UpdatePrintJobState(jobId, state, subState);
    state = PRINT_JOB_BLOCKED;
    subState = PRINT_JOB_BLOCKED_OFFLINE - 1;
    EXPECT_EQ(service->checkJobState(state, subState), false);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
    subState = PRINT_JOB_BLOCKED_UNKNOWN + 1;
    EXPECT_EQ(service->checkJobState(state, subState), true);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_USERID);
    state = PRINT_JOB_COMPLETED;
    subState = PRINT_JOB_COMPLETED_FILE_CORRUPT + 1;
    EXPECT_EQ(service->checkJobState(state, subState), false);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0050_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0051_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    EXPECT_EQ(service->AdapterGetFileCallBack(jobId, state, subState), E_PRINT_NONE);
    std::string type = PRINT_GET_FILE_EVENT_TYPE;
    sptr<IPrintCallback>  listener = new MockPrintCallbackProxy();
    service->registeredListeners_[type] = listener;
    service->AdapterGetFileCallBack(jobId, state, subState);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    service->AdapterGetFileCallBack(jobId, state, subState);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_FAILED;
    service->AdapterGetFileCallBack(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0052_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->printJobList_[jobId] = printJob;
    state = PRINT_JOB_BLOCKED;
    std::string printerId = "1234";
    printJob->SetPrinterId(printerId);
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
    userData->queuedJobList_[jobId] = printJob;
    state = PRINT_JOB_COMPLETED;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0053_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), false);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = printJob;
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), false);
    userData->queuedJobList_.clear();
    service->currentUserId_ = 0;
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), false);
    service->currentUserId_ = 100;
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0055_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t event = -1;
    std::string jobId = GetDefaultJobId();
    EXPECT_EQ(service->NotifyPrintServiceEvent(jobId, event), E_PRINT_INVALID_PARAMETER);
    event = 3;
    EXPECT_EQ(service->NotifyPrintServiceEvent(jobId, event), E_PRINT_INVALID_PARAMETER);
    event = 0;
    service->NotifyPrintServiceEvent(jobId, event);
    auto printJob = std::make_shared<PrintJob>();
    service->printJobList_[jobId] = printJob;
    service->NotifyPrintServiceEvent(jobId, event);
    event = 1;
    service->NotifyPrintServiceEvent(jobId, event);
    event = 2;
    service->NotifyPrintServiceEvent(jobId, event);
    event = 3;
    service->NotifyPrintServiceEvent(jobId, event);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0056_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterPrinterCallback(type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->UnregisterPrinterCallback(type), E_PRINT_INVALID_TOKEN);
    sptr<IPrintCallback> listener2 = new MockPrintCallbackProxy();
    service->RegisterPrinterCallback(type, listener2);
    service->UnregisterPrinterCallback(type);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0057_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int event = 0;
    PrinterInfo info;
    EXPECT_EQ(service->SendPrinterChangeEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0059_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    std::string previewResult = "";
    service->RequestPreview(jobInfo, previewResult);

    std::string extensionId = "DEFAULT_EXTENSION_ID";
    std::string extInfo = "spooler";
    service->SendExtensionEvent(extensionId, extInfo);
    EXPECT_EQ(service->UnregisterAllExtCallback(extensionId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0060_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    AppExecFwk::ExtensionAbilityInfo extInfo;
    extInfo.bundleName = "spooler";

    PrintExtensionInfo newExtInfo;
    PrintExtensionInfo judgeExtInfo;
    judgeExtInfo.SetExtensionId(extInfo.bundleName);
    judgeExtInfo.SetVendorId(extInfo.bundleName);
    judgeExtInfo.SetVendorName(extInfo.bundleName);
    judgeExtInfo.SetVendorIcon(0);
    judgeExtInfo.SetVersion("1.0.0");
    newExtInfo = service->ConvertToPrintExtensionInfo(extInfo);
    EXPECT_EQ(newExtInfo.extensionId_, judgeExtInfo.extensionId_);
    EXPECT_EQ(newExtInfo.vendorId_, judgeExtInfo.vendorId_);
    EXPECT_EQ(newExtInfo.vendorName_, judgeExtInfo.vendorName_);
    EXPECT_EQ(newExtInfo.vendorIcon_, judgeExtInfo.vendorIcon_);
    EXPECT_EQ(newExtInfo.version_, judgeExtInfo.version_);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0061_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    printJob->SetJobState(PRINT_JOB_RUNNING);
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    printJob->SetPrinterId("1234");
    std::string extensionId = PrintUtils::GetExtensionId("1234");
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    printJob->SetPrinterId("com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620");
    std::string extensionId2 = PrintUtils::GetExtensionId("com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620");
    std::string cid2 = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
    service->extCallbackMap_[cid2] = extCb;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0062_NeedRename, TestSize.Level1)
{
    DelayedSingleton<PrintBMSHelper>::GetInstance()->hasBms = false;
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<std::string> extensionIds;
    std::string extensionId = "com.ohos.spooler";
    extensionIds.push_back(extensionId);
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
    std::vector<PrintExtensionInfo> extensionInfos;
    service->QueryAllExtension(extensionInfos);
    service->StartDiscoverPrinter(extensionIds);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0063_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = "com.ohos.spooler:0";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DESTROY_EXTENSION);
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0064_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    PrinterCapability caps;
    Json::Value opsJson;
    opsJson["key"] = "value";
    caps.SetOption(PrintJsonUtil::WriteString(opsJson));
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    caps.SetSupportedPageSize(pageSizeList);
    printerInfo->SetCapability(caps);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0065_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0066_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    std::string savePrinterPreference = "test";
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0067_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0068_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0069_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    PrinterCapability printerCaps;
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    service->printSystemData_.discoveredPrinterInfoList_["123"] = nullptr;
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_["456"] = printerInfo;
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0079_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    PrintJob printJob;
    Json::Value opsJson;
    opsJson["key"] = "value";
    printJob.SetPrinterId(printerId);
    printJob.SetOption(PrintJsonUtil::WriteString(opsJson));
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    auto ret = service->StartNativePrintJob(printJob);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
    auto extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    ret = service->StartNativePrintJob(printJob);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0080_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "123";
    service->SetLastUsedPrinter(printerId);
    auto printer = std::make_shared<PrinterInfo>();
    auto ret = service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    service->SetLastUsedPrinter(printerId);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0081_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINT_JOB_UNKNOWN + 1;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    service->checkJobState(state, subState);
    std::string jobId = "123";
    auto ret = service->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0082_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    std::string jobId = "123";
    std::string type = PRINT_GET_FILE_EVENT_TYPE;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[type] = listener;
    auto ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_FAILED;
    ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
    subState = PRINT_JOB_BLOCKED_UNKNOWN;
    ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0083_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = 0;
    std::string printerId = "1234";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    userData->printJobList_[jobId] = printJob;
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0084_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = 0;
    std::string printerId = "1234";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    userData->printJobList_[jobId] = printJob;
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0085_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    service->printAppCount_ = 1;
    service->ReportCompletedPrint(printerId);
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    service->queuedJobList_[jobId] = printJob;
    service->printAppCount_ = 0;
    service->ReportCompletedPrint(printerId);
    EXPECT_EQ(service->unloadCount_, 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0086_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "";
    EXPECT_EQ(service->isEprint(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0087_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    auto ret = service->QueryPrinterCapability(printerId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    ret = service->QueryPrinterCapability(printerId);
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_CAP);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    ret = service->QueryPrinterCapability(printerId);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0088_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    auto ret = service->RegisterExtCallback(extensionCid, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    std::string extensionCid2 = "123:20";
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_EXTENSION);
    std::string extensionId = "123";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_EXTENSION);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADING;
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    std::string extensionCid3 = "123:2";
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0089_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t callbackId = 0;
    std::string extensionId = "123";
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    auto ret = service->UnregisterAllExtCallback(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0090_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "123";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    auto ret = service->LoadExtSuccess(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADING;
    ret = service->LoadExtSuccess(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0091_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    std::string type = PRINT_CALLBACK_ADAPTER;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_NE(listener, nullptr);
    service->On(jobId, type, listener);
    type = PRINTER_CHANGE_EVENT_TYPE;
    service->On(jobId, type, listener);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0092_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->helper_ = nullptr;
    AAFwk::Want want;
    auto ret = service->StartAbility(want);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0093_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    EXPECT_NE(service->SendPrinterDiscoverEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0094_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    EXPECT_NE(service->SendPrinterChangeEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0095_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    service->SendPrinterEvent(info);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[PRINTER_EVENT_TYPE] = listener;
    service->SendPrinterEvent(info);
    EXPECT_EQ(info.GetPrinterState(), PRINTER_UNKNOWN);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0096_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    PrinterEvent printerEvent = PRINTER_EVENT_STATE_CHANGED;
    service->registeredListeners_["test"] = nullptr;
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info), 0);

    std::string eventType = "123" + PRINTER_CHANGE_EVENT_TYPE;
    service->registeredListeners_[eventType] = nullptr;
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info), 0);

    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[eventType] = listener;
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0097_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    jobInfo.SetJobId("1");
    service->SendPrintJobEvent(jobInfo);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[PRINTJOB_EVENT_TYPE] = listener;
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_BLOCKED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_FAILED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_CANCELLED);
    std::string taskEvent = PrintUtils::GetTaskEventId(jobInfo.GetJobId(), EVENT_CANCEL);
    service->registeredListeners_[taskEvent] = listener;
    service->SendPrintJobEvent(jobInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0098_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "123";
    std::string extInfo = "123";
    EXPECT_EQ(service->SendExtensionEvent(extensionId, extInfo), 0);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[EXTINFO_EVENT_TYPE] = listener;
    EXPECT_NE(service->SendExtensionEvent(extensionId, extInfo), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0099_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    std::string jobId = "123";
    jobInfo.SetJobId(jobId);
    service->isJobQueueBlocked_ = true;
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, true);
    service->isJobQueueBlocked_ = false;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, false);
    jobInfo.SetJobState(PRINT_JOB_BLOCKED);
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, true);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, true);
    service->isJobQueueBlocked_ = true;
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, true);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    auto job = std::make_shared<PrintJob>();
    job->SetJobState(PRINT_JOB_COMPLETED);
    auto job2 = std::make_shared<PrintJob>();
    job2->SetJobState(PRINT_JOB_BLOCKED);
    userData->queuedJobList_["1"] = job;
    userData->queuedJobList_["2"] = job2;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, true);
    userData->queuedJobList_.clear();
    userData->queuedJobList_["1"] = job;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, false);
    service->userJobMap_.clear();
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0100_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobName = "";
    PrintAttributes printAttributes;
    std::string taskId = "";
    auto ret = service->PrintByAdapter(jobName, printAttributes, taskId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0102_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    uint32_t state = PRINT_JOB_RUNNING;
    uint32_t subState = PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    auto attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
    state = PRINT_JOB_SPOOLER_CLOSED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
    state = PRINT_JOB_COMPLETED;
    PrintAttributes printAttributes;
    service->printAttributesList_[jobId] = printAttributes;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0103_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->helper_ = nullptr;
    AAFwk::Want want;
    EXPECT_FALSE(service->StartPluginPrintIconExtAbility(want));
    service->helper_ = std::make_shared<PrintServiceHelper>();
    service->StartPluginPrintIconExtAbility(want);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0104_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    EXPECT_EQ(service->GetUserDataByJobId(jobId), nullptr);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    EXPECT_EQ(service->GetUserDataByJobId(jobId), nullptr);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_NE(service->GetUserDataByJobId(jobId), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0105_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    service->RegisterAdapterListener(jobId);
    auto lisIt = service->adapterListenersByJobId_.find(jobId);
    EXPECT_EQ(lisIt, service->adapterListenersByJobId_.end());
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[PRINT_ADAPTER_EVENT_TYPE] = listener;
    service->RegisterAdapterListener(jobId);
    lisIt = service->adapterListenersByJobId_.find(jobId);
    EXPECT_NE(lisIt, service->adapterListenersByJobId_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0106_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    auto ret = service->SetDefaultPrinter(printerId, 0);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0107_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    EXPECT_EQ(service->CheckIsDefaultPrinter(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0108_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    EXPECT_EQ(service->CheckIsLastUsedPrinter(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0109_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerName = "pixlab_0759";
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0111_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "printerId";
    int32_t userId1 = 100;
    int32_t userId2 = 101;
    std::shared_ptr<PrintUserData> userData1 = std::make_shared<PrintUserData>();
    auto ret = userData1->SetDefaultPrinter("test", 0);
    EXPECT_EQ(ret, E_PRINT_NONE);
    std::shared_ptr<PrintUserData> userData2 = std::make_shared<PrintUserData>();
    ret = userData1->SetDefaultPrinter(printerId, 0);
    EXPECT_EQ(ret, E_PRINT_NONE);
    service->printUserMap_[userId1] = userData1;
    service->printUserMap_[userId2] = userData2;
    service->DeletePrinterFromUserData(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0112_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = 0;
    std::string printerId = "1234";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    userData->queuedJobList_[jobId] = printJob;
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    service->currentUserId_ = 0;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0113_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string taskId = "";
    std::string type = PRINTER_CHANGE_EVENT_TYPE;
    auto ret = service->Off(taskId, type);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0120_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    std::map<std::string, std::shared_ptr<PrintJob>> jobList;
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_BLOCKED);
    jobList.insert(std::make_pair("test", job));
    EXPECT_EQ(service->DetermineUserJobStatus(jobList), PRINT_JOB_BLOCKED);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0121_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    std::map<std::string, std::shared_ptr<PrintJob>> jobList;
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_COMPLETED);
    jobList.insert(std::make_pair("test", job));
    EXPECT_EQ(service->DetermineUserJobStatus(jobList), PRINT_JOB_COMPLETED);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0122_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    std::map<std::string, std::shared_ptr<PrintJob>> jobList;
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_RUNNING);
    jobList.insert(std::make_pair("test", job));
    EXPECT_EQ(service->DetermineUserJobStatus(jobList), PRINT_JOB_RUNNING);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0123_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int32_t userId = 100;
    auto userData1 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData1, nullptr);
    auto userData2 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData2, nullptr);
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_BLOCKED);
    userData1->queuedJobList_.insert(std::make_pair("test1", job));
    service->NotifyCurrentUserChanged(userId);
    auto job2 = std::make_shared<PrintJob>();
    EXPECT_NE(job2, nullptr);
    job2->SetJobState(PRINT_JOB_RUNNING);
    userData1->queuedJobList_.insert(std::make_pair("test2", job2));
    service->NotifyCurrentUserChanged(userId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0124_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int32_t userId = 100;
    auto userData1 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData1, nullptr);
    auto userData2 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData2, nullptr);
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_COMPLETED);
    userData1->queuedJobList_.insert(std::make_pair("test1", job));
    service->NotifyCurrentUserChanged(userId);
    auto job2 = std::make_shared<PrintJob>();
    EXPECT_NE(job2, nullptr);
    job2->SetJobState(PRINT_JOB_RUNNING);
    userData1->queuedJobList_.insert(std::make_pair("test2", job2));
    service->NotifyCurrentUserChanged(userId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0125_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    uint32_t subState = PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED;
    EXPECT_EQ(service->GetListeningState(subState), PREVIEW_ABILITY_DESTROY_FOR_CANCELED);
    subState = PRINT_JOB_SPOOLER_CLOSED_FOR_STARTED;
    EXPECT_EQ(service->GetListeningState(subState), PREVIEW_ABILITY_DESTROY_FOR_STARTED);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    EXPECT_EQ(service->GetListeningState(subState), PREVIEW_ABILITY_DESTROY);
    uint32_t state1 = service->GetListeningState(PRINT_JOB_SPOOLER_CLOSED, subState);
    uint32_t state2 = service->GetListeningState(subState);
    EXPECT_EQ(state1, state2);
    state1 = service->GetListeningState(PRINT_JOB_BLOCKED, subState);
    EXPECT_EQ(state1, PRINT_TASK_BLOCK);
    state1 = service->GetListeningState(PRINT_JOB_QUEUED, PRINT_JOB_COMPLETED_SUCCESS);
    EXPECT_EQ(state1, PRINT_TASK_SUCCEED);
    state1 = service->GetListeningState(PRINT_JOB_QUEUED, PRINT_JOB_COMPLETED_FAILED);
    EXPECT_EQ(state1, PRINT_TASK_FAIL);
    state1 = service->GetListeningState(PRINT_JOB_QUEUED, PRINT_JOB_COMPLETED_CANCELLED);
    EXPECT_EQ(state1, PRINT_TASK_CANCEL);
    state1 = service->GetListeningState(PRINT_JOB_QUEUED, PRINT_JOB_BLOCKED_OUT_OF_INK);
    EXPECT_EQ(state1, PRINT_TASK_FAIL);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0126_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerName = "testPrinterName";
    EXPECT_EQ(service->printSystemData_.QueryPrinterIdByStandardizeName(printerName), "");
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0128_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "Pixlab_0759";
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0129_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrinterInfo> printers;
    service->DiscoverUsbPrinters(printers);
    EXPECT_EQ(printers.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0130_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    EXPECT_EQ(service->AddPrinterToDiscovery(info), E_PRINT_NONE);
    EXPECT_EQ(service->UpdatePrinterInDiscovery(info), E_PRINT_NONE);
    info.SetPrinterId("1234");
    EXPECT_EQ(service->UpdatePrinterInDiscovery(info), E_PRINT_NONE);

    std::shared_ptr<PrinterInfo> info1 = std::make_shared<PrinterInfo>();
    info1->SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    service->printSystemData_.discoveredPrinterInfoList_[DEFAULT_EXT_PRINTER_ID] = info1;
    EXPECT_EQ(service->RemovePrinterFromDiscovery(DEFAULT_EXT_PRINTER_ID), E_PRINT_NONE);
    EXPECT_EQ(service->RemovePrinterFromDiscovery(DEFAULT_EXT_PRINTER_ID), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0131_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0132_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->RemoveVendorPrinterFromDiscovery(vendorName, printerId));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0133_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    PrinterInfo info;
    PrinterInfo info2;
    info.SetPrinterId(printerId);
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_INVALID_PRINTER);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_INVALID_PRINTER);
    EXPECT_TRUE(service->RemoveVendorPrinterFromDiscovery(vendorName, printerId));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0134_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string ppdName;
    std::string ppdData;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_FALSE(service->RemoveVendorPrinterFromCups(vendorName, printerId));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    info.SetUri("uri");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    info.SetPrinterMake("maker");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData);
    ppdData = "ppd";
    service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData);
    service->RemoveVendorPrinterFromCups(vendorName, printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0135_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_EQ(service->TryConnectPrinterByIp(""), E_PRINT_INVALID_PRINTER);
    std::string param = "{\"protocol\":\"ipp\"}";
    EXPECT_EQ(service->TryConnectPrinterByIp(param), E_PRINT_INVALID_PRINTER);
    param = "{\"protocol\":\"ipp\",\"ip\":\"a.b.c.d\"}";
    EXPECT_EQ(service->TryConnectPrinterByIp(param), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0136_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string ppdName;
    std::string ppdData;
    PrinterInfo info;
    info.SetPrinterName(vendorName);
    info.SetPrinterId(printerId);
    PrinterCapability cap;
    info.SetCapability(cap);
    info.SetUri("uri");
    info.SetPrinterMake("maker");
    ppdData = "ppd";
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData);

    std::string vendorName1 = "fwk.driver";
    std::string printerId1 = "testprinter1";
    PrinterInfo info1;
    info1.SetPrinterName(vendorName1);
    info1.SetPrinterId(printerId1);
    PrinterCapability cap1;
    info1.SetCapability(cap1);
    info1.SetUri("uri1");
    info1.SetPrinterMake("maker1");
    EXPECT_TRUE(service->RenamePrinterWhenAdded(info1) == "fwk.driver 1");
    service->RemoveVendorPrinterFromCups(vendorName, printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0137_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0138_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    std::string type = "testType";
    EXPECT_EQ(service->CheckUserIdInEventType(type), false);
    type = PRINTER_CHANGE_EVENT_TYPE;
    EXPECT_EQ(service->CheckUserIdInEventType(type), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0139_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string ppdName;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_FALSE(service->RemoveVendorPrinterFromCups(vendorName, printerId)); // TODO
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    info.SetUri("uri");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    info.SetPrinterMake("maker");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    ppdName = "ppd";
    service->RemoveVendorPrinterFromCups(vendorName, printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0140_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "testPrinterId";
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0141_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:testPrinterId";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    service->printSystemData_.AddPrinterToDiscovery(infoPtr);
    std::string extensionId = "com.ohos.spooler";
    EXPECT_EQ(service->AddSinglePrinterInfo(info, extensionId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0143_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    PrinterPreferences preferences;
    preferences.SetBorderless(true);
    EXPECT_EQ(service->SetPrinterPreference(printerId, preferences), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0144_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.ohos.spooler:testPrinterId";
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    PrinterInfo info;
    EXPECT_EQ(service->UpdatePrinterCapability(printerId, info), true);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0145_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string userName = service->GetCallerUserName();
    EXPECT_FALSE(userName.empty());
    EXPECT_EQ(service->StartPrintJobInternal(nullptr), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, QueryPrinterCapabilityByUri_WhenHasMake_ShouldSucc, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    info->SetPrinterMake("test");
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    // success call to cupsd but response is nothing
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, QueryPrinterCapabilityByUri_WhenNotHasMake_ShouldFailed, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0147_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    Json::Value opsJson;
    opsJson["key"] = "value";
    info->SetOption(PrintJsonUtil::WriteString(opsJson));
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0148_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string printerId = "USB-PixLab_V1-1620";
    std::string standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "usb:ipp://192.168.186.1:631/ipp/print";
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    Json::Value opsJson;
    opsJson["make"] = 123;
    info->SetOption(PrintJsonUtil::WriteString(opsJson));
    service->printSystemData_.discoveredPrinterInfoList_[standardizeId] = info;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, standardizeId, printerCaps), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0149_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "testPrinterId";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0150_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    auto printer = std::make_shared<PrinterInfo>();
    printer->SetPrinterName("testPrinterName");
    std::string printerId = "";
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0155_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string jobId = "123";
    printJob.SetJobId(jobId);
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    printJob.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    Json::Value infoJson;
    infoJson["printerName"] = "testPrinterName";
    printJob.SetOption(PrintJsonUtil::WriteString(infoJson));
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    EXPECT_EQ(service->CheckPrintJob(printJob), false);
    auto printJobPtr = std::make_shared<PrintJob>(printJob);
    service->printJobList_[jobId] = printJobPtr;
    EXPECT_EQ(service->CheckPrintJob(printJob), true);
}

/**
* @tc.name: PrintServiceAbilityTest_0157
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ConnectPrinter
* @tc.require: use old version printerId
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0157_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("1234");
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_INVALID_PRINTER);
    info->SetPrinterId("com.ohos.spooler:mdns://testId");
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_INVALID_PRINTER);
    PrinterInfo printer;
    service->printSystemData_.InsertAddedPrinter(info->GetPrinterId(), printer);
    EXPECT_EQ(service->ConnectPrinter(info->GetPrinterId()), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_CheckPrinterUriDifferent
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC CheckPrinterUriDifferent
* @tc.require: use old version printerId
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_CheckPrinterUriSame, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("com.ohos.spooler:mdns://testId");
    printerInfo->SetUri("ipp://a");

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId("com.ohos.spooler:mdns://testId");
    addedPrinter.SetUri("ipp://a");
    service->printSystemData_.InsertAddedPrinter(addedPrinter.GetPrinterId(), addedPrinter);

    EXPECT_FALSE(service->CheckPrinterUriDifferent(printerInfo));
}

/**
* @tc.name: PrintServiceAbilityTest_CheckPrinterUriDifferent
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC CheckPrinterUriDifferent
* @tc.require: use new version printerId
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_CheckPrinterUriDifferent, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("com.ohos.spooler:mdns://testId");
    printerInfo->SetUri("ipp://a");

    PrinterInfo addedPrinter;
    addedPrinter.SetPrinterId("com.ohos.spooler:mdns://testId");
    addedPrinter.SetUri("ipps://a");
    service->printSystemData_.InsertAddedPrinter(addedPrinter.GetPrinterId(), addedPrinter);

    EXPECT_TRUE(service->CheckPrinterUriDifferent(printerInfo));
}

/**
* @tc.name: FlushCacheFileToUserData_WhenEmptyFdlist_ShouldTrue
* @tc.desc: Verify the FlushCacheFileToUserData do nothing case.
* @tc.type: FUNC FlushCacheFileToUserData
* @tc.require: EmptyFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, FlushCacheFileToUserData_WhenEmptyFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); // EmptyFdlist
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->FlushCacheFileToUserData(jobId), false);
}

/**
* @tc.name: FlushCacheFileToUserData_WhenEmptyFdlist_ShouldTrue
* @tc.desc: Verify the FlushCacheFileToUserData failed case.
* @tc.type: FUNC FlushCacheFileToUserData
* @tc.require: BedFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, FlushCacheFileToUserData_WhenBedFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); 
    userData->queuedJobList_[jobId] = printJob;
    std::vector<uint32_t> fdList = { 999 }; // Bed Fdlist
    printJob->SetFdList(fdList);
    EXPECT_EQ(service->FlushCacheFileToUserData(jobId), false);
}

/**
* @tc.name: DeleteCacheFileFromUserData_WhenEmptyFdlist_ShouldTrue
* @tc.desc: Verify the DeleteCacheFileFromUserData failed case.
* @tc.type: FUNC DeleteCacheFileFromUserData
* @tc.require: EmptyFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, DeleteCacheFileFromUserData_WhenEmptyFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); 
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->DeleteCacheFileFromUserData(jobId), false);
}

/**
* @tc.name: OpenCacheFileFd_WhenEmptyFdlist_ShouldTrue
* @tc.desc: Verify the OpenCacheFileFd do nothing case.
* @tc.type: FUNC OpenCacheFileFd
* @tc.require: EmptyFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, OpenCacheFileFd_WhenEmptyFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::vector<uint32_t> getFdList;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); // EmptyFdlist
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->OpenCacheFileFd(jobId, getFdList), false);
}

/**
* @tc.name: OpenCacheFileFd_WhenEmptyFdlist_ShouldTrue
* @tc.desc: Verify the OpenCacheFileFd failed case.
* @tc.type: FUNC OpenCacheFileFd
* @tc.require: BedFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, OpenCacheFileFd_WhenBedFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::vector<uint32_t> getFdList;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->OpenCacheFileFd(jobId, getFdList), false);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); 
    userData->queuedJobList_[jobId] = printJob;
    std::vector<uint32_t> fdList = { 999 }; // Bed Fdlist
    printJob->SetFdList(fdList);
    EXPECT_EQ(service->OpenCacheFileFd(jobId, getFdList), false);
}


/**
* @tc.name: QueryQueuedPrintJobById_WhenInvalidJobId_ShouldF
* @tc.desc: Verify the QueryQueuedPrintJobById failed case.
* @tc.type: FUNC QueryQueuedPrintJobById
* @tc.require: BedFdlist printJob
*/
HWTEST_F(PrintServiceAbilityTest, QueryQueuedPrintJobById_WhenBedFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    PrintJob getPrintJob;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>(); 
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->QueryQueuedPrintJobById(jobId, getPrintJob), E_PRINT_INVALID_PRINTJOB);
}
} // namespace OHOS::Print
