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
#include "nlohmann/json.hpp"
#include "print_ipp_over_usb_manager.h"
#include "mock_print_callback_proxy.h"
#include "mock_print_extension_callback_proxy.h"


using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using json = nlohmann::json;
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
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001, TestSize.Level1)
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
    sptr<PrintServiceAbility> service = PrintServiceAbility::GetInstance();
    EXPECT_NE(service->instance_, nullptr);
    EXPECT_EQ(PrintServiceAbility::GetInstance()->Init(), E_PRINT_SERVER_FAILURE);
}
/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ManualStart()
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002, TestSize.Level1)
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
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003, TestSize.Level1)
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
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0004, TestSize.Level1)
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
    std::string printerPreference = "";
    EXPECT_EQ(service->GetPrinterPreference(printerId, printerPreference), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->SetPrinterPreference(printerId, printerPreference), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->SetDefaultPrinter(printerId, 0), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DeletePrinterFromCups(printerUri, printerName, printerMake), E_PRINT_NO_PERMISSION);

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
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006, TestSize.Level1)
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
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0007, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    service->SetHelper(helper);
    helper = make_shared<PrintServiceHelper>();
    if (helper != nullptr) {
        service->SetHelper(helper);
    }
}

/**
* @tc.name: PrintServiceAbilityTest_0008
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC ConnectPrinter
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId ="1234";
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printerInfoList_[printerId] = info;
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId ="1234";
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printerInfoList_[printerId] = info;
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012, TestSize.Level1)
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
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_INVALID_PARAMETER);
    listener = new MockPrintCallbackProxy();
    if (listener != nullptr) {
        service->On(taskId, type, listener);
    }
    service->registeredListeners_[type] = listener;
    taskId = "";
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
    delete listener;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0013, TestSize.Level1)
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
    service->printerInfoList_[printerId] = info;
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NONE);
    std::vector<std::string> newPrinterIds;
    newPrinterIds.push_back("1234");
    auto cupsPrinter = std::make_shared<CupsPrinterInfo>();
    service->printSystemData_.addedPrinterMap_[printerId] = cupsPrinter;
    service->RemovePrinters(newPrinterIds);
    printerInfos.clear();
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0014, TestSize.Level1)
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
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_SERVER_FAILURE);
    std::string extensionId = PrintUtils::GetExtensionId(GetDefaultPrinterId());
    sptr<IPrintExtensionCallback> listener = nullptr;
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    service->extCallbackMap_[cid] = listener;
    service->StartPrintJob(testJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0018, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId ="1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    service->notifyAdapterJobChanged(jobId, state, subState);
    PrintAttributes attr;
    service->printAttributesList_[jobId] = attr;
    service->notifyAdapterJobChanged(jobId, state, subState);
    sptr<IPrintCallback> listener = nullptr;
    service->adapterListenersByJobId_[jobId] = listener;
    service->notifyAdapterJobChanged(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0019, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId ="1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    
    state = PRINT_JOB_BLOCKED;
    service->notifyAdapterJobChanged(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0020, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobName = "a.jpeg";
    PrintAttributes printAttributes;
    std::string taskId ="1";
    service->PrintByAdapter(jobName, printAttributes, taskId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0021, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "1";
    PrintAttributes printAttributes;
    uint32_t fd = 46;
    sptr<IPrintCallback> listener = nullptr;
    service->adapterListenersByJobId_[jobId] = listener;
    service->StartGetPrintFile(jobId, printAttributes, fd);
    service->adapterListenersByJobId_.clear();
 
    service->StartGetPrintFile(jobId, printAttributes, fd);
    service->printAttributesList_[jobId] = printAttributes;
    service->StartGetPrintFile(jobId, printAttributes, fd);
    std::string newJobId = "2";
    service->StartGetPrintFile(newJobId, printAttributes, fd);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0022, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "1234";
    EXPECT_EQ(service->getPrinterInfo(printerId), nullptr);
    std::shared_ptr<PrinterInfo> info =std::make_shared<PrinterInfo>();
    service->printerInfoList_[printerId] = info;
    service->getPrinterInfo(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    service->CheckJobQueueBlocked(jobInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "com.huawei.hmos.spooler:0";
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->OnStop();
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->OnStop();
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "com.huawei.hmos.spooler:0";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_STOP_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0029, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_.insert(std::make_pair(userId, userData));
    service->QueryAllPrintJob(printJobs);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0030, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    service->QueryAllPrintJob(printJobs);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->QueryAllPrintJob(printJobs);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0031, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0032, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterInfoList_[printerId] = printerInfo;
    keyList.push_back("printerId");
    keyList.push_back("printerName");
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0033, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<CupsPrinterInfo>();
    printerInfo->name = "testName";
    printerInfo->uri = "testUri";
    printerInfo->maker = "testMaker";
    service->printSystemData_.addedPrinterMap_[printerId] = printerInfo;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0034, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printJobId = "1";
    PrintJob printJob;
    service->QueryPrintJobById(printJobId, printJob);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->QueryPrintJobById(printJobId, printJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0035, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerUri = "testPrinterUri";
    std::string printerName = "testPrinterName";
    std::string printerMake = "testPrinterMake";
    EXPECT_EQ(service->AddPrinterToCups(printerUri, printerName, printerMake), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0036, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob1;
    printJob1.SetOption("test");
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob1), false);

    PrintJob printJob2;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    printJob2.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<CupsPrinterInfo>();
    printerInfo->name = "testName";
    printerInfo->uri = "testUri";
    printerInfo->maker = "testMaker";
    service->printSystemData_.addedPrinterMap_[printerId] = printerInfo;
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob2), false);

    nlohmann::json infoJson;
    infoJson["printerName"] = "testPrinterName";
    printJob2.SetOption(infoJson.dump());
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob2), true);
    service->StartNativePrintJob(printJob2);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->StartNativePrintJob(printJob2);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0037, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string jobId = GetDefaultJobId();
    service->AddNativePrintJob(jobId, printJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0038, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    printJob.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<CupsPrinterInfo>();
    printerInfo->name = "testName";
    printerInfo->uri = "testUri";
    printerInfo->maker = "testMaker";
    service->printSystemData_.addedPrinterMap_.insert(std::make_pair(printerId, printerInfo));
    printJob.SetOption("test");
    EXPECT_EQ(service->StartNativePrintJob(printJob), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0040, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0041, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = GetDefaultJobId();
    service->CancelPrintJob(jobId);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->CancelPrintJob(jobId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0042, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    printJob.SetJobId(GetDefaultJobId());
    service->SetPrintJobCanceled(printJob);
    std::string jobId = "123";
    printJob.SetJobId(jobId);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->SetPrintJobCanceled(printJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0043, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    int32_t userId = 100;
    service->CancelUserPrintJobs(userId);

    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->CancelUserPrintJobs(userId);

    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->CancelUserPrintJobs(userId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0044, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    service->SendQueuePrintJob(printerId);

    std::string jobId = GetDefaultJobId();
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    service->SendQueuePrintJob(printerId);
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->SendQueuePrintJob(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0045, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerUri = "111.222.333";
    std::string printerId = "pixlab_0759";
    PrinterCapability printerCaps;
    EXPECT_EQ(service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0046, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    service->StartPrintJobCB(jobId, printJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0048, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINTER_UNKNOWN + 1;
    std::string printerId ="1234";
    service->UpdatePrinterState(printerId, state);
    state = PrinterState::PRINTER_ADDED;
    service->UpdatePrinterState(printerId, state);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printerInfoList_[printerId] = info;
    service->UpdatePrinterState(printerId, state);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0049, TestSize.Level1)
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
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
    state = PRINT_JOB_COMPLETED;
    subState = PRINT_JOB_COMPLETED_FILE_CORRUPT + 1;
    EXPECT_EQ(service->checkJobState(state, subState), false);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0050, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0051, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0052, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->printJobList_[jobId] = printJob;
    state = PRINT_JOB_BLOCKED;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
    userData->queuedJobList_[jobId] = printJob;
    state = PRINT_JOB_COMPLETED;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0053, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0055, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0056, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0057, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int event = 0;
    PrinterInfo info;
    service->SendPrinterChangeEvent(event, info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0058, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintJob> jobInfo = std::make_shared<PrintJob>();
    std::string printerId = "1234";
    uint32_t subState = 0;
    service->ReportHisysEvent(jobInfo, printerId, subState);
    printerId = "ePrintID";
    service->ReportHisysEvent(jobInfo, printerId, subState);
    std::shared_ptr<PrinterInfo> printInfo = std::make_shared<PrinterInfo>();
    printInfo->SetPrinterName("Direct0759");
    service->printerInfoList_[printerId] = printInfo;
    service->ReportHisysEvent(jobInfo, printerId, subState);
    nlohmann::json infoJson;
    infoJson["printerUri"] = "ipp123";
    jobInfo->SetOption(infoJson.dump());
    service->ReportHisysEvent(jobInfo, printerId, subState);
    infoJson["jobDescription"] = "testPrinter";
    jobInfo->SetOption(infoJson.dump());
    service->ReportHisysEvent(jobInfo, printerId, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0059, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0060, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    AppExecFwk::ExtensionAbilityInfo extInfo;
    extInfo.bundleName = "spooler";

    PrintExtensionInfo newExtInfo;
    newExtInfo = service->ConvertToPrintExtensionInfo(extInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0061, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->CancelPrintJob(jobId);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = printJob;
    service->CancelPrintJob(jobId);
    printJob->SetJobState(PRINT_JOB_RUNNING);
    service->CancelPrintJob(jobId);
    printJob->SetPrinterId("1234");
    std::string extensionId = PrintUtils::GetExtensionId("1234");
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->CancelPrintJob(jobId);
    printJob->SetPrinterId("com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620");
    std::string extensionId2 = PrintUtils::GetExtensionId("com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620");
    std::string cid2 = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
    service->extCallbackMap_[cid2] = extCb;
    service->CancelPrintJob(jobId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0062, TestSize.Level1)
{
    DelayedSingleton<PrintBMSHelper>::GetInstance()->hasBms = false;
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::vector<std::string> extensionIds;
    std::string extensionId = "com.huawei.hmos.spooler";
    extensionIds.push_back(extensionId);
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
    std::vector<PrintExtensionInfo> extensionInfos;
    service->QueryAllExtension(extensionInfos);
    service->StartDiscoverPrinter(extensionIds);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0063, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = "com.huawei.hmos.spooler:0";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DESTROY_EXTENSION);
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->extCallbackMap_[cid] = listener;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0064, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterInfo info;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<CupsPrinterInfo>();
    printerInfo->name = "testName";
    printerInfo->uri = "testUri";
    printerInfo->maker = "testMaker";
    PrinterCapability caps;
    nlohmann::json opsJson;
    opsJson["key"] = "value";
    caps.SetOption(opsJson.dump());
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    caps.SetPageSize(pageSizeList);
    printerInfo->printerCapability = caps;
    service->printSystemData_.addedPrinterMap_[printerId] = printerInfo;
    EXPECT_EQ(service->QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0065, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    service->printSystemData_.addedPrinterInfoList_[printerId] = info;
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    service->QueryPrinterProperties(printerId, keyList, valueList);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0066, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    service->printSystemData_.addedPrinterInfoList_[printerId] = info;
    std::string savePrinterPreference = "test";
    service->printerIdAndPreferenceMap_[printerId] = savePrinterPreference;
    std::vector<std::string> keyList;
    keyList.emplace_back("pagesizeId");
    keyList.emplace_back("orientation");
    keyList.emplace_back("duplex");
    keyList.emplace_back("quality");
    keyList.emplace_back("test");
    std::vector<std::string> valueList;
    service->QueryPrinterProperties(printerId, keyList, valueList);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0067, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    service->printerIdAndPreferenceMap_[printerExtId] = "test";
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0068, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    std::string printerExtId = PrintUtils::GetGlobalId("", printerId);
    service->printerIdAndPreferenceMap_["123"] = "test";
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}
 
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0069, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    PrinterCapability printerCaps;
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    service->printerInfoList_["123"] = nullptr;
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printerInfoList_["456"] = printerInfo;
    service->printerInfoList_[printerId] = printerInfo;
    service->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0070, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "DIRECT-HUAWEI_PixLab_V1-1620";
    service->StandardizePrinterId(printerId);
    std::string printerId2 = "p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    service->StandardizePrinterId(printerId2);
    std::string printerId3 = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    service->StandardizePrinterId(printerId3);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0071, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PreferenceSetting printerDefaultAttr;
    nlohmann::json capOpt;
    service->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
    capOpt["defaultPageSizeId"] = 123;
    capOpt["orientation-requested-default"] = 123;
    capOpt["sides-default"] = 123;
    capOpt["print-quality-default"] = 123;
    service->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
    capOpt["defaultPageSizeId"] = "123";
    capOpt["orientation-requested-default"] = "123";
    capOpt["sides-default"] = "123";
    capOpt["print-quality-default"] = "123";
    service->BuildPrinterPreferenceByDefault(capOpt, printerDefaultAttr);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0072, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string key;
    std::string supportedOpts;
    std::vector<std::string> optAttrs;
    service->BuildPrinterPreferenceByOption(key, supportedOpts, optAttrs);
    std::string supportedOpts2 = "test";
    service->BuildPrinterPreferenceByOption(key, supportedOpts2, optAttrs);
    nlohmann::json optJson;
    nlohmann::json itemJson;
    itemJson["key"] = "value";
    optJson["testList"] = itemJson;
    std::string supportedOpts3 = optJson.dump();
    service->BuildPrinterPreferenceByOption(key, supportedOpts3, optAttrs);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0073, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterCapability cap;
    PrinterPreference printPreference;
    cap.SetOption("test");
    service->BuildPrinterPreference(cap, printPreference);
    nlohmann::json capJson;
    capJson["key"] = "value";
    cap.SetOption(capJson.dump());
    service->BuildPrinterPreference(cap, printPreference);
    nlohmann::json capJson2;
    capJson2["cupsOptions"] = "value";
    cap.SetOption(capJson2.dump());
    service->BuildPrinterPreference(cap, printPreference);
    nlohmann::json capJson3;
    nlohmann::json capOpt3;
    capOpt3["supportedPageSizeArray"] = 123;
    capOpt3["orientation-requested-supported"] = 123;
    capOpt3["sides-supported"] = 123;
    capOpt3["print-quality-supported"] = 123;
    capJson3["cupsOptions"] = capOpt3;
    cap.SetOption(capJson3.dump());
    service->BuildPrinterPreference(cap, printPreference);
    nlohmann::json capJson4;
    nlohmann::json capOpt4;
    capOpt4["supportedPageSizeArray"] = "123";
    capOpt4["orientation-requested-supported"] = "123";
    capOpt4["sides-supported"] = "123";
    capOpt4["print-quality-supported"] = "123";
    capJson4["cupsOptions"] = capOpt4;
    cap.SetOption(capJson4.dump());
    service->BuildPrinterPreference(cap, printPreference);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0074, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string key = "key";
    nlohmann::json jsonArrObject = nlohmann::json::object();
    jsonArrObject["key"] = "value";
    std::vector<std::string> printerAttrs;
    service->BuildPrinterAttrComponentByJson(key, jsonArrObject, printerAttrs);

    nlohmann::json jsonArrObject2 = nlohmann::json::array();
    nlohmann::json attrItem = nlohmann::json::object();
    attrItem["123"] = "123";
    nlohmann::json attrItem2 = nlohmann::json::object();;
    attrItem2["key"] = "123";
    nlohmann::json attrItem3 = nlohmann::json::object();;
    attrItem3["key"] = 123;
    jsonArrObject2.push_back(attrItem);
    jsonArrObject2.push_back(attrItem2);
    jsonArrObject2.push_back(attrItem3);
    service->BuildPrinterAttrComponentByJson(key, jsonArrObject2, printerAttrs);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0075, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    std::string printerPreference = "";
    service->GetPrinterPreference(printerId, printerPreference);
    service->printerIdAndPreferenceMap_["111"] = "123";
    service->GetPrinterPreference(printerId, printerPreference);
    service->printerIdAndPreferenceMap_["123"] = "123";
    service->GetPrinterPreference(printerId, printerPreference);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0076, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    std::string printerSetting = "test";
    service->SetPrinterPreference(printerId, printerSetting);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0077, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "123";
    std::string printerPreference = "test";
    service->printerIdAndPreferenceMap_["111"] = "123";
    service->ReadPreferenceFromFile(printerId, printerPreference);
    service->printerIdAndPreferenceMap_["123"] = "123";
    service->ReadPreferenceFromFile(printerId, printerPreference);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0078, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->InitPreferenceMap();
    service->printerIdAndPreferenceMap_["printerId"] = "123";
    nlohmann::json printPreferenceJson;
    printPreferenceJson["key"] = "value";
    service->printerIdAndPreferenceMap_["printerId2"] = printPreferenceJson.dump();
    service->WritePreferenceToFile();
    service->InitPreferenceMap();
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0079, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    PrintJob printJob;
    nlohmann::json opsJson;
    opsJson["key"] = "value";
    printJob.SetPrinterId(printerId);
    printJob.SetOption(opsJson.dump());
    auto cupsPrinter = std::make_shared<CupsPrinterInfo>();
    service->printSystemData_.addedPrinterMap_[printerId] = cupsPrinter;
    service->StartNativePrintJob(printJob);
    auto extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->StartNativePrintJob(printJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0080, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "123";
    service->SetLastUsedPrinter(printerId);
    auto cupsPrinter = std::make_shared<CupsPrinterInfo>();
    service->printSystemData_.addedPrinterMap_[printerId] = cupsPrinter;
    service->SetLastUsedPrinter(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0081, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINT_JOB_UNKNOWN + 1;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    service->checkJobState(state, subState);
    std::string jobId = "123";
    service->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0082, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    std::string jobId = "123";
    std::string type = PRINT_GET_FILE_EVENT_TYPE;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[type] = listener;
    service->AdapterGetFileCallBack(jobId, state, subState);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_FAILED;
    service->AdapterGetFileCallBack(jobId, state, subState);
    subState = PRINT_JOB_BLOCKED_UNKNOWN;
    service->AdapterGetFileCallBack(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0083, TestSize.Level1)
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
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0084, TestSize.Level1)
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
    service->printerInfoList_[printerId] = printerInfo;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0085, TestSize.Level1)
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
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0086, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "";
    service->isEprint(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0087, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    service->QueryPrinterCapability(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printerInfoList_[printerId] = printerInfo;
    service->QueryPrinterCapability(printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_CAP);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->QueryPrinterCapability(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0088, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    service->RegisterExtCallback(extensionCid, listener);
    std::string extensionCid2 = "123:20";
    service->RegisterExtCallback(extensionCid2, listener);
    std::string extensionId = "123";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    service->RegisterExtCallback(extensionCid2, listener);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADING;
    service->RegisterExtCallback(extensionCid2, listener);
    std::string extensionCid3 = "123:2";
    service->RegisterExtCallback(extensionCid2, listener);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0089, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    uint32_t callbackId = 0;
    std::string extensionId = "123";
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    sptr<IPrintExtensionCallback> extCb = nullptr;
    service->extCallbackMap_[cid] = extCb;
    service->UnregisterAllExtCallback(extensionId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0090, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "123";
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_UNLOAD;
    service->LoadExtSuccess(extensionId);
    service->extensionStateList_[extensionId] = PRINT_EXTENSION_LOADING;
    service->LoadExtSuccess(extensionId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0091, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0092, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->helper_ = nullptr;
    AAFwk::Want want;
    service->StartAbility(want);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0093, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    service->SendPrinterDiscoverEvent(event, info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0094, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    service->SendPrinterChangeEvent(event, info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0095, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    service->SendPrinterEvent(info);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[PRINTER_EVENT_TYPE] = listener;
    service->SendPrinterEvent(info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0096, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterInfo info;
    PrinterEvent printerEvent = PRINTER_EVENT_STATE_CHANGED;
    service->registeredListeners_["test"] = nullptr;
    service->SendPrinterEventChangeEvent(printerEvent, info);

    std::string eventType = "123" + PRINTER_CHANGE_EVENT_TYPE;
    service->registeredListeners_[eventType] = nullptr;
    service->SendPrinterEventChangeEvent(printerEvent, info);

    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[eventType] = listener;
    service->SendPrinterEventChangeEvent(printerEvent, info);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0097, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0098, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string extensionId = "123";
    std::string extInfo = "123";
    service->SendExtensionEvent(extensionId, extInfo);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[EXTINFO_EVENT_TYPE] = listener;
    service->SendExtensionEvent(extensionId, extInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0099, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrintJob jobInfo;
    std::string jobId = "123";
    jobInfo.SetJobId(jobId);
    service->isJobQueueBlocked_ = true;
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->CheckJobQueueBlocked(jobInfo);
    service->isJobQueueBlocked_ = false;
    service->CheckJobQueueBlocked(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_BLOCKED);
    service->CheckJobQueueBlocked(jobInfo);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    service->CheckJobQueueBlocked(jobInfo);
    service->isJobQueueBlocked_ = true;
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->CheckJobQueueBlocked(jobInfo);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    auto job = std::make_shared<PrintJob>();
    job->SetJobState(PRINT_JOB_COMPLETED);
    auto job2 = std::make_shared<PrintJob>();
    job2->SetJobState(PRINT_JOB_BLOCKED);
    userData->queuedJobList_["1"] = job;
    userData->queuedJobList_["2"] = job2;
    service->CheckJobQueueBlocked(jobInfo);
    userData->queuedJobList_.clear();
    userData->queuedJobList_["1"] = job;
    service->CheckJobQueueBlocked(jobInfo);
    service->userJobMap_.clear();
    service->CheckJobQueueBlocked(jobInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0100, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobName = "";
    PrintAttributes printAttributes;
    std::string taskId = "";
    service->PrintByAdapter(jobName, printAttributes, taskId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0102, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    uint32_t state = PRINT_JOB_RUNNING;
    uint32_t subState = PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    state = PRINT_JOB_SPOOLER_CLOSED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    state = PRINT_JOB_COMPLETED;
    PrintAttributes printAttributes;
    service->printAttributesList_[jobId] = printAttributes;
    service->notifyAdapterJobChanged(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0103, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->helper_ = nullptr;
    AAFwk::Want want;
    EXPECT_FALSE(service->StartPluginPrintIconExtAbility(want));
    service->helper_ = std::make_shared<PrintServiceHelper>();
    service->StartPluginPrintIconExtAbility(want);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0104, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    service->GetUserDataByJobId(jobId);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->GetUserDataByJobId(jobId);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    service->GetUserDataByJobId(jobId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0105, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "123";
    service->RegisterAdapterListener(jobId);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    service->registeredListeners_[PRINT_ADAPTER_EVENT_TYPE] = listener;
    service->RegisterAdapterListener(jobId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0106, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    service->SetDefaultPrinter(printerId, 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0107, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    service->CheckIsDefaultPrinter(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0108, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "1234";
    service->CheckIsLastUsedPrinter(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0109, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerUri = "111.222.333";
    std::string printerName = "pixlab_0759";
    std::string printerMake = "pixlab b5";
    service->DeletePrinterFromCups(printerUri, printerName, printerMake);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0111, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "printerId";
    int32_t userId1 = 100;
    int32_t userId2 = 101;
    std::shared_ptr<PrintUserData> userData1 = std::make_shared<PrintUserData>();
    userData1->SetDefaultPrinter("test", 0);
    std::shared_ptr<PrintUserData> userData2 = std::make_shared<PrintUserData>();
    userData1->SetDefaultPrinter(printerId, 0);
    service->printUserMap_[userId1] = userData1;
    service->printUserMap_[userId2] = userData2;
    service->DeletePrinterFromUserData(printerId);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0112, TestSize.Level1)
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
    service->printerInfoList_[printerId] = printerInfo;
    service->currentUserId_ = 0;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0113, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string taskId = "";
    std::string type = PRINTER_CHANGE_EVENT_TYPE;
    service->Off(taskId, type);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0120, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0121, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0122, TestSize.Level1)
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0123, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int32_t userId = 100;
    auto userData1 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData1, nullptr);
    auto userData2 = service->GetUserDataByUserId(100);
    EXPECT_EQ(userData1, userData2);
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0124, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int32_t userId = 100;
    auto userData1 = service->GetUserDataByUserId(100);
    EXPECT_NE(userData1, nullptr);
    auto userData2 = service->GetUserDataByUserId(100);
    EXPECT_EQ(userData1, userData2);
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0125, TestSize.Level1)
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
} // namespace OHOS::Print
