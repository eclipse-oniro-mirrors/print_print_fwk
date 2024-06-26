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
#include "print_bms_helper.h"
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
    service->RemovePrinters(newPrinterIds);
    printerInfos.clear();
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_INVALID_PARAMETER);
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0017, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    service->CallStatusBar();
    service->helper_= nullptr;
    service->CallStatusBar();
    service->SetHelper(nullptr);
    service->CallStatusBar();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->SetHelper(helper);
    service->CallStatusBar();
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
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0032, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-1620";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_INVALID_PRINTER);
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterInfoList_[printerId] = printerInfo;
    keyList.push_back("printerId");
    keyList.push_back("printerName");
    EXPECT_EQ(service->QueryPrinterProperties(printerId, keyList, valueList), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0033, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-1620";
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
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-1620";
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
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-1620";
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
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
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
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-1620";
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0047, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int32_t userId = 100;
    service->SwitchUser(userId);
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
    EXPECT_EQ(service->checkJobState(state, subState), false);
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
    std::string type = "PRINT_GET_FILE_EVENT_TYPE";
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
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->printJobList_[jobId] = printJob;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
    state = PRINT_JOB_BLOCKED;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
    state = PRINT_JOB_COMPLETED;
    service->CheckAndSendQueuePrintJob(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0053, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string jobId = "1";
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), true);
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->printJobList_[jobId] = printJob;
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), true);
    userData->printJobList_.clear();
    service->currentUserId_ = 0;
    EXPECT_EQ(service->IsQueuedJobListEmpty(jobId), true);
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
    event = 1;
    service->NotifyPrintServiceEvent(jobId, event);
    event = 2;
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
  // namespace Print
}  // namespace OHOS
