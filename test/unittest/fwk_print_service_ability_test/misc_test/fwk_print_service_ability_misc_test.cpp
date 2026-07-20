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

#include "print_service_ability_test_common.h"

namespace OHOS {
namespace Print {

/**
 * @tc.name: PrintServiceAbilityTest_0003
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC GetPrintJobOrderId()
 * @tc.require:
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003_NeedRename, TestSize.Level0)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->GetPrintJobOrderId();
    EXPECT_NE(service->currentJobOrderId_, 0);
}

/**
 * @tc.name: PrintServiceAbilityTestPartOne_ErrorToken_ShouldNoPermission
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTestPartOne_ErrorToken_ShouldNoPermission, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->StartService(), E_PRINT_NO_PERMISSION);
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->CallSpooler(fileList, fdList, taskId), E_PRINT_NO_PERMISSION);
    std::string printerId = "1234";
    EXPECT_EQ(service->ConnectPrinter(printerId), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DisconnectPrinter(printerId), E_PRINT_NO_PERMISSION);
    std::vector<std::string> extensionIds;
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NO_PERMISSION);
    std::vector<PrintExtensionInfo> extensionInfos;
    EXPECT_EQ(service->QueryAllExtension(extensionInfos), E_PRINT_NO_PERMISSION);
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(service->QueryAllActivePrintJob(printJobs), E_PRINT_NO_PERMISSION);
    std::vector<PrintJob> historyPrintJobs;
    EXPECT_EQ(service->QueryAllPrintJob(historyPrintJobs), E_PRINT_NO_PERMISSION);
    std::vector<std::string> printerList;
    EXPECT_EQ(service->QueryAddedPrinter(printerList), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->QueryRawAddedPrinter(printerList), E_PRINT_NO_PERMISSION);
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
}

/**
 * @tc.name: PrintServiceAbilityTestPartTwo_ErrorToken_ShouldNoPermission
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTestPartTwo_ErrorToken_ShouldNoPermission, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->StartService(), E_PRINT_NO_PERMISSION);
    std::string taskId = "";
    std::string printerId = "1234";
    std::string printJobId = "1";
    PrintJob printJob;
    std::vector<PrinterInfo> printerInfos;
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NO_PERMISSION);
    std::vector<std::string> printerIds;
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NO_PERMISSION);
    uint32_t state = PrinterState::PRINTER_ADDED;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_NO_PERMISSION);
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobStateOnlyForSystemApp(printJobId, state, subState), E_PRINT_NO_PERMISSION);
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
    PrinterInfo info;
    EXPECT_EQ(service->AddRawPrinter(info), E_PRINT_NO_PERMISSION);
}

/**
 * @tc.name: PrintServiceAbilityTestPartThree_ErrorToken_ShouldNoPermission
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTestPartThree_ErrorToken_ShouldNoPermission, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->StartService(), E_PRINT_NO_PERMISSION);
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    std::string printerId = "1234";
    PrinterInfo info;
    std::vector<std::string> valueList;
    std::string printerName = "pixlab_0759";
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    PrinterPreferences printerPreference;
    std::string detail;
    std::string jobId = "jobId";
    std::string userName = "userName";
    char userPassword[] = "userPassword";

    EXPECT_EQ(service->SetPrinterPreference(printerId, printerPreference), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->SetDefaultPrinter(printerId, 0), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NO_PERMISSION);
    std::vector<PrinterInfo> printers;
    EXPECT_EQ(service->DiscoverUsbPrinters(printers), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->AnalyzePrintEvents(printerId, type, detail), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->AuthPrintJob(jobId, userName, userPassword), E_PRINT_NO_PERMISSION);
#ifdef VIRTUAL_PRINTER_ENABLE
    EXPECT_EQ(service->SavePdfFileJob("job_id", 1), E_PRINT_NO_PERMISSION);
#else
    EXPECT_EQ(service->SavePdfFileJob("job_id", 1), E_PRINT_SERVER_FAILURE);
#endif

    PrintServiceMockPermission::MockPermission();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockHelper, QueryAccounts(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int>{100}), Return(true)));
    service->SetHelper(mockHelper);
    EXPECT_EQ(service->StartService(), E_PRINT_NONE);
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_INVALID_PARAMETER);

    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
    EXPECT_EQ(service->AnalyzePrintEvents(printerId, type, detail), E_PRINT_NONE);
    EXPECT_EQ(service->AuthPrintJob(jobId, userName, userPassword), E_PRINT_INVALID_PRINTJOB);
#ifdef VIRTUAL_PRINTER_ENABLE
    EXPECT_EQ(service->SavePdfFileJob("job_id", 1), E_PRINT_INVALID_USERID);
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_0006
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC CallSpooler
 * @tc.require: has token
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006_NeedRename, TestSize.Level0)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    service->SetHelper(helper);
    EXPECT_EQ(service->helper_, helper);
    helper = make_shared<PrintServiceHelper>();
    if (helper != nullptr) {
        service->SetHelper(helper);
        EXPECT_EQ(service->helper_, helper);
    }
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0013_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0029_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_.insert(std::make_pair(userId, userData));
    EXPECT_EQ(service->QueryAllActivePrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0156_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::vector<PrintJob> printJobs;
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_INVALID_USERID);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_.erase(userId);
    service->printUserMap_.insert(std::make_pair(userId, userData));
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0030_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::vector<PrintJob> printJobs;
    service->QueryAllActivePrintJob(printJobs);
    EXPECT_EQ(service->QueryAllActivePrintJob(printJobs), E_PRINT_NONE);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    service->QueryAllActivePrintJob(printJobs);
    EXPECT_EQ(service->QueryAllActivePrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0034_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printJobId = "1";
    PrintJob printJob;
    EXPECT_EQ(service->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0036_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob1;
    printJob1.SetOption("test");
    EXPECT_EQ(service->UpdatePrintJobOptionByPrinterId(printJob1), false);

    PrintJob printJob2;
    std::string printerId = "com.ohos.spooler:p2p://DIRECTI-PixLab_V1-1620";
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
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0048_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    uint32_t state = PRINTER_UNKNOWN + 1;
    std::string printerId = "1234";
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PARAMETER);
    state = PrinterState::PRINTER_ADDED;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PRINTER);
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = info;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0055_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0060_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0063_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionId = "com.ohos.spooler:0";
    int32_t userId = service->GetCurrentUserId();
    std::string stateKey = PrintUtils::MakeExtensionStateKey(userId, extensionId);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_UNLOAD;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_LOADED;
    EXPECT_EQ(service->DestroyExtension(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0080_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "123";
    service->SetLastUsedPrinter(printerId);
    auto printer = std::make_shared<PrinterInfo>();
    auto ret = service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    service->SetLastUsedPrinter(printerId);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0086_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "";
    EXPECT_EQ(service->isEprint(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0104_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::string jobId = "123";
    EXPECT_EQ(service->GetUserDataByJobId(jobId), nullptr);
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    EXPECT_EQ(service->GetUserDataByJobId(jobId), nullptr);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_NE(service->GetUserDataByJobId(jobId), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0106_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "1234";
    auto ret = service->SetDefaultPrinter(printerId, 0);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0107_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::string printerId = "1234";
    EXPECT_EQ(service->CheckIsDefaultPrinter(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0108_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "1234";
    EXPECT_EQ(service->CheckIsLastUsedPrinter(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, DeletePrinterFromUserData_InvalidPrinterId_ReturnsEarly, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    std::string invalidPrinterId = "invalid_printer_id";

    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    userData->SetUserId(100);
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    userPrefs.SetPrinterId("other_printer");
    userPrefs.SetVendorOptions(R"({"user_field":"value"})");
    userData->SavePrinterUserPreferences("other_printer", "OtherPrinter", userPrefs);
    service->printUserMap_[100] = userData;

    EXPECT_TRUE(userData->printerUserPreferences_.count("other_printer") > 0);

    service->DeletePrinterFromUserData(invalidPrinterId);

    EXPECT_TRUE(userData->printerUserPreferences_.count("other_printer") > 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0123_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0137_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    EXPECT_EQ(service->UpdatePrinterInSystem(info), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0138_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    std::string type = "testType";
    EXPECT_EQ(service->CheckUserIdInEventType(type), false);
    type = PRINTER_CHANGE_EVENT_TYPE;
    EXPECT_EQ(service->CheckUserIdInEventType(type), false);
}

HWTEST_F(PrintServiceAbilityTest, GetKeyList_ShouldReturnEmptyList_WhenCompIsNull, TestSize.Level1)
{
    PrintMapSafe<std::string> map;
    std::function<bool(const std::string &)> comp = nullptr;
    std::vector<std::string> result = map.GetKeyList(comp);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintServiceAbilityTest, GetKeyList_ShouldReturnEmptyList_WhenMapIsEmpty, TestSize.Level1)
{
    PrintMapSafe<std::string> map;
    std::function<bool(const std::string &)> comp = [](const std::string &value) { return value == "test"; };
    std::vector<std::string> result = map.GetKeyList(comp);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintServiceAbilityTest, GetKeyList_ShouldReturnEmptyList_WhenNotElementsSatisfiesComp, TestSize.Level1)
{
    PrintMapSafe<std::string> map;
    std::function<bool(const std::string &)> comp = [](const std::string &value) { return value == "test"; };
    map.Insert("key1", "value1");
    map.Insert("key2", "value2");
    std::vector<std::string> result = map.GetKeyList(comp);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintServiceAbilityTest, GetKeyList_ShouldReturnListOfKeys_WhenElementSatifiesComp, TestSize.Level1)
{
    PrintMapSafe<std::string> map;
    std::function<bool(const std::string &)> comp = [](const std::string &value) { return value == "value2"; };
    map.Insert("key1", "value1");
    map.Insert("key2", "value2");
    std::vector<std::string> result = map.GetKeyList(comp);
    EXPECT_EQ(result.size(), 1);  // 1 element matched
    EXPECT_EQ(result[0], "key2");
}

HWTEST_F(PrintServiceAbilityTest, GetKeyList_ShouldReturnListOfKeys_WhenMultiElementSatifiesComp, TestSize.Level1)
{
    PrintMapSafe<std::string> map;
    std::function<bool(const std::string &)> comp = [](const std::string &value) { return value == "value2"; };
    map.Insert("key1", "value1");
    map.Insert("key2", "value2");
    map.Insert("key3", "value2");
    std::vector<std::string> result = map.GetKeyList(comp);
    EXPECT_EQ(result.size(), 2);  // 2 elements matched
}

HWTEST_F(PrintServiceAbilityTest, RefreshEprinterErrorCapability_ShouldReturnReplaceColor_WhenEprint, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = EPRINTID;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    PrinterCapability caps;
    std::vector<uint32_t> colorList = { 0 };
    caps.SetSupportedColorMode(colorList);
    info.SetCapability(caps);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, info);
    service->RefreshEprinterErrorCapability();
    info = *service->printSystemData_.addedPrinterMap_.Find(printerId);
    info.GetCapability(caps);
    caps.GetSupportedColorMode(colorList);
    EXPECT_EQ(colorList.size(), 2);
}

HWTEST_F(PrintServiceAbilityTest, RefreshEprinterErrorCapability_ShouldReturnNone_WhenNoEprint, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "123";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    PrinterCapability caps;
    std::vector<uint32_t> colorList = { 0 };
    caps.SetSupportedColorMode(colorList);
    info.SetCapability(caps);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, info);
    service->RefreshEprinterErrorCapability();
    info = *service->printSystemData_.addedPrinterMap_.Find(printerId);
    info.GetCapability(caps);
    caps.GetSupportedColorMode(colorList);
    EXPECT_EQ(colorList.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, RefreshEprinterErrorCapability_ShouldReturnNone_WhenEprintHasColor, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = EPRINTID;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    PrinterCapability caps;
    std::vector<uint32_t> colorList = { 0, 1, 2 };
    caps.SetSupportedColorMode(colorList);
    info.SetCapability(caps);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, info);
    service->RefreshEprinterErrorCapability();
    info = *service->printSystemData_.addedPrinterMap_.Find(printerId);
    info.GetCapability(caps);
    caps.GetSupportedColorMode(colorList);
    EXPECT_EQ(colorList.size(), 3);
}

HWTEST_F(PrintServiceAbilityTest, PrinterDisableTest, TestSize.Level1)
{
#ifdef EDM_SERVICE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    EXPECT_EQ(service->IsDisablePrint(), false);
#endif // EDM_SERVICE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, ReportBannedEventTest, TestSize.Level1)
{
#ifdef EDM_SERVICE_ENABLE
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    std::string emptyString = "";
    EXPECT_EQ(service->ReportBannedEvent(emptyString), 401);
    std::string jsonString =
            "{\n"
            "    \"key\": \"option\",\n"
            "    \"value\": \"jobName\"\n"
            "}";
    EXPECT_EQ(service->ReportBannedEvent(jsonString), 0);
#endif // EDM_SERVICE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, CheckStartExtensionPermission, TestSize.Level1)
{
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_EQ(service->CheckStartExtensionPermission(), false);
}

HWTEST_F(PrintServiceAbilityTest,
    GetSharedHosts_Test, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::vector<PrintSharedHost> sharedHosts;
    EXPECT_EQ(service->GetSharedHosts(sharedHosts), E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest,
    AuthSmbDevice_Test, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    PrintSharedHost sharedHost;
    std::string userName;
    char *userPasswd = nullptr;
    std::vector<PrinterInfo> printerInfos;
    EXPECT_EQ(service->AuthSmbDevice(sharedHost, userName, userPasswd, printerInfos), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(printerInfos.empty(), true);
}

HWTEST_F(PrintServiceAbilityTest, UpdateExtensionInfo_WhenInvalidExtensionId_ShouldReturnInvalid, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    std::string extInfo = "test_ext_info";
    std::string extensionId = "invalid_extension_id";
    int32_t result = service->UpdateExtensionInfo(extInfo);
    EXPECT_EQ(result, E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: UpdatePrinterCapability_CustomDriverPrinterAlreadyAdded_StillInserts
* @tc.desc: Custom driver printers always re-insert even when already added
* @tc.type: FUNC
* @tc.require: startsWith(printerId, "fwk.driver.printer.driver") bypasses IsPrinterAdded check
*/
HWTEST_F(PrintServiceAbilityTest,
    UpdatePrinterCapability_CustomDriverPrinterAlreadyAdded_StillInserts, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "fwk.driver.printer.driver.com.example:TestPrinter";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("TestPrinter");
    service->printSystemData_.InsertAddedPrinter(printerId, printerInfo);
    EXPECT_TRUE(service->printSystemData_.IsPrinterAdded(printerId));
    bool result = service->UpdatePrinterCapability(printerId, printerInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(service->printSystemData_.IsPrinterAdded(printerId));
}

/**
* @tc.name: UpdatePrinterCapability_RegularPrinterAlreadyAdded_SkipsInsert
* @tc.desc: Regular printers skip re-insertion when already added (existing behavior unchanged)
* @tc.type: FUNC
* @tc.require: Non-custom-driver printer that is already added goes to else branch
*/
HWTEST_F(PrintServiceAbilityTest,
    UpdatePrinterCapability_RegularPrinterAlreadyAdded_SkipsInsert, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "com.ohos.spooler:SomePrinter";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("SomePrinter");
    service->printSystemData_.InsertAddedPrinter(printerId, printerInfo);
    EXPECT_TRUE(service->printSystemData_.IsPrinterAdded(printerId));
    bool result = service->UpdatePrinterCapability(printerId, printerInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_HandleWebPrinterUninstall, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    std::string printerId = "123";
    info.SetPrinterId(printerId);
    service->AddSinglePrinterInfo(info, WEBPRINTER_BUNDLE_NAME);
    printerId = PrintUtils::GetGlobalId(WEBPRINTER_BUNDLE_NAME, printerId);
    EXPECT_NE(service->printSystemData_.QueryDiscoveredPrinterInfoById(printerId), nullptr);
    info.SetPrinterId(printerId);
    service->HandleWebPrinterUninstall();
    EXPECT_EQ(service->printSystemData_.QueryDiscoveredPrinterInfoById(printerId), nullptr);
}
#ifdef REMOTE_SERVICE_ENABLE

HWTEST_F(PrintServiceAbilityTest, IsExtensionPrintJob_remoteprinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string cid = REMOTE_EXT_BUNDLE_NAME;
    cid = cid + ":1";
    EXPECT_TRUE(service->IsExtensionPrintJob(PRINT_EXTENSION_BUNDLE_NAME));
}
#endif  // REMOTE_SERVICE_ENABLE


HWTEST_F(PrintServiceAbilityTest, IsExtensionPrintJob_eprint, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string cid = PRINT_EXTENSION_BUNDLE_NAME;
    cid = cid + ":1";
    EXPECT_TRUE(service->IsExtensionPrintJob("com.ohos.remote:1"));
}

HWTEST_F(PrintServiceAbilityTest, IsExtensionPrintJob_notExt, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string cid = ":1";
    EXPECT_FALSE(service->IsExtensionPrintJob(cid));
}

HWTEST_F(PrintServiceAbilityTest, ParseSingleAdvanceOptJson_NonStringItem_ShouldSkip, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string keyword = "testKeyword";
    Json::Value singleOptArray;
    singleOptArray.append("validString");
    singleOptArray.append(123);
    singleOptArray.append(true);
    Json::Value singleAdvanceOptJson;
    service->ParseSingleAdvanceOptJson(keyword, singleOptArray, singleAdvanceOptJson);
    EXPECT_TRUE(singleAdvanceOptJson.isMember("choice"));
    EXPECT_EQ(1, singleAdvanceOptJson["choice"]["default"].size());
}

}  // namespace Print
}  // namespace OHOS
