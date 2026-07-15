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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0014_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintJob testJob;
    std::string jobId = GetDefaultJobId();
    testJob.SetJobId(jobId);
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> job = std::make_shared<PrintJob>();
    service->printJobList_["1"] = job;
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_INVALID_PRINTJOB);
    service->printJobList_["0"] = job;
    service->StartPrintJob(testJob);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0020_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobName = "a.jpeg";
    PrintAttributes printAttributes;
    std::string taskId = "1";
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0021_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "1";
    PrintAttributes printAttributes;
    uint32_t fd = 46;
    EXPECT_EQ(service->StartGetPrintFile(jobId, printAttributes, fd), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0037_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
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
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
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
    std::string type = "0";
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
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = GetDefaultJobId();
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintServiceAbilityTest, RestartPrintJob_WhenInvalidUserData_ShouldFailed, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = GetDefaultJobId();
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
    int32_t userId = 100;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->RestartPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, RestartPrintJob_WhenBedfd_ShouldFailed, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);

    std::string jobId = GetDefaultJobId();
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->SendQueuePrintJob(printerId), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0046_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    service->StartPrintJobCB(jobId, printJob);
    EXPECT_EQ(printJob->jobState_, PRINT_JOB_QUEUED);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0052_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    int32_t userId = 100;
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    service->printUserMap_.insert(std::make_pair(userId, nullptr));
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_INVALID_USERID);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_.erase(userId);
    service->userJobMap_.insert(std::make_pair(jobId, userId));
    service->printUserMap_.insert(std::make_pair(userId, userData));
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    std::string printerId = "1234";
    printJob->SetPrinterId(printerId);
    printJob->SetJobId(jobId);
    printJob->SetOption("{\"test\":\"test\"}");
    userData->AddPrintJobToHistoryList(printJob->GetPrinterId(), printJob->GetJobId(), printJob);
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(printJob->GetJobId(), state, subState), E_PRINT_NONE);
    userData->printJobList_[jobId] = printJob;
    state = PRINT_JOB_BLOCKED;
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(printJob->GetJobId(), state, subState), E_PRINT_NONE);
    state = PRINT_JOB_COMPLETED;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(printJob->GetJobId(), state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0053_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0061_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "123";
    int32_t userId = 100;
    service->printUserMap_[userId] = nullptr;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_USERID);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId("1234");
    printJob->SetOption("{\"test\":\"test\"}");
    userData->AddPrintJobToHistoryList(printJob->GetPrinterId(), printJob->GetJobId(), printJob);
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    printJob->SetJobState(PRINT_JOB_RUNNING);
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    std::string extensionId = PrintUtils::GetExtensionId("1234");
    sptr<IPrintExtensionCallback> extCb = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterExtensionListener(
        EXTCB_CANCEL_PRINT, extensionId, extCb);
    service->CancelPrintJob(jobId);
    printJob->SetPrinterId("com.huawei.hmos.spooler:p2p://DIRECT-PixLab_V1-1620");
    std::string extensionId2 = PrintUtils::GetExtensionId("com.huawei.hmos.spooler:p2p://DIRECT-PixLab_V1-1620");
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
    DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterExtensionListener(
        EXTCB_CANCEL_PRINT, extensionId2, extCb);
    EXPECT_EQ(service->CancelPrintJob(jobId), E_PRINT_NONE);
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
}

HWTEST_F(PrintServiceAbilityTest, StartNativePrintJob_Is_JobId_Empty, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
    std::string printerId = "123";
    PrintJob printJob;
    Json::Value opsJson;
    opsJson["key"] = "value";
    printJob.SetPrinterId(printerId);
    printJob.SetOption(PrintJsonUtil::WriteString(opsJson));
    auto printer = std::make_shared<PrinterInfo>();
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printer);
    auto ret = service->StartNativePrintJob(printJob);
    EXPECT_EQ(ret, E_PRINT_NONE);
    printJob.SetJobId("jobId");
    ret = service->StartNativePrintJob(printJob);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0083_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
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
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0084_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0100_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobName = "";
    PrintAttributes printAttributes;
    std::string taskId = "";
    auto ret = service->PrintByAdapter(jobName, printAttributes, taskId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0112_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
    std::string jobId = "1";
    int32_t userId = 0;
    service->userJobMap_[jobId] = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = 0;
    std::string printerId = "1234";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    printJob->SetOption("{\"test\":\"test\"}");
    userData->queuedJobList_[jobId] = printJob;
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    service->printSystemData_.discoveredPrinterInfoList_[printerId] = printerInfo;
    service->currentUserId_ = 0;
    EXPECT_EQ(service->CheckAndSendQueuePrintJob(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0145_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string userName = service->GetCallerUserName();
    EXPECT_FALSE(userName.empty());
    EXPECT_EQ(service->StartPrintJobInternal(nullptr), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0155_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    PrintJob printJob;
    std::string jobId = "123";
    printJob.SetJobId(jobId);
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-PixLab_V1-1620";
    printJob.SetPrinterId(printerId);
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName("testName");
    printerInfo->SetUri("testUri");
    printerInfo->SetPrinterMake("testMaker");
    Json::Value infoJson;
    infoJson["printerName"] = "testPrinterName";
    printJob.SetOption(PrintJsonUtil::WriteString(infoJson));
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_EQ(service->CheckPrintJob(printJob), false);
    auto printJobPtr = std::make_shared<PrintJob>(printJob);
    service->printJobList_[jobId] = printJobPtr;
    EXPECT_EQ(service->CheckPrintJob(printJob), true);
}

HWTEST_F(PrintServiceAbilityTest, CancelPrintJobHandleCallback_SyncMode_ShouldExecuteCallback, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->helper_ = mockHelper;
    EXPECT_CALL(*mockHelper, IsSyncMode()).WillOnce(Return(true));
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_001");
    userData->queuedJobList_["job_001"] = printJob;
    service->CancelPrintJobHandleCallback(userData, "ext_001", "job_001");
    EXPECT_EQ(userData->queuedJobList_.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, CancelPrintJobHandleCallback_AsyncMode_ShouldPostTask, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->helper_ = mockHelper;
    EXPECT_CALL(*mockHelper, IsSyncMode()).WillOnce(Return(false));
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_002");
    userData->queuedJobList_["job_002"] = printJob;
    service->CancelPrintJobHandleCallback(userData, "ext_002", "job_002");
    EXPECT_EQ(userData->queuedJobList_.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, CancelPrintJobHandleCallback_ServiceHandlerNull_ShouldLogWarning, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    service->serviceHandler_ = nullptr;
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_004");
    userData->queuedJobList_["job_004"] = printJob;
    service->CancelPrintJobHandleCallback(userData, "ext_004", "job_004");
    EXPECT_EQ(userData->queuedJobList_.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, SendQueuePrintJob_WhenNotExtension, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = PRINT_EXTENSION_BUNDLE_NAME + ":printerId";
    std::string jobId = "job_001";
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    userData->queuedJobList_[jobId] = printJob;
    service->printUserMap_[userId] = userData;
    bool result = service->SendQueuePrintJob(printerId);
    EXPECT_EQ(result, false);
#endif // CUPS_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, RequestPreview_WhenJobIdNotFound_ShouldReturnInvalidPrintJob, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    PrintJob jobInfo;
    std::string preview;
    int32_t result = service->RequestPreview(jobInfo, preview);
    EXPECT_EQ(result, E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, RequestPreview_WhenPrintJobNull_ShouldReturnInvalidPrintJob, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    userData->printJobList_["job_001"] = nullptr;
    service->printUserMap_[userId] = userData;
    PrintJob jobInfo;
    std::string preview;
    int32_t result = service->RequestPreview(jobInfo, preview);
    EXPECT_EQ(result, E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, RequestPreview_WhenPrinterInfoNull_ShouldReturnInvalidPrintJob, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_001");
    printJob->SetJobState(PRINT_JOB_QUEUED);
    printJob->SetPrinterId("printer_id");
    userData->printJobList_["job_001"] = printJob;
    service->printUserMap_[userId] = userData;
    PrintJob jobInfo;
    std::string preview;
    int32_t result = service->RequestPreview(jobInfo, preview);
    EXPECT_EQ(result, E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, RequestPreview_WhenListenerEmpty_ShouldReturnServerFailure, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    int32_t userId = 100;
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    std::string printId = std::string(DEFAULT_EXTENSION_ID) + ":printer_id";
    printJob->SetJobId("job_001");
    printJob->SetJobState(PRINT_JOB_QUEUED);
    printJob->SetPrinterId(printId);
    userData->printJobList_["job_001"] = printJob;
    service->printUserMap_[userId] = userData;
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printId);
    service->printSystemData_.discoveredPrinterInfoList_[printId] = printerInfo;
    std::string preview;
    int32_t result = service->RequestPreview(*printJob, preview);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

#ifdef REMOTE_SERVICE_ENABLE
HWTEST_F(PrintServiceAbilityTest, StartPrintJobInternal, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = EPRINTID;
    std::string jobId = "job_001";
    uint32_t subState = 1;

    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(printerId);
    printJob->SetJobState(PRINT_JOB_BLOCKED);
    printJob->SetSubState(subState);

    EXPECT_EQ(service->StartPrintJobInternal(printJob), E_PRINT_SERVER_FAILURE);
}
#endif  // REMOTE_SERVICE_ENABLE

}  // namespace Print
}  // namespace OHOS
