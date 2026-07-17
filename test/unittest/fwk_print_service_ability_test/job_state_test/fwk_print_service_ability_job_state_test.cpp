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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0018_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    service->notifyAdapterJobChanged(jobId, state, subState);
    auto attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
    std::shared_ptr<PrintAttributes> attr = std::make_shared<PrintAttributes>();
    service->printAttributesList_[jobId] = attr;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_NE(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0019_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string jobId = "1";
    uint32_t state = PRINT_JOB_PREPARED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;

    state = PRINT_JOB_BLOCKED;
    service->notifyAdapterJobChanged(jobId, state, subState);
    auto attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintJob jobInfo;
    service->CheckJobQueueBlocked(jobInfo);
    EXPECT_EQ(service->isJobQueueBlocked_, false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0049_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    uint32_t state = PRINTER_UNKNOWN + 1;
    uint32_t subState = 0;
    uint32_t userId = 100;
    EXPECT_EQ(service->checkJobState(state, subState), true);
    service->UpdatePrintJobState(jobId, state, subState);
    state = PRINT_JOB_BLOCKED;
    subState = PRINT_JOB_BLOCKED_OFFLINE - 1;
    EXPECT_EQ(service->checkJobState(state, subState), false);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
    subState = PRINT_JOB_BLOCKED_UNKNOWN + 1;
    EXPECT_EQ(service->checkJobState(state, subState), true);
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->userJobMap_.insert(std::make_pair(jobId, userId));
    service->printUserMap_.insert(std::make_pair(userId, userData));
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PRINTJOB);
    state = PRINT_JOB_COMPLETED;
    subState = PRINT_JOB_COMPLETED_FILE_CORRUPT + 1;
    EXPECT_EQ(service->checkJobState(state, subState), false);
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0050_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), false);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0081_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    uint32_t state = PRINT_JOB_UNKNOWN + 1;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    service->checkJobState(state, subState);
    std::string jobId = "123";
    auto ret = service->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobStateOnlyForSystemApp_EnterpriseManagePrintPermission, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    service->helper_ = mockHelper;
    
    std::string jobId = "123";
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly([](const std::string &permission) {
            if (permission == PERMISSION_NAME_ENTERPRISE_MANAGE_PRINT) {
                return true;
            }
            return false;
        });
    
    auto ret = service->UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0099_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0102_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
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
    std::shared_ptr<PrintAttributes> printAttributes = std::make_shared<PrintAttributes>();
    service->printAttributesList_[jobId] = printAttributes;
    service->notifyAdapterJobChanged(jobId, state, subState);
    attrIt = service->printAttributesList_.find(jobId);
    EXPECT_EQ(attrIt, service->printAttributesList_.end());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0120_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
    EXPECT_NE(service, nullptr);
    std::map<std::string, std::shared_ptr<PrintJob>> jobList;
    auto job = std::make_shared<PrintJob>();
    EXPECT_NE(job, nullptr);
    job->SetJobState(PRINT_JOB_RUNNING);
    jobList.insert(std::make_pair("test", job));
    EXPECT_EQ(service->DetermineUserJobStatus(jobList), PRINT_JOB_RUNNING);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0125_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
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

/**
 * @tc.name: QueryQueuedPrintJobById_WhenInvalidJobId_ShouldF
 * @tc.desc: Verify the QueryQueuedPrintJobById failed case.
 * @tc.type: FUNC QueryQueuedPrintJobById
 * @tc.require: BedFdlist printJob
 */
HWTEST_F(PrintServiceAbilityTest, QueryQueuedPrintJobById_WhenBedFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
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

HWTEST_F(PrintServiceAbilityTest, BlockUserPrintJobs_UserNotFound_ShouldReturn, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    int32_t userId = -1;
    service->BlockUserPrintJobs(userId);
    EXPECT_EQ(service->printUserMap_.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, BlockUserPrintJobs_UserDataNull_ShouldReturn, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    int32_t userId = 100;
    service->printUserMap_[userId] = nullptr;
    service->BlockUserPrintJobs(userId);
    EXPECT_EQ(service->printUserMap_.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, BlockUserPrintJobs_EmptyJobList_ShouldReturn, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto userData = std::make_shared<PrintUserData>();
    int32_t userId = 100;
    service->printUserMap_[userId] = userData;
    service->BlockUserPrintJobs(userId);
    EXPECT_EQ(userData->queuedJobList_.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, BlockUserPrintJobs_SingleJob_ShouldBlock, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto userData = std::make_shared<PrintUserData>();
    int32_t userId = 100;
    service->printUserMap_[userId] = userData;
    auto printJob = std::make_shared<PrintJob>();
    std::string jobId = "job_001";
    printJob->SetJobId(jobId);
    userData->queuedJobList_[jobId] = printJob;
    service->AddToPrintJobList(jobId, printJob);
    service->BlockUserPrintJobs(userId);
    EXPECT_EQ(userData->queuedJobList_.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, BlockPrintJob_UserDataNull_ShouldReturnInvalidUserId, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "job_002";
    int32_t ret = service->BlockPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_INVALID_USERID);
}

HWTEST_F(PrintServiceAbilityTest, BlockPrintJob_JobNotFound_ShouldReturnInvalidPrintJob, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    int32_t userId = 100;
    service->printUserMap_[userId] = userData;
    std::string jobId = "job_003";
    service->AddToPrintJobList(jobId, printJob);
    int32_t ret = service->BlockPrintJob(jobId);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, SendQueuePrintJob_WhenJobStateNotPrepared_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "test_printer_id";
    std::string jobId = "job_001";
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    int32_t userId = 100;
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_BLOCKED);
    userData->queuedJobList_[jobId] = printJob;
    service->printUserMap_[userId] = userData;
    bool result = service->SendQueuePrintJob(printerId);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, SendQueuePrintJob_WhenJobStatePrepared_ShouldReturnTrue, TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "test_printer_id";
    std::string jobId = "job_001";
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    userData->queuedJobList_[jobId] = printJob;
    service->printUserMap_[userId] = userData;
    service->helper_ = nullptr;
    service->currentUserId_ = userId;
    service->serviceHandler_ = nullptr;
    EXPECT_EQ(service->SendQueuePrintJob(printerId), true);
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*helper, QueryAccounts(_)).WillRepeatedly(
        [](std::vector<int32_t>& accountList) {
            accountList = {0};
            return true;
        }
    );
    EXPECT_CALL(*helper, IsSyncMode()).WillOnce(Return(true));
    service->helper_ = helper;
    EXPECT_EQ(service->SendQueuePrintJob(printerId), true);
    OHOS::uid_ = 0;
}

HWTEST_F(PrintServiceAbilityTest, RequestPreview_WhenJobStateInvalid_ShouldReturnInvalidPrintJob, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintServiceMockPermission::MockPermission();
    int32_t userId = service->GetCurrentUserId();
    auto userData = std::make_shared<PrintUserData>();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_001");
    printJob->SetJobState(PRINT_JOB_PREPARED);
    userData->printJobList_["job_001"] = printJob;
    service->printUserMap_[userId] = userData;
    PrintJob jobInfo;
    std::string preview;
    int32_t result = service->RequestPreview(jobInfo, preview);
    EXPECT_EQ(result, E_PRINT_INVALID_PRINTJOB);
}
#ifdef HAVE_PRINT_FAILURE_AI_NOTIFIER

HWTEST_F(PrintServiceAbilityTest, HandleJobBlockedState_PrinterInAddedList_NotifySuccess, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "123";
    std::string jobId = "job_001";
    uint32_t subState = 1;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("Printer123");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));

    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(printerId);
    printJob->SetJobState(PRINT_JOB_BLOCKED);
    printJob->SetSubState(subState);

    PrintFailureAiNotifier::GetInstance().jobStateMap_.clear();
    service->HandleJobBlockedState(printJob, subState);

    auto &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_EQ(notifier.jobStateMap_.size(), 1);
    EXPECT_NE(notifier.jobStateMap_.find(jobId), notifier.jobStateMap_.end());
    EXPECT_NE(notifier.jobStateMap_[jobId].find(subState), notifier.jobStateMap_[jobId].end());
}

HWTEST_F(PrintServiceAbilityTest, HandleJobBlockedState_PrinterNotInAddedList_NoNotify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = "123";
    std::string jobId = "job_001";
    uint32_t subState = 1;

    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(printerId);
    printJob->SetJobState(PRINT_JOB_BLOCKED);
    printJob->SetSubState(subState);

    PrintFailureAiNotifier::GetInstance().jobStateMap_.clear();
    service->HandleJobBlockedState(printJob, subState);

    auto &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_EQ(notifier.jobStateMap_.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, HandleJobBlockedState_Eprint_SkipNotify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    std::string printerId = EPRINTID;
    std::string jobId = "job_001";
    uint32_t subState = 1;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("Eprint");
    service->printSystemData_.addedPrinterMap_.Insert(printerId, std::make_shared<PrinterInfo>(printerInfo));

    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(printerId);
    printJob->SetJobState(PRINT_JOB_BLOCKED);
    printJob->SetSubState(subState);

    PrintFailureAiNotifier::GetInstance().jobStateMap_.clear();
    service->HandleJobBlockedState(printJob, subState);

    auto &notifier = PrintFailureAiNotifier::GetInstance();
    EXPECT_EQ(notifier.jobStateMap_.size(), 0);
}

#endif  // HAVE_PRINT_FAILURE_AI_NOTIFIER

}  // namespace Print
}  // namespace OHOS
