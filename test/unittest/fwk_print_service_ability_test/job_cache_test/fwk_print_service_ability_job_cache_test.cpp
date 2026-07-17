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
 * @tc.name: FlushCacheFileToUserData_WhenEmptyFdlist_ShouldTrue
 * @tc.desc: Verify the FlushCacheFileToUserData failed case.
 * @tc.type: FUNC FlushCacheFileToUserData
 * @tc.require: BedFdlist printJob
 */
HWTEST_F(PrintServiceAbilityTest, FlushCacheFileToUserData_WhenBedFdlist_ShouldFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = printJob;
    std::vector<uint32_t> fdList = {999};  // Bed Fdlist
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
    auto service = PrintServiceAbilityTest::CreateService();
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
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "123";
    int32_t userId = 100;
    service->userJobMap_[jobId] = userId;
    service->currentUserId_ = userId;
    std::vector<uint32_t> getFdList;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();  // EmptyFdlist
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
    auto service = PrintServiceAbilityTest::CreateService();
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
    std::vector<uint32_t> fdList = {999};  // Bed Fdlist
    printJob->SetFdList(fdList);
    EXPECT_EQ(service->OpenCacheFileFd(jobId, getFdList), false);
}

HWTEST_F(PrintServiceAbilityTest, QueryHistoryPrintJobById, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    service->helper_ = nullptr;
    int32_t userId = 0;
    PrintJob printJob;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = nullptr;
    EXPECT_EQ(service->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_INVALID_USERID);
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintServiceAbilityTest, DeletePrintJobFromHistoryList, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "1";
    int32_t userId = 100;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = nullptr;
    EXPECT_EQ(service->DeletePrintJobFromHistoryList(jobId), false);
    service->printUserMap_[userId] = userData;
    EXPECT_EQ(service->DeletePrintJobFromHistoryList(jobId), false);
}

HWTEST_F(PrintServiceAbilityTest, AddPrintJobToHistoryList, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto printJob = std::make_shared<PrintJob>();
    EXPECT_EQ(service->AddPrintJobToHistoryList(printJob), false);
}

HWTEST_F(PrintServiceAbilityTest, DeleteCacheFileFromUserData_ShouldReturn, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    bool result = service->DeleteCacheFileFromUserData("");
    EXPECT_EQ(result, false);
}

}  // namespace Print
}  // namespace OHOS
