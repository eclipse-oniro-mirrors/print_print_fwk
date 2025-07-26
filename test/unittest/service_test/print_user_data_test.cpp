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
#include <vector>
#include <string>
#include <map>
#include "printer_info.h"
#include "iprint_callback.h"
#define private public
#include "print_user_data.h"
#undef private
#include "print_constant.h"
#include "print_log.h"
#include "mock_print_callback_stub.h"
#include "print_json_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintUserDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintUserDataTest::SetUpTestCase(void) {}

void PrintUserDataTest::TearDownTestCase(void) {}

void PrintUserDataTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintUserDataTest_%{public}d", ++testNo);
}

void PrintUserDataTest::TearDown(void) {}

/**
 * @tc.name: PrintServiceStubTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUserDataTest, PrintUserDataTest_0001_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0002_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->UnregisterPrinterCallback(type);
    EXPECT_EQ(userData->registeredListeners_.size(), 0);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0003_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    std::string type2 = "222";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->UnregisterPrinterCallback(type2);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0004_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    sptr<IPrintCallback> listener = nullptr;
    PrinterInfo info;
    int event = 0;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->SendPrinterEvent(type, event, info);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0005_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    std::string type2 = "222";
    sptr<IPrintCallback> listener = nullptr;
    PrinterInfo info;
    int event = 0;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->SendPrinterEvent(type2, event, info);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0006_NeedRename, TestSize.Level1)
{
    std::string type = "111";
    std::string type2 = "222";
    sptr<IPrintCallback> listener = nullptr;
    sptr<IPrintCallback> newListener = nullptr;
    PrinterInfo info;
    int event = 0;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->RegisterPrinterCallback(type2, newListener);
    userData->SendPrinterEvent(type, event, info);
    EXPECT_EQ(userData->registeredListeners_.size(), 2);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0007_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobId = "1";
    PrintJob findPrintJob;
    EXPECT_EQ(userData->QueryPrintJobById(jobId, findPrintJob), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    EXPECT_EQ(userData->QueryPrintJobById(jobId, findPrintJob), E_PRINT_NONE);
    jobId = "2";
    EXPECT_EQ(userData->QueryPrintJobById(jobId, findPrintJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0008_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    std::string newJobId = "2";
    userData->UpdateQueuedJobList(newJobId, printJob, jobOrderId);
    EXPECT_EQ(userData->queuedJobList_[newJobId], nullptr);
    EXPECT_EQ(userData->jobOrderList_[jobOrderId], "");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0009_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(userData->QueryAllActivePrintJob(printJobs), E_PRINT_NONE);
    printJob = nullptr;
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0010_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string type = "111";
    sptr<IPrintCallback> listener = new (std::nothrow) DummyPrintCallbackStub();
    PrinterInfo info;
    int event = 0;
    userData->RegisterPrinterCallback(type, listener);
    userData->SendPrinterEvent(type, event, info);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0011_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    EXPECT_EQ(userData->queuedJobList_[jobId], printJob);
    EXPECT_EQ(userData->jobOrderList_[jobOrderId], jobId);
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    EXPECT_EQ(userData->queuedJobList_[jobId], printJob);
    EXPECT_EQ(userData->jobOrderList_[jobOrderId], jobId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0012_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->jobOrderList_.insert(std::make_pair(jobOrderId, jobId));
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(userData->QueryAllActivePrintJob(printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0013_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    int32_t userId = 101;
    userData->SetUserId(userId);
    EXPECT_EQ(userData->userId_, userId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0014_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-0105";
    userData->SetLastUsedPrinter(printerId);
    std::string printerId2 = "";
    userData->SetLastUsedPrinter(printerId2);
    EXPECT_EQ(userData->lastUsedPrinterId_, printerId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0015_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->GetDefaultPrinter(), "");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0016_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->ParseUserData(), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0017_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string fileData = "";
    EXPECT_EQ(userData->GetFileData(fileData), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0018_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->SetUserDataToFile(), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0019_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->GetLastUsedPrinter(), "");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0020_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-0105";
    userData->SetDefaultPrinter(printerId, 0);
    std::string printerId2 = "";
    auto ret = userData->SetDefaultPrinter(printerId2, 0);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0021_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    userData->ParseUserDataFromJson(jsonObject);
    Json::Value userDataList;
    jsonObject["print_user_data"] = userDataList;
    userData->ParseUserDataFromJson(jsonObject);

    Json::Value jsonObject2;
    Json::Value userDataList2;
    userData->userId_ = 100;
    Json::Value userData2;
    userDataList2["100"] = userData2;
    jsonObject2["print_user_data"] = userDataList2;
    userData->ParseUserDataFromJson(jsonObject2);

    Json::Value jsonObject3;
    Json::Value userDataList3;
    Json::Value userData3;
    userDataList3["100"] = userData3;
    jsonObject3["print_user_data"] = userDataList3;
    userData->ParseUserDataFromJson(jsonObject3);
    EXPECT_EQ(userData->useLastUsedPrinterForDefault_, true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0022_NeedRename, TestSize.Level1)
{
    auto printUserData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    Json::Value userDataList;
    printUserData->userId_ = 100;
    Json::Value userData;
    userData["defaultPrinter"] = 123;
    userDataList["100"] = userData;
    jsonObject["print_user_data"] = userDataList;
    printUserData->ParseUserDataFromJson(jsonObject);

    Json::Value jsonObject2;
    Json::Value userDataList2;
    Json::Value userData2;
    userData2["defaultPrinter"] = "123";
    userDataList2["100"] = userData2;
    jsonObject2["print_user_data"] = userDataList2;
    printUserData->ParseUserDataFromJson(jsonObject2);

    Json::Value jsonObject3;
    Json::Value userDataList3;
    Json::Value userData3;
    userData3["defaultPrinter"] = "123";
    userData3["lastUsedPrinter"] = 123;
    userDataList3["100"] = userData3;
    jsonObject3["print_user_data"] = userDataList3;
    printUserData->ParseUserDataFromJson(jsonObject3);

    Json::Value jsonObject4;
    Json::Value userDataList4;
    Json::Value userData4;
    userData4["defaultPrinter"] = "123";
    userData4["lastUsedPrinter"] = "123";
    userDataList4["100"] = userData4;
    jsonObject4["print_user_data"] = userDataList4;
    printUserData->ParseUserDataFromJson(jsonObject4);
    EXPECT_EQ(printUserData->lastUsedPrinterId_, "123");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0023_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    std::string fileData0 = "test";
    EXPECT_EQ(userData->CheckFileData(fileData0, jsonObject), false);

    Json::Value fileJson;
    fileJson["key"] = "value";
    std::string fileData = PrintJsonUtil::WriteString(fileJson);
    EXPECT_EQ(userData->CheckFileData(fileData, jsonObject), false);

    Json::Value fileJson2;
    fileJson2["version"] = 123;
    std::string fileData2 = PrintJsonUtil::WriteString(fileJson2);
    EXPECT_EQ(userData->CheckFileData(fileData2, jsonObject), false);

    Json::Value fileJson3;
    fileJson3["version"] = "123";
    std::string fileData3 = PrintJsonUtil::WriteString(fileJson3);
    EXPECT_EQ(userData->CheckFileData(fileData3, jsonObject), false);

    Json::Value fileJson4;
    fileJson4["version"] = "v1";
    std::string fileData4 = PrintJsonUtil::WriteString(fileJson4);
    EXPECT_EQ(userData->CheckFileData(fileData4, jsonObject), false);

    Json::Value fileJson5;
    fileJson5["version"] = "v1";
    fileJson5["print_user_data"] = "100";
    std::string fileData5 = PrintJsonUtil::WriteString(fileJson5);
    EXPECT_EQ(userData->CheckFileData(fileData5, jsonObject), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0030_NeedRename, TestSize.Level1)
{
    std::string printerId1 = "com.ohos.spooler:p2p://DIRECT_PixLab_V1-0105";
    std::string printerId2 = "com.ohos.spooler:p2p://DIRECT_PixLab_V1-0106";
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_NE(userData, nullptr);
    userData->SetLastUsedPrinter(printerId1);
    EXPECT_STREQ(userData->GetLastUsedPrinter().c_str(), printerId1.c_str());
    userData->SetDefaultPrinter(printerId2, DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER);
    EXPECT_EQ(userData->CheckIfUseLastUsedPrinterForDefault(), true);
    userData->SetLastUsedPrinter(printerId2);
    userData->SetDefaultPrinter(printerId1, DELETE_DEFAULT_PRINTER);
    userData->DeletePrinter(printerId1);
    userData->DeletePrinter(printerId2);
    userData->SetDefaultPrinter(printerId2, DELETE_LAST_USED_PRINTER);
}

HWTEST_F(PrintUserDataTest, QueryQueuedPrintJobById_WhenNonexistenceJob_ShouldInvalidJobError, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobId = "123";
    EXPECT_NE(userData, nullptr);
    PrintJob getPrintJob;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->QueryQueuedPrintJobById(jobId, getPrintJob), E_PRINT_INVALID_PRINTJOB);
    userData->queuedJobList_["testId"] = printJob;
    EXPECT_EQ(userData->QueryQueuedPrintJobById(jobId, getPrintJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintUserDataTest, QueryQueuedPrintJobById_WhenExistenceJob_ShouldNoneError, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_NE(userData, nullptr);
    std::string jobId = "123";
    PrintJob getPrintJob;
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->queuedJobList_[jobId] = nullptr;
    EXPECT_EQ(userData->QueryQueuedPrintJobById(jobId, getPrintJob), E_PRINT_INVALID_PRINTJOB);
    userData->queuedJobList_[jobId] = printJob;
    EXPECT_EQ(userData->QueryQueuedPrintJobById(jobId, getPrintJob), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0031_NeedRename0, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::vector<std::string> printerIds;
    std::string jobOrderId = "0";
    std::string printerId = "1";
    std::string jobId = "123";
    printerIds.push_back(printerId);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(userData->QueryAllPrintJob(printerIds, printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0031_NeedRename1, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::vector<std::string> printerIds;
    std::string jobOrderId = "0";
    std::string printerId = "1";
    std::string jobId = "123";
    printerIds.push_back(printerId);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->jobOrderList_.insert(std::make_pair(jobOrderId, jobId));
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(userData->QueryAllPrintJob(printerIds, printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0031_NeedRename2, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::vector<std::string> printerIds;
    std::vector<PrintJob> printJobs;
    std::string printerId = "1";
    std::string jobId = "123";
    printerIds.push_back(printerId);
    userData->InitPrintHistoryJobList(printerId);
    userData->printHistoryJobList_[printerId]->insert(std::make_pair(jobId, nullptr));
    EXPECT_EQ(userData->QueryAllPrintJob(printerIds, printJobs), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    printJob->SetJobId(jobId);
    userData->printHistoryJobList_[printerId]->erase(jobId);
    userData->printHistoryJobList_[printerId]->insert(std::make_pair(jobId, printJob));
    EXPECT_EQ(userData->QueryAllPrintJob(printerIds, printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0032_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobId = "0";
    std::string printerId = "1";
    PrintJob printJob;
    userData->InitPrintHistoryJobList(printerId);
    userData->printHistoryJobList_.insert(std::make_pair(printerId, nullptr));
    EXPECT_EQ(userData->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_INVALID_PRINTJOB);
    userData->printHistoryJobList_.erase(printerId);
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList->insert(std::make_pair(jobId, nullptr));
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList)));
    EXPECT_EQ(userData->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_INVALID_PRINTJOB);
    std::shared_ptr<PrintJob> printJob1 = std::make_shared<PrintJob>();
    printJob1->SetOption("{\"test\":\"test\"}");
    printJob1->SetJobId(jobId);
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList1 =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList1->insert(std::pair<std::string, std::shared_ptr<PrintJob>>(jobId, printJob1));
    userData->printHistoryJobList_.erase(printerId);
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList1)));
    EXPECT_EQ(userData->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0033_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->AddPrintJobToHistoryList(printerId, jobId, printjob), false);
    printjob = std::make_shared<PrintJob>();
    printjob->SetOption("test");
    EXPECT_EQ(userData->AddPrintJobToHistoryList(printerId, jobId, printjob), false);
    printjob->SetOption("{\"test\":\"test\"}");
    EXPECT_EQ(userData->AddPrintJobToHistoryList(printerId, jobId, printjob), true);
    auto printerHistroyJobList = userData->printHistoryJobList_.find(printerId);
    for (int32_t i = 2; i <= 501; i++) {
        std::shared_ptr<PrintJob> printjob1 = std::make_shared<PrintJob>();
        (printerHistroyJobList->second)->insert(std::make_pair(std::to_string(i), printjob1));
    }
    EXPECT_EQ(userData->AddPrintJobToHistoryList(printerId, jobId, printjob), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0034_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    bool complete = true;
    int32_t userId = 100;
    userData->SetUserId(userId);
    userData->FlushPrintHistoryJobFile(printerId);
    EXPECT_EQ(complete, true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0036_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    std::string filePath = "";
    std::string printerId = "1";
    EXPECT_EQ(userData->GetJsonObjectFromFile(jsonObject, filePath, printerId), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintHistory_NoJobInPrintHistoryJobList_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printerHistoryJson;
    Json::Value printJobInfoJson;
    std::string printerId = "1";
    printerHistoryJson[printerId] = printJobInfoJson;
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(printerHistoryJson, printerId), false);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0038_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "123";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->DeletePrintJobFromHistoryList(jobId), false);
    userData->InitPrintHistoryJobList(printerId);
    userData->AddPrintJobToHistoryList(printerId, jobId, printjob);
    EXPECT_EQ(userData->DeletePrintJobFromHistoryList(jobId), false);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0039_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    printJob->SetPrinterId(printerId);
    printJob->SetJobId(jobId);
    EXPECT_EQ(userData->DeletePrintJobFromHistoryListByPrinterId(printerId), true);
    userData->AddPrintJobToHistoryList(printerId, jobId, printJob);
    EXPECT_EQ(userData->DeletePrintJobFromHistoryListByPrinterId(jobId), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0040_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    std::vector<std::string> printerIds = {printerId};
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->ContainsHistoryPrintJob(printerIds, jobId), false);
    userData->AddPrintJobToHistoryList(printerId, jobId, printjob);
    EXPECT_EQ(userData->ContainsHistoryPrintJob(printerIds, jobId), false);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0041_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    bool complete = true;
    userData->InitPrintHistoryJobList(printerId);
    EXPECT_EQ(complete, true);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintHistory_NoPrinterInJson_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printerHistoryJson;
    Json::Value printJobInfoJson;
    std::string printerId = "testPrinterId";
    std::string jobId = "testJobId";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList1 =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList1->insert(std::pair<std::string, std::shared_ptr<PrintJob>>(jobId, printjob));
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList1)));
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(printerHistoryJson, printerId), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintHistory_WrongTypeOfJob_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printerHistoryJson;
    std::string printerId = "testPrinterId";
    std::string jobId = "testJobId";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList1 =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList1->insert(std::pair<std::string, std::shared_ptr<PrintJob>>(jobId, printjob));
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList1)));
    printerHistoryJson[printerId] = "testResult";
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(printerHistoryJson, printerId), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintHistory_JobIsNull_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printerHistoryJson;
    Json::Value printJobInfoJson;
    std::string printerId = "testPrinterId";
    std::string jobId = "testJobId";
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList1 =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList1->insert(std::pair<std::string, std::shared_ptr<PrintJob>>(jobId, nullptr));
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList1)));
    printerHistoryJson[printerId] = printJobInfoJson;
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(printerHistoryJson, printerId), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintHistory_JobNotNull_ReturnTrue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printerHistoryJson;
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    printJobInfoJson["printerId"] = "testPrinterId";
    std::string printerId = "testPrinterId";
    std::string jobId = "testJobId";
    std::shared_ptr<PrintJob> printjob = std::make_shared<PrintJob>();
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>> printerHistoryJobList1 =
        std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
    printerHistoryJobList1->insert(std::pair<std::string, std::shared_ptr<PrintJob>>(jobId, printjob));
    userData->printHistoryJobList_.insert(std::pair<std::string,
    std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>(printerId, std::move(printerHistoryJobList1)));
    printerHistoryJson[printerId] = printJobInfoJson;
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(printerHistoryJson, printerId), true);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_NoJobIdInJson_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_WrongTypeOfJobId_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = 123;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_NoPrinterIdInJson_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_WrongTypeOfPrinterId_ReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    printJobInfoJson["printerId"] = 123;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    EXPECT_EQ(userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_NoMemberInJson_GetJobStateReturnDefaultValue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    printJobInfoJson["printerId"] = "testPrinterId";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->GetJobState(), PRINT_JOB_PREPARED);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_WrongValueType_GetJobStateReturnDefaultValue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    printJobInfoJson["printerId"] = "testPrinterId";
    printJobInfoJson["jobState"] = "1";
    printJobInfoJson["subState"] = "1";
    printJobInfoJson["copyNumber"] = "1";
    printJobInfoJson["isSequential"] = "1";
    printJobInfoJson["isLandscape"] = "1";
    printJobInfoJson["colorMode"] = "1";
    printJobInfoJson["duplexMode"] = "1";
    printJobInfoJson["pageRange"] = "1";
    printJobInfoJson["pageSize"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->GetJobState(), PRINT_JOB_PREPARED);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintJob_CorrectValue_GetJobStateCorrectly, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["jobId"] = "testJobId";
    printJobInfoJson["printerId"] = "testPrinterId";
    printJobInfoJson["jobState"] = 4;
    printJobInfoJson["subState"] = 0;
    printJobInfoJson["copyNumber"] = 1;
    printJobInfoJson["isSequential"] = true;
    printJobInfoJson["isLandscape"] = true;
    printJobInfoJson["colorMode"] = 1;
    printJobInfoJson["duplexMode"] = 1;
    Json::Value pageRangeJson;
    pageRangeJson["key"] = "value";
    printJobInfoJson["pageRange"] = pageRangeJson;
    Json::Value pageSizeJson;
    pageSizeJson["key"] = "value";
    printJobInfoJson["pageSize"] = pageSizeJson;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->GetJobState(), 4);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_NoMemberInJson_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_WrongValueType_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = "1";
    printJobInfoJson["hasPreview"] = "1";
    printJobInfoJson["hasOption"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_HasmarginIsFalse_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = false;
    printJobInfoJson["hasPreview"] = false;
    printJobInfoJson["hasOption"] = false;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_NoMarginInJson_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    printJobInfoJson["hasPreview"] = true;
    printJobInfoJson["hasOption"] = true;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_WrongTypeOfMargin_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    printJobInfoJson["margin"] = "1";
    printJobInfoJson["hasPreview"] = true;
    printJobInfoJson["preview"] = "1";
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = 1;
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), false);
}

HWTEST_F(PrintUserDataTest,
    ParseOptionalJsonObjectToPrintJob_NoHasResultInPreview_HasMarginReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["key"] = "value";
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    EXPECT_EQ(printHistoryJob->HasMargin(), true);
}

HWTEST_F(PrintUserDataTest,
    ParseOptionalJsonObjectToPrintJob_WrongTypeOfHasResult_HasResultReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["hasResult_"] = "1";
    previewJson["previewRange_"] = "1";
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    PrintPreviewAttribute previewAttr;
    printHistoryJob->GetPreview(previewAttr);
    EXPECT_EQ(previewAttr.HasResult(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_HasResultIsFalse_HasResultReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["hasResult_"] = false;
    Json::Value previewRangeJson;
    previewJson["previewRange_"] = previewRangeJson;
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    PrintPreviewAttribute previewAttr;
    printHistoryJob->GetPreview(previewAttr);
    EXPECT_EQ(previewAttr.HasResult(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_NoResultInJson_HasResultReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["hasResult_"] = true;
    Json::Value previewRangeJson;
    previewJson["previewRange_"] = previewRangeJson;
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    PrintPreviewAttribute previewAttr;
    printHistoryJob->GetPreview(previewAttr);
    EXPECT_EQ(previewAttr.HasResult(), false);
}

HWTEST_F(PrintUserDataTest, ParseOptionalJsonObjectToPrintJob_WrongTypeOfResult_HasResultReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["hasResult_"] = true;
    previewJson["result_"] = "1";
    Json::Value previewRangeJson;
    previewJson["previewRange_"] = previewRangeJson;
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    PrintPreviewAttribute previewAttr;
    printHistoryJob->GetPreview(previewAttr);
    EXPECT_EQ(previewAttr.HasResult(), false);
}

HWTEST_F(PrintUserDataTest,
    ParseOptionalJsonObjectToPrintJob_CorrectValueOfResult_HasResultReturnTrue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value printJobInfoJson;
    printJobInfoJson["hasmargin"] = true;
    Json::Value marginJson;
    marginJson["key"] = "value";
    printJobInfoJson["margin"] = marginJson;
    printJobInfoJson["hasPreview"] = true;
    Json::Value previewJson;
    previewJson["hasResult_"] = true;
    previewJson["result_"] = 1;
    Json::Value previewRangeJson;
    previewRangeJson["key"] = "value";
    previewJson["previewRange_"] = previewRangeJson;
    printJobInfoJson["preview"] = previewJson;
    printJobInfoJson["hasOption"] = true;
    printJobInfoJson["option"] = "1";
    std::shared_ptr<PrintJob> printHistoryJob = std::make_shared<PrintJob>();
    userData->ParseOptionalJsonObjectToPrintJob(printJobInfoJson, printHistoryJob);
    PrintPreviewAttribute previewAttr;
    printHistoryJob->GetPreview(previewAttr);
    EXPECT_EQ(previewAttr.HasResult(), true);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintPageSize_NullValue_GetEmptyId, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    PrintPageSize pageSize = userData->ParseJsonObjectToPrintPageSize(jsonObject);
    EXPECT_EQ(pageSize.GetId(), "");
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintPageSize_WrongValueType_GetEmptyId, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["id_"] = 1;
    jsonObject["name_"] = 1;
    jsonObject["width_"] = "1";
    jsonObject["height_"] = "1";
    PrintPageSize pageSize = userData->ParseJsonObjectToPrintPageSize(jsonObject);
    EXPECT_EQ(pageSize.GetId(), "");
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintPageSize_WrongType_GetEmptyId, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["id_"] = "1";
    jsonObject["name_"] = "1";
    jsonObject["width_"] = 1;
    jsonObject["height_"] = 1;
    PrintPageSize pageSize = userData->ParseJsonObjectToPrintPageSize(jsonObject);
    EXPECT_EQ(pageSize.GetId(), "1");
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_NullValue_HasStartPageReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_WrongValueType_HasStartPageReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasStartPage_"] = "1";
    jsonObject["hasEndPage_"] = "1";
    jsonObject["pages"] = "1";
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_HasStartPageIsFalse_HasStartPageReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasStartPage_"] = false;
    jsonObject["hasEndPage_"] = false;
    Json::Value pagesJsonObject;
    pagesJsonObject.append("1");
    pagesJsonObject.append(1);
    jsonObject["pages"] = pagesJsonObject;
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_NoStartPage_HasStartPageReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasStartPage_"] = true;
    jsonObject["hasEndPage_"] = true;
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_WrongTyprOfStartPage_HasStartPageReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasStartPage_"] = true;
    jsonObject["startPage"] = "1";
    jsonObject["hasEndPage_"] = true;
    jsonObject["endPage"] = "2";
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToPrintRange_CorrectValue_HasStartPageReturnTrue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasStartPage_"] = true;
    jsonObject["startPage"] = 1;
    jsonObject["hasEndPage_"] = true;
    jsonObject["endPage"] = 2;
    PrintRange printRange = userData->ParseJsonObjectToPrintRange(jsonObject);
    EXPECT_EQ(printRange.HasStartPage(), true);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_NullValue_HasTopReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_WrongValueType_HasTopReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasTop_"] = "1";
    jsonObject["hasLeft_"] = "1";
    jsonObject["hasRight_"] = "1";
    jsonObject["hasBottom_"] = "1";
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_HasTopIsFalse_HasTopReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasTop_"] = false;
    jsonObject["hasLeft_"] = false;
    jsonObject["hasRight_"] = false;
    jsonObject["hasBottom_"] = false;
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_NoTop_HasTopReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasTop_"] = true;
    jsonObject["hasLeft_"] = true;
    jsonObject["hasRight_"] = true;
    jsonObject["hasBottom_"] = true;
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_WrongTypeOfTop_HasTopReturnFalse, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasTop_"] = true;
    jsonObject["top_"] = "1";
    jsonObject["hasLeft_"] = true;
    jsonObject["left_"] = "1";
    jsonObject["hasRight_"] = true;
    jsonObject["right_"] = "1";
    jsonObject["hasBottom_"] = true;
    jsonObject["bottom_"] = "1";
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), false);
}

HWTEST_F(PrintUserDataTest, ParseJsonObjectToMargin_CorrectValue_HasTopReturnTrue, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    jsonObject["hasTop_"] = true;
    jsonObject["top_"] = 1;
    jsonObject["hasLeft_"] = true;
    jsonObject["left_"] = 1;
    jsonObject["hasRight_"] = true;
    jsonObject["right_"] = 1;
    jsonObject["hasBottom_"] = true;
    jsonObject["bottom_"] = 1;
    PrintMargin margin = userData->ParseJsonObjectToMargin(jsonObject);
    EXPECT_EQ(margin.HasTop(), true);
}
}
}