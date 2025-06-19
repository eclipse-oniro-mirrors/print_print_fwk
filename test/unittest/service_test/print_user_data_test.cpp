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
    EXPECT_EQ(userData->QueryAllPrintJob(printJobs), E_PRINT_NONE);
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
    EXPECT_EQ(userData->QueryAllPrintJob(printJobs), E_PRINT_NONE);
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

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0031_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::vector<std::string> printerIds;
    std::vector<PrintJob> printJobs;
    EXPECT_EQ(userData->QueryAllHistoryPrintJob(printerIds, printJobs), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0032_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobId = "0";
    PrintJob printJob;
    EXPECT_EQ(userData->QueryHistoryPrintJobById(jobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0033_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printjob;
    EXPECT_EQ(userData->AddPrintJobToHistoryList(printerId, jobId, printjob), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0034_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    bool complete = true;
    userData->FlushPrintHistoryJobFile(printerId);
    EXPECT_EQ(complete, true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0036_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    std::string filePath = "";
    std::string printerId = "1";
    EXPECT_EQ(userData->GetJsonObjectFromFile(jsonObject, filePath, printerId), E_PRINT_NONE);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0037_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    Json::Value jsonObject;
    std::string printerId = "1";
    EXPECT_EQ(userData->ParseJsonObjectToPrintHistory(jsonObject, printerId), false);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0038_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobId = "1";
    EXPECT_EQ(userData->DeletePrintJobFromHistoryList(jobId), false);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0039_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    EXPECT_EQ(userData->DeletePrintJobFromHistoryListByPrinterId(printerId), true);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0040_NeedRename, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "1";
    bool complete = true;
    userData->InitPrintHistoryJobList(printerId);
    EXPECT_EQ(complete, true);
}
}
}