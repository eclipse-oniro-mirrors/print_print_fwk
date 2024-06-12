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
HWTEST_F(PrintUserDataTest, PrintUserDataTest_0001, TestSize.Level1)
{
    std::string type = "111";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0002, TestSize.Level1)
{
    std::string type = "111";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->UnregisterPrinterCallback(type);
    EXPECT_EQ(userData->registeredListeners_.size(), 0);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0003, TestSize.Level1)
{
    std::string type = "111";
    std::string type2 = "222";
    sptr<IPrintCallback> listener = nullptr;
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->RegisterPrinterCallback(type, listener);
    userData->UnregisterPrinterCallback(type2);
    EXPECT_EQ(userData->registeredListeners_.size(), 1);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0004, TestSize.Level1)
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

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0005, TestSize.Level1)
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

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0006, TestSize.Level1)
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
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0007, TestSize.Level1)
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

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0008, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    std::string newJobId = "2";
    userData->UpdateQueuedJobList(newJobId, printJob, jobOrderId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0009, TestSize.Level1)
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

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0010, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string type = "111";
    sptr<IPrintCallback> listener = new (std::nothrow) DummyPrintCallbackStub();
    PrinterInfo info;
    int event = 0;
    userData->RegisterPrinterCallback(type, listener);
    userData->SendPrinterEvent(type, event, info);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0011, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    userData->AddToPrintJobList(jobId, printJob);
    userData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0012, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string jobOrderId = "0";
    std::string jobId = "1";
    std::shared_ptr<PrintJob> printJob = std::make_shared<PrintJob>();
    userData->jobOrderList_.insert(std::make_pair(jobOrderId, jobId));
    std::vector<PrintJob> printJobs;
    userData->QueryAllPrintJob(printJobs);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0013, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    int32_t userId = 101;
    userData->SetUserId(userId);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0014, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-HW_PixLab_V1-0105";
    userData->SetLastUsedPrinter(printerId);
    std::string printerId2 = "";
    userData->SetLastUsedPrinter(printerId2);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0015, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->GetDefaultPrinter(), "");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0016, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->ParseUserData();
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0017, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string fileData = "";
    userData->GetFileData(fileData);
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0018, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    userData->SetUserDataToFile();
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0019, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    EXPECT_EQ(userData->GetLastUsedPrinter(), "");
}

HWTEST_F(PrintUserDataTest, PrintUserDataTest_0020, TestSize.Level1)
{
    auto userData = std::make_shared<OHOS::Print::PrintUserData>();
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-H_PixLab_V1-0105";
    userData->SetDefaultPrinter(printerId);
    std::string printerId2 = "";
    userData->SetDefaultPrinter(printerId2);
}

}
}