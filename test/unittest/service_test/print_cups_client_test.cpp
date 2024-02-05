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
#define private public
#include "print_cups_client.h"
#undef private
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"printer1\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\","
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"]}";

class PrintCupsClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string GetDefaultJobId();
};

void PrintCupsClientTest::SetUpTestCase(void) {}

void PrintCupsClientTest::TearDownTestCase(void) {}

void PrintCupsClientTest::SetUp(void) {}

void PrintCupsClientTest::TearDown(void) {}

std::string PrintCupsClientTest::GetDefaultJobId()
{
    return std::to_string(0);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0001, TestSize.Level1)
{
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(testJob);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0002, TestSize.Level1)
{
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(testJob);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0003, TestSize.Level1)
{
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(testJob);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0004, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->CancelCupsJob(GetDefaultJobId());
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0005, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter("printid-1234");
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0006, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->StartCupsdService();
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0007, TestSize.Level1)
{
    std::string path = "";
    mode_t mode = 16;
    DelayedSingleton<PrintCupsClient>::GetInstance()->ChangeFilterPermission(path, mode);
    path = "/data/cupsFiles";
    DelayedSingleton<PrintCupsClient>::GetInstance()->ChangeFilterPermission(path, mode);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0008, TestSize.Level1)
{
    const char *srcDir = "";
    const char *destDir = "";
    DelayedSingleton<PrintCupsClient>::GetInstance()->CopyDirectory(srcDir, destDir);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0009, TestSize.Level1)
{
    const char *srcDir = "/data/cupFiles/1";
    const char *destDir = "/data/cupFiles/2";
    DelayedSingleton<PrintCupsClient>::GetInstance()->CopyDirectory(srcDir, destDir);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0010, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0011, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->StopCupsdService();
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0012, TestSize.Level1)
{
    const char *makeModel = "ppd-make-and-model";
    std::vector<std::string> ppds;
    DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPPDInformation(makeModel, ppds);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0013, TestSize.Level1)
{
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    std::string printerName = "DIRECT-HUAWEI_PixLab_V1-0105";
    std::string printerMake = "*PPD-Adobe: "4.3"";
    int32_t ret =
        DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0014, TestSize.Level1)
{
    std::string printerName = "DIRECT-HUAWEI_PixLab_V1-0105";
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter(printerName);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0015, TestSize.Level1)
{
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    PrinterCapability printerCaps;
    int32_t ret =
        DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerCaps);
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0016, TestSize.Level1)
{
    PrintJob jobInfo;
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(jobInfo);
    jobInfo.SetJobId(1);
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(jobInfo);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0017, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->StartNextJob();
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    printCupsClient.jobQueue_.push_back(jobParams);
    DelayedSingleton<PrintCupsClient>::GetInstance()->StartNextJob();
    printCupsClient.currentJob_ = jobParams;
    DelayedSingleton<PrintCupsClient>::GetInstance()->StartNextJob();
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0018, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->JobCompleteCallback();
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    printCupsClient.currentJob_ = jobParams;
    DelayedSingleton<PrintCupsClient>::GetInstance()->StartNextJob();
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0019, TestSize.Level1)
{
    JobParameters *jobParams = nullptr;
    int num_options = 0;
    cups_option_t *options = nullptr;
    int ret =
        DelayedSingleton<PrintCupsClient>::GetInstance()->FillBorderlessOptions(jobParams, num_options, &options);
    EXPEXT_EQ(ret, 0)
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    PrintPageSize pageSize;
    pageSize.SetId = "A4";
    pageSize.SetName = "A4";
    pageSize.SetWidth = 202;
    pageSize.SetHeight = 297;
    jobInfo.SetPageSize(pageSize);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    ret = DelayedSingleton<PrintCupsClient>::GetInstance()->FillBorderlessOptions(jobParams, num_options, &options);
    EXPEXT_EQ(ret, 1);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0020, TestSize.Level1)
{
    JobParameters *jobParams = nullptr;
    int num_options = 0;
    cups_option_t *options = nullptr;
    int ret = DelayedSingleton<PrintCupsClient>::GetInstance()->FillJobOptions(jobParams, num_options, &options);
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    ret = DelayedSingleton<PrintCupsClient>::GetInstance()->FillJobOptions(jobParams, num_options, &options);
    EXPEXT_EQ(ret, 3);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0021, TestSize.Level1)
{
    JobParameters *jobParams = nullptr;
    bool ret = DelayedSingleton<PrintCupsClient>::GetInstance()->CheckPrinterMakeModel(jobParams);
    EXPEXT_EQ(ret, false);
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    ret = DelayedSingleton<PrintCupsClient>::GetInstance()->CheckPrinterMakeModel(jobParams);
    EXPEXT_EQ(ret, false);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    int num_options = 0;
    uint32_t jobId = 1;
    cups_option_t *options = nullptr;
    http_t *http = nullptr;
    bool ret =
        DelayedSingleton<PrintCupsClient>::GetInstance()->VerifyPrintJob(jobParams, num_options, jobId, options, http);
    EXPEXT_EQ(ret, false);
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    ret =
        DelayedSingleton<PrintCupsClient>::GetInstance()->VerifyPrintJob(jobParams, num_options, jobId, options, http);
    EXPEXT_EQ(ret, false);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    CallbackFunc callback = [this]() { JobCompleteCallback(); };
    DelayedSingleton<PrintCupsClient>::GetInstance()->StartCupsJob(jobParams, callback);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0024, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    CallbackFunc callback = [this]() { JobCompleteCallback(); };
    DelayedSingleton<PrintCupsClient>::GetInstance()->MonitorJobState(jobParams, callback);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0025, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    JobStatus *jobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = true;
    DelayedSingleton<PrintCupsClient>::GetInstance()->JobStatusCallback(jobParams, jobStatus, isOffline);
    isOffline = false;
    DelayedSingleton<PrintCupsClient>::GetInstance()->JobStatusCallback(jobParams, jobStatus, isOffline);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0026, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    JobStatus *jobStatus = nullptr;
    DelayedSingleton<PrintCupsClient>::GetInstance()->ReportBlockedReason(jobParams, jobStatus);
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    *jobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    DelayedSingleton<PrintCupsClient>::GetInstance()->ReportBlockedReason(jobParams, jobStatus);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0027, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char* printerUri = "ipp://192.168.186.1:631/ipp/print";
    bool ret = DelayedSingleton<PrintCupsClient>::GetInstance()->CheckPrinterOnline(printerUri);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0028, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string serviceJobId = 1;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    printCupsClient.jobQueue_.push_back(jobParams);
    DelayedSingleton<PrintCupsClient>::GetInstance()->CancelCupsJob(serviceJobId);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0029, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    DelayedSingleton<PrintCupsClient>::GetInstance()->DumpJobParameters(jobParams);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0030, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetJobId(1);
    DelayedSingleton<PrintCupsClient>::GetInstance()->BuildJobParameters(jobInfo);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0031, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    DelayedSingleton<PrintCupsClient>::GetInstance()->BuildJobParameters(testJob);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0032, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetMedieSize(testJob);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0033, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t duplexCode = 0;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetDulpexString(duplexCode);
    duplexCode = 1;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetDulpexString(duplexCode);
    duplexCode = 2;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetDulpexString(duplexCode);
    duplexCode = 3;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetDulpexString(duplexCode);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0034, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t colorCode = 0;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetColorString(colorCode);
    colorCode = 1;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetColorString(colorCode);
    colorCode = 2;
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetColorString(colorCode);
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0035, TestSize.Level1)
{
    DelayedSingleton<PrintCupsClient>::GetInstance()->IsCupsServerAlive();
}

HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0036, TestSize.Level1)
{
    float num = 1000;
    float ret = DelayedSingleton<PrintCupsClient>::GetInstance()->ConvertInchTo100MM(num);
    EXPECT_EQ(ret, 2540);
}

} // namespace Print
} // namespace OHOS