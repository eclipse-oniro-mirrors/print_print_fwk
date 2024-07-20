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
using json = nlohmann::json;

namespace OHOS {
namespace Print {
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"printer1\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\",\"borderless\":true,"
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"]}";

static const std::string PRINTER_STATE_NONE = "none";
static const std::string PRINTER_STATE_MEDIA_EMPTY = "media-empty";
static const std::string PRINTER_STATE_MEDIA_JAM = "media-jam";
static const std::string PRINTER_STATE_PAUSED = "paused";
static const std::string PRINTER_STATE_TONER_LOW = "toner-low";
static const std::string PRINTER_STATE_TONER_EMPTY = "toner-empty";
static const std::string PRINTER_STATE_DOOR_EMPTY = "door-open";
static const std::string PRINTER_STATE_MEDIA_NEEDED = "media-needed";
static const std::string PRINTER_STATE_MARKER_LOW = "marker-supply-low";
static const std::string PRINTER_STATE_MARKER_EMPTY = "marker-supply-empty";
static const std::string PRINTER_STATE_INK_EMPTY = "marker-ink-almost-empty";
static const std::string PRINTER_STATE_COVER_OPEN = "cover-open";
static const std::string PRINTER_STATE_OFFLINE = "offline";

class PrintCupsClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string GetDefaultJobId();
};

void PrintCupsClientTest::SetUpTestCase(void)
{}

void PrintCupsClientTest::TearDownTestCase(void)
{}

void PrintCupsClientTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCupsClientTest_%{public}d", ++testNo);
}

void PrintCupsClientTest::TearDown(void)
{}

std::string PrintCupsClientTest::GetDefaultJobId()
{
    return std::to_string(0);
}

/**
 * @tc.name: PrintCupsClientTest_0001
 * @tc.desc: StartCupsdService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.StartCupsdService();
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0002
 * @tc.desc: ChangeFilterPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string path = "";
    mode_t mode = 16;
    printCupsClient.ChangeFilterPermission(path, mode);
}

/**
 * @tc.name: PrintCupsClientTest_0003
 * @tc.desc: SymlinkDirectory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *srcDir = "";
    const char *destDir = "";
    printCupsClient.SymlinkDirectory(srcDir, destDir);
}

/**
 * @tc.name: PrintCupsClientTest_0004
 * @tc.desc: CopyDirectory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *srcDir = "";
    const char *destDir = "";
    printCupsClient.CopyDirectory(srcDir, destDir);
}

/**
 * @tc.name: PrintCupsClientTest_0005
 * @tc.desc: InitCupsResources
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.InitCupsResources();
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0006
 * @tc.desc: StopCupsdService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.StartCupsdService();
    EXPECT_EQ(ret, E_PRINT_NONE);
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsClientTest_0007
 * @tc.desc: StopCupsdService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsClientTest_0008
 * @tc.desc: SetDefaultPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "DIRECT-PixLab_V1-0105";
    printCupsClient.SetDefaultPrinter(printerName);
    printCupsClient.StartCupsdService();
    printCupsClient.SetDefaultPrinter(printerName);
}

/**
 * @tc.name: PrintCupsClientTest_0009
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "DIRECT-PixLab_V1-0105";
    std::string printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-0105";
    PrinterInfo info;
    info.SetPrinterName(printerName);
    printCupsClient.QueryPrinterInfoByPrinterId(printerId, info);
}

/**
 * @tc.name: PrintCupsClientTest_0012
 * @tc.desc: QueryPrinterCapabilityByUri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerUri = "ipp://192.168.186.1:631/ipp/print";
    std::string printerId = "1";
    PrinterCapability printerCaps;
    int32_t ret = printCupsClient.QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintCupsClientTest_0013
 * @tc.desc: AddCupsPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0013, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    PrintJob testJob;
    printCupsClient->AddCupsPrintJob(testJob);
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

/**
 * @tc.name: PrintCupsClientTest_0014
 * @tc.desc: AddCupsPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0014, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    printCupsClient->AddCupsPrintJob(testJob);
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

/**
 * @tc.name: PrintCupsClientTest_0015
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0015, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

/**
 * @tc.name: PrintCupsClientTest_0016
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0016, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient->BuildJobParameters(testJob);
    printCupsClient->jobQueue_.push_back(jobParams);
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0018
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0018, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    JobParameters *jobParams = nullptr;
    printCupsClient->jobQueue_.push_back(jobParams);
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0019
 * @tc.desc: JobCompleteCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0019, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    printCupsClient->JobCompleteCallback();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

/**
 * @tc.name: PrintCupsClientTest_0021
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0021, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    jobParams->borderless = 1;
    jobParams->mediaSize = "";
    jobParams->mediaType = "";
    int numOptions = 0;
    cups_option_t *options = nullptr;
    printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(numOptions, 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0022
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    jobParams->mediaSize = "testMediaSize";
    jobParams->mediaType = "testMediaType";
    int numOptions = 0;
    cups_option_t *options = nullptr;
    printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(numOptions, 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0023
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    jobParams->borderless = 1;
    jobParams->mediaType = CUPS_MEDIA_TYPE_PHOTO_GLOSSY;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(numOptions, 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0024
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0024, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    jobParams->borderless = 1;
    jobParams->mediaType = CUPS_MEDIA_TYPE_PHOTO_GLOSSY;
    jobParams->mediaSize = CUPS_MEDIA_4X6;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(numOptions, 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0025
 * @tc.desc: FillJobOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0025, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    jobParams->printerId = "1";
    jobParams->numCopies = 2;
    jobParams->duplex = "";
    jobParams->printQuality = "";
    jobParams->color = "";
    int ret = printCupsClient.FillJobOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 6);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0026
 * @tc.desc: FillJobOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0026, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo);
    jobParams->printerId = "1";
    jobParams->numCopies = 0;
    jobParams->duplex = "test_duplex";
    jobParams->printQuality = "test_printQuality";
    jobParams->color = "test_color";
    int ret = printCupsClient.FillJobOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 6);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0027
 * @tc.desc: QueryAddedPrinterList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0027, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<std::string> printerNameList;
    printerNameList.push_back("testPrinterName");
    printCupsClient.StopCupsdService();
    printCupsClient.QueryAddedPrinterList(printerNameList);
}

/**
 * @tc.name: PrintCupsClientTest_0028
 * @tc.desc: QueryAddedPrinterList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0028, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<std::string> printerNameList;
    printerNameList.push_back("testPrinterName");
    printCupsClient.StartCupsdService();
    printCupsClient.QueryAddedPrinterList(printerNameList);
}

/**
 * @tc.name: PrintCupsClientTest_0030
 * @tc.desc: GetPPDFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0030, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    printCupsClient.StopCupsdService();
    printCupsClient.GetPPDFile(printerName);
}

/**
 * @tc.name: PrintCupsClientTest_0031
 * @tc.desc: GetPPDFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0031, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    printCupsClient.StartCupsdService();
    printCupsClient.GetPPDFile(printerName);
}

/**
 * @tc.name: PrintCupsClientTest_0032
 * @tc.desc: QueryPrinterAttrList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0032, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    printCupsClient.QueryPrinterAttrList(printerName, keyList, valueList);
}

/**
 * @tc.name: PrintCupsClientTest_0033
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0033, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerId = "testPrinterId";
    PrinterInfo info;
    info.SetPrinterName("testPrinterName");
    printCupsClient.QueryPrinterInfoByPrinterId(printerId, info);
}

/**
 * @tc.name: PrintCupsClientTest_0034
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0034, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    bool ret = printCupsClient.CheckPrinterMakeModel(jobParams);
    EXPECT_EQ(ret, false);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0036
 * @tc.desc: VerifyPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0036, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    int num = 0;
    uint32_t jobId = 1;
    cups_option_t *options = nullptr;
    http_t *http = nullptr;
    bool ret = printCupsClient.VerifyPrintJob(jobParams, num, jobId, options, http);
    EXPECT_EQ(ret, false);
    delete jobParams;
    delete options;
    delete http;
}

/**
 * @tc.name: PrintCupsClientTest_0039
 * @tc.desc: UpdatePrintJobStateInJobParams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0039, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_BLOCKED_UNKNOWN;
    printCupsClient.UpdatePrintJobStateInJobParams(jobParams, state, subState);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0042
 * @tc.desc: UpdateJobStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0042, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobStatus *prevousJobStatus = nullptr;
    JobStatus *jobStatus = nullptr;
    printCupsClient.UpdateJobStatus(prevousJobStatus, jobStatus);
    JobStatus *prevousJobStatus2 = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    printCupsClient.UpdateJobStatus(prevousJobStatus2, jobStatus);
    delete prevousJobStatus;
    delete jobStatus;
    delete prevousJobStatus2;
}

/**
 * @tc.name: PrintCupsClientTest_0043
 * @tc.desc: UpdateJobStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0043, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobStatus *prevousJobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    printCupsClient.UpdateJobStatus(prevousJobStatus, jobStatus);
    delete prevousJobStatus;
    delete jobStatus;
}

/**
 * @tc.name: PrintCupsClientTest_0044
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0044, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = true;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0045
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0045, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_COMPLETED;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0046
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0046, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_PROCESSING;
    int ret = memcpy_s(jobStatus->printer_state_reasons,
        sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_NONE.c_str(),
        strlen(PRINTER_STATE_NONE.c_str()));
    if (ret != 0) {
        delete jobParams;
        delete jobStatus;
        delete param;
        return;
    }
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0047
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0047, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_PROCESSING;
    int ret = memcpy_s(jobStatus->printer_state_reasons,
        sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MEDIA_EMPTY.c_str(),
        strlen(PRINTER_STATE_MEDIA_EMPTY.c_str()));
    if (ret != 0) {
        delete jobParams;
        delete jobStatus;
        delete param;
        return;
    }
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0048
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0048, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_CANCELED;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0049
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0049, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_ABORTED;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0050
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0050, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_PENDING;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0051
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0051, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_HELD;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0052
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0052, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    bool isOffline = false;
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    jobStatus->job_state = IPP_JOB_STOPPED;
    printCupsClient.JobStatusCallback(param, jobStatus, isOffline);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0053
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0053, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobStatus *jobStatus = nullptr;
    JobMonitorParam *param = nullptr;
    printCupsClient.ReportBlockedReason(param, jobStatus);
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0054
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0054, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility = nullptr,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    printCupsClient.ReportBlockedReason(param, jobStatus);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0055
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0055, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MEDIA_EMPTY.c_str(), strlen(PRINTER_STATE_MEDIA_EMPTY.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MEDIA_JAM.c_str(), strlen(PRINTER_STATE_MEDIA_JAM.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_PAUSED.c_str(), strlen(PRINTER_STATE_PAUSED.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_TONER_LOW.c_str(), strlen(PRINTER_STATE_TONER_LOW.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_TONER_EMPTY.c_str(), strlen(PRINTER_STATE_TONER_EMPTY.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_DOOR_EMPTY.c_str(), strlen(PRINTER_STATE_DOOR_EMPTY.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    delete jobParams;
    delete jobStatus;
    delete param;
}

/**
 * @tc.name: PrintCupsClientTest_0056
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0056, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    http_t *http = nullptr;
    printCupsClient.QueryJobState(http, param, jobStatus);
    delete jobParams;
    delete jobStatus;
    delete param;
    delete http;
}

/**
 * @tc.name: PrintCupsClientTest_0057
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0057, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        0,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    http_t *http = nullptr;
    printCupsClient.QueryJobState(http, param, jobStatus);
    delete jobParams;
    delete jobStatus;
    delete param;
    delete http;
}

/**
 * @tc.name: PrintCupsClientTest_0059
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0059, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.CancelCupsJob(GetDefaultJobId());
}

/**
 * @tc.name: PrintCupsClientTest_0060
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0060, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string serviceJobId = "0";
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    printCupsClient.jobQueue_.push_back(jobParams);
    PRINT_HILOGI("CancelCupsJob(): printCupsClient.jobQueue_.size(): %{public}u", printCupsClient.jobQueue_.size());
    printCupsClient.CancelCupsJob(serviceJobId);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0061
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0061, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string serviceJobId = "1";
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    printCupsClient.jobQueue_.push_back(jobParams);
    printCupsClient.currentJob_ = jobParams;
    printCupsClient.CancelCupsJob(serviceJobId);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0062
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0062, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string serviceJobId = "1";
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    PrintJob testJob2;
    testJob2.SetJobId(serviceJobId);
    testJob2.SetFdList(files);
    testJob2.SetPageSize(pageSize);
    testJob2.SetPrinterId("printid-1234");
    testJob2.SetOption(JOB_OPTIONS);
    JobParameters *jobParams2 = printCupsClient.BuildJobParameters(testJob2);
    printCupsClient.currentJob_ = jobParams2;
    printCupsClient.CancelCupsJob(serviceJobId);
    delete jobParams;
    delete jobParams2;
}

/**
 * @tc.name: PrintCupsClientTest_0066
 * @tc.desc: BuildJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0066, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    testJob.SetOption("test");
    printCupsClient.BuildJobParameters(testJob);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0067
 * @tc.desc: BuildJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0067, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(R"({"key": "value"})");
    printCupsClient.BuildJobParameters(testJob);
    json optionJson = json::parse(testJob.GetOption());
    optionJson["printerUri"] = "ipp://192.168.0.1:111/ipp/print";
    optionJson["printerName"] = "printer1";
    optionJson["documentFormat"] = "application/pdf";
    testJob.SetOption(optionJson.dump());
    printCupsClient.BuildJobParameters(testJob);
    optionJson["cupsOptions"] = "testCupsOptions";
    optionJson["printQuality"] = "printQuality";
    optionJson["jobName"] = "jobName";
    optionJson["mediaType"] = "mediaType";
    testJob.SetOption(optionJson.dump());
    printCupsClient.BuildJobParameters(testJob);
    optionJson["printQuality"] = 1;
    testJob.SetOption(optionJson.dump());
    printCupsClient.BuildJobParameters(testJob);
}

/**
 * @tc.name: PrintCupsClientTest_0068
 * @tc.desc: DumpJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0068, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    printCupsClient.DumpJobParameters(jobParams);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0069
 * @tc.desc: GetMedieSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0069, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    testJob.SetColorMode(1);
    testJob.SetCopyNumber(1);
    testJob.SetDuplexMode(0);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    printCupsClient.GetMedieSize(testJob);
}

/**
 * @tc.name: PrintCupsClientTest_0070
 * @tc.desc: GetDulpexString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0070, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t duplexCode = 0;
    printCupsClient.GetDulpexString(duplexCode);
    duplexCode = 1;
    printCupsClient.GetDulpexString(duplexCode);
    duplexCode = 2;
    printCupsClient.GetDulpexString(duplexCode);
    duplexCode = 3;
    printCupsClient.GetDulpexString(duplexCode);
}

/**
 * @tc.name: PrintCupsClientTest_0071
 * @tc.desc: GetColorString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0071, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t colorCode = 0;
    printCupsClient.GetColorString(colorCode);
    colorCode = 1;
    printCupsClient.GetColorString(colorCode);
    colorCode = 2;
    printCupsClient.GetColorString(colorCode);
}

/**
 * @tc.name: PrintCupsClientTest_0072
 * @tc.desc: IsCupsServerAlive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0072, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.IsCupsServerAlive();
}

/**
 * @tc.name: PrintCupsClientTest_0073
 * @tc.desc: IsPrinterExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0073, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *printerUri = "ipp://192.168.186.1:631/ipp/print";
    const char *printerName = "DIRECT-PixLab_V1-0105";
    const char *ppdName = "DIRECT-PixLab_V1-0105.ppd";
    printCupsClient.IsPrinterExist(printerUri, printerName, ppdName);
}

/**
 * @tc.name: PrintCupsClientTest_0074
 * @tc.desc: ConvertInchTo100MM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0074, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    float num = 1000;
    float ret = printCupsClient.ConvertInchTo100MM(num);
    EXPECT_EQ(ret, 2540);
}

/**
 * @tc.name: PrintCupsClientTest_0075
 * @tc.desc: IsIpConflict
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0075, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerId = "com.huawei.hmos.spooler:usb://DIRECT-HUAWEI_PixLab_V1-1620";
    std::string nic = "";
    printCupsClient.IsIpConflict(printerId, nic);
    printerId = "com.huawei.hmos.spooler:p2p://DIRECT-HUAWEI_PixLab_V1-1620";
    printCupsClient.IsIpConflict(printerId, nic);
}

/**
 * @tc.name: PrintCupsClientTest_0076
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0076, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    std::vector<uint32_t> files = {1};
    testJob.SetFdList(files);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("pgid-1234");
    testJob.SetPageSize(pageSize);
    testJob.SetPrinterId("printid-1234");
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob);
    JobStatus *jobStatus = new (std::nothrow) JobStatus{{'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam{jobParams->serviceAbility,
        jobParams->serviceJobId,
        1,
        "ipp://192.168.186.1:631/ipp/print",
        "DIRECT-PixLab_V1-0105"};
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MEDIA_NEEDED.c_str(), strlen(PRINTER_STATE_MEDIA_NEEDED.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MARKER_LOW.c_str(), strlen(PRINTER_STATE_MARKER_LOW.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_MARKER_EMPTY.c_str(), strlen(PRINTER_STATE_MARKER_EMPTY.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_INK_EMPTY.c_str(), strlen(PRINTER_STATE_INK_EMPTY.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_COVER_OPEN.c_str(), strlen(PRINTER_STATE_COVER_OPEN.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_OFFLINE.c_str(), strlen(PRINTER_STATE_OFFLINE.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    memcpy_s(jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons),
        PRINTER_STATE_NONE.c_str(), strlen(PRINTER_STATE_NONE.c_str()));
    printCupsClient.ReportBlockedReason(param, jobStatus);
    delete jobParams;
    delete jobStatus;
    delete param;
}

}  // namespace Print
}  // namespace OHOS