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

#include <thread>
#include <gtest/gtest.h>
#define private public
#include "print_cups_client.h"
#undef private
#include "print_constant.h"
#include "print_log.h"
#include "fstream"
#include "print_json_util.h"
#define private public
#include "print_service_ability.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Print {
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"printer1\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\",\"borderless\":true,"
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"],\"isAutoRotate\":true}";

const uint32_t DIR_MODE = 0771;
const int32_t STATE_UPDATE_STEP = 5;
const int TEST_CUPS_JOB_ID = 100;

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
static const std::string DEFAULT_MAKE_MODEL = "IPP Everywhere";
static const std::string REMOTE_PRINTER_MAKE_MODEL = "Remote Printer";

static const std::string TEST_SERVICE_JOB_ID = "test_id";
static const std::string PRINTER_URI = "test_printer_uri";
static const std::string PRINTER_PRINTER_NAME = "test_printer_name";
static const std::string PRINTER_PRINTER_ID = "test_printer_id";
static const std::string JOB_USER_NAME = "test_user";

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
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0001_NeedRename, TestSize.Level0)
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
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0002_NeedRename, TestSize.Level0)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string path = "";
    mode_t mode = 16;
    EXPECT_EQ(printCupsClient.ChangeFilterPermission(path, mode), false);
}

/**
 * @tc.name: PrintCupsClientTest_0003
 * @tc.desc: SymlinkDirectory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0003_NeedRename, TestSize.Level0)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *srcDir = "./PrintCupsClientTest_0003_srcDir";
    const char *destDir = "./PrintCupsClientTest_0003_destDir";

    if (access(srcDir, F_OK) != 0) {
        mkdir(srcDir, DIR_MODE);
    }
    if (access(destDir, F_OK) != 0) {
        mkdir(destDir, DIR_MODE);
    }

    std::string srcFilePath = "./PrintCupsClientTest_0003_srcDir/PrintCupsClientTestFileName";
    std::ofstream testSrcFile(srcFilePath.c_str(), std::ios::out);
    EXPECT_EQ(testSrcFile.is_open(), true);
    testSrcFile.close();

    printCupsClient.SymlinkDirectory(srcDir, destDir);

    struct stat destDirstat = {};
    EXPECT_EQ(lstat((std::string(destDir) + "/PrintCupsClientTestFileName").c_str(), &destDirstat), 0);
    EXPECT_EQ(S_ISLNK(destDirstat.st_mode), true);

    EXPECT_GE(std::filesystem::remove_all(std::filesystem::current_path() / srcDir), 0);
    EXPECT_GE(std::filesystem::remove_all(std::filesystem::current_path() / destDir), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0004
 * @tc.desc: CopyDirectory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0004_NeedRename, TestSize.Level0)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *srcDir = "./PrintCupsClientTest_0004_srcDir";
    const char *destDir = "./PrintCupsClientTest_0004_destDir";
    const char *subSrcDir = "PrintCupsClientTest_0004_srcDir/PrintCupsClientTest";

    if (access(srcDir, F_OK) != 0) {
        mkdir(srcDir, DIR_MODE);
    }

    if (access(destDir, F_OK) != 0) {
        mkdir(destDir, DIR_MODE);
    }

    if (access(subSrcDir, F_OK) != 0) {
        mkdir(subSrcDir, DIR_MODE);
    }

    std::string srcFilePath = std::string(subSrcDir) + "/PrintCupsClientTestFileName";
    std::ofstream testSrcFile(srcFilePath.c_str(), std::ios::out);
    EXPECT_EQ(testSrcFile.is_open(), true);
    testSrcFile.close();

    printCupsClient.CopyDirectory(srcDir, destDir);

    EXPECT_EQ(
        std::filesystem::is_regular_file(std::string(destDir) + "/PrintCupsClientTest/PrintCupsClientTestFileName"),
        true);
    EXPECT_GE(std::filesystem::remove_all(std::filesystem::current_path() / srcDir), 0);
    EXPECT_GE(std::filesystem::remove_all(std::filesystem::current_path() / destDir), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0005
 * @tc.desc: InitCupsResources
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0005_NeedRename, TestSize.Level0)
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
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0006_NeedRename, TestSize.Level0)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.StartCupsdService();
    EXPECT_EQ(ret, E_PRINT_NONE);
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsClientTest_0008
 * @tc.desc: SetDefaultPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0008_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "DIRECT-PixLab_V1-0105";
    printCupsClient.SetDefaultPrinter(printerName);
    EXPECT_EQ(printCupsClient.StartCupsdService(), E_PRINT_NONE);
    printCupsClient.SetDefaultPrinter(printerName);
}

/**
 * @tc.name: PrintCupsClientTest_0009
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0009_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "DIRECT-PixLab_V1-0105";
    std::string printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-0105";
    PrinterInfo info;
    info.SetPrinterName(printerName);
    EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintCupsClientTest_0012
 * @tc.desc: QueryPrinterCapabilityByUri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0012_NeedRename, TestSize.Level1)
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
HWTEST_F(PrintCupsClientTest, AddCupsPrintJob_ShouldAddFailed_WhenCorrectPrintJob, TestSize.Level1)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    PrintJob testJob;
    printCupsClient->AddCupsPrintJob(testJob, JOB_USER_NAME);
    EXPECT_EQ(printCupsClient->currentJob_, nullptr);
}

/**
 * @tc.name: PrintCupsClientTest_0014
 * @tc.desc: AddCupsPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, AddCupsPrintJob_ShouldAddSucceed_WhenNormalPrintJob, TestSize.Level0)
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
    printCupsClient->AddCupsPrintJob(testJob, JOB_USER_NAME);
    EXPECT_EQ(printCupsClient->currentJob_->printerId, "printid-1234");
}

HWTEST_F(PrintCupsClientTest, QueryAllPpdInfoTest, TestSize.Level0)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    std::vector<PpdInfo> infos;
    EXPECT_FALSE(printCupsClient->QueryAllPPDInformation("", infos));
    EXPECT_FALSE(printCupsClient->QueryAllPPDInformation("wrongMake", infos));
}


HWTEST_F(PrintCupsClientTest, GetAllPPDFileTest, TestSize.Level0)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    std::vector<PpdInfo> infos;
    int32_t ret = printCupsClient->GetAllPPDFile(infos);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0015
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, StartNextJob_DoNothing_When_NullInQueue, TestSize.Level0)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    printCupsClient->toCups_ = false;
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    EXPECT_EQ(printCupsClient->jobQueue_.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0016
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, StartNextJob_Succeed_When_OnePrintJobInQueue, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient->BuildJobParameters(testJob, JOB_USER_NAME);
    printCupsClient->jobQueue_.push_back(jobParams);
    EXPECT_EQ(printCupsClient->jobQueue_.size(), 1);
    printCupsClient->toCups_ = false;
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    EXPECT_EQ(printCupsClient->jobQueue_.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0018
 * @tc.desc: StartNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, StartNextJob_ClearQueue_When_NullptrPrintJobInQueue, TestSize.Level0)
{
    auto printCupsClient = std::make_shared<OHOS::Print::PrintCupsClient>();
    JobParameters *jobParams = nullptr;
    printCupsClient->jobQueue_.push_back(jobParams);
    EXPECT_EQ(printCupsClient->jobQueue_.size(), 1);
    printCupsClient->toCups_ = false;
    printCupsClient->StartNextJob();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    EXPECT_EQ(printCupsClient->jobQueue_.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0019
 * @tc.desc: JobCompleteCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0019_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient->BuildJobParameters(testJob, JOB_USER_NAME);
    printCupsClient->JobSentCallback();  // currentJob_ is null, do nothing
    printCupsClient->currentJob_ = jobParams;
    printCupsClient->JobSentCallback();  // clear currentJob_
    EXPECT_EQ(printCupsClient->currentJob_, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

/**
 * @tc.name: PrintCupsClientTest_0020
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0020_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillBorderlessOptions(nullptr, numOptions, &options), 0);
    EXPECT_EQ(printCupsClient.FillJobOptions(nullptr, numOptions, &options), 0);
}
/**
 * @tc.name: PrintCupsClientTest_0021
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillThreeOptions_When_SetBorderless, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->borderless = 1;
    jobParams->mediaSize = "";
    jobParams->mediaType = "";
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options), 3);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0022
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillThreeOptions_When_SetNotBorderless, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->mediaSize = "testMediaSize";
    jobParams->mediaType = "testMediaType";
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options), 3);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0023
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0023_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->borderless = 0;
    jobParams->mediaType = CUPS_MEDIA_TYPE_PHOTO_GLOSSY;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    int ret = printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(ret, 3);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0024
 * @tc.desc: FillBorderlessOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0024_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->borderless = 1;
    jobParams->mediaType = CUPS_MEDIA_TYPE_PHOTO_GLOSSY;
    jobParams->mediaSize = CUPS_MEDIA_4X6;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    int ret = printCupsClient.FillBorderlessOptions(jobParams, numOptions, &options);
    EXPECT_EQ(ret, 2);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0025
 * @tc.desc: FillJobOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillJobOptions_SetNullValue_ReturnCorrectNumOptions, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo, JOB_USER_NAME);
    jobParams->printerId = "1";
    jobParams->numCopies = 2;
    jobParams->duplex = "";
    jobParams->printQuality = "";
    jobParams->color = "";
    jobParams->isAutoRotate = true;
    jobParams->isCollate = false;
    jobParams->isReverse = false;
    int ret = printCupsClient.FillJobOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 9);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0026
 * @tc.desc: FillJobOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillJobOptions_SetTrueValue_ReturnCorrectNumOptions, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo, JOB_USER_NAME);
    jobParams->printerId = "1";
    jobParams->numCopies = 0;
    jobParams->duplex = "test_duplex";
    jobParams->printQuality = "test_printQuality";
    jobParams->color = "test_color";
    jobParams->borderless = 1;
    jobParams->mediaType = CUPS_MEDIA_TYPE_PHOTO_GLOSSY;
    jobParams->mediaSize = CUPS_MEDIA_4X6;
    jobParams->isCollate = true;
    jobParams->isReverse = true;
    int ret = printCupsClient.FillJobOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 8);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0027
 * @tc.desc: QueryAddedPrinterList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0027_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<std::string> printerNameList;
    printerNameList.push_back("testPrinterName");
    printCupsClient.StopCupsdService();
    EXPECT_EQ(printCupsClient.QueryAddedPrinterList(printerNameList), E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0028
 * @tc.desc: QueryAddedPrinterList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0028_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<std::string> printerNameList;
    printerNameList.push_back("testPrinterName");
    printCupsClient.StartCupsdService();
    EXPECT_EQ(printCupsClient.QueryAddedPrinterList(printerNameList), E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0030
 * @tc.desc: GetPPDFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0030_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    printCupsClient.StopCupsdService();
    ppd_file_t *ppd = printCupsClient.GetPPDFile(printerName);
    EXPECT_EQ(ppd, nullptr);
}

/**
 * @tc.name: PrintCupsClientTest_0031
 * @tc.desc: GetPPDFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0031_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    EXPECT_EQ(printCupsClient.StartCupsdService(), E_PRINT_NONE);
    printCupsClient.GetPPDFile(printerName);
}

/**
 * @tc.name: PrintCupsClientTest_0032
 * @tc.desc: QueryPrinterAttrList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0032_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(printCupsClient.QueryPrinterAttrList(printerName, keyList, valueList), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintCupsClientTest_0033
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0033_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerId = "testPrinterId";
    PrinterInfo info;
    info.SetPrinterName("testPrinterName");
    EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintCupsClientTest_0034
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0034_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobParameters *jobParams = nullptr;
    bool driverMissing = false;
    bool ret = printCupsClient.CheckPrinterMakeModel(jobParams, driverMissing);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PrintCupsClientTest_0036
 * @tc.desc: VerifyPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0036_NeedRename, TestSize.Level1)
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
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0039_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_NE(jobParams, nullptr);
    EXPECT_NE(jobParams->serviceAbility, nullptr);

    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_BLOCKED_UNKNOWN;
    printCupsClient.UpdatePrintJobStateInJobParams(jobParams, state, subState);

    auto jobId = jobParams->serviceJobId;
    auto userData = jobParams->serviceAbility->GetUserDataByJobId(jobId);
    EXPECT_EQ(userData, nullptr);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0042
 * @tc.desc: UpdateJobStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0042_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    EXPECT_FALSE(printCupsClient.CheckPrinterDriverExist(std::string()));
    EXPECT_TRUE(printCupsClient.CheckPrinterDriverExist(DEFAULT_MAKE_MODEL));
    EXPECT_TRUE(printCupsClient.CheckPrinterDriverExist(BSUNI_PPD_NAME));
    EXPECT_FALSE(printCupsClient.CheckPrinterDriverExist(REMOTE_PRINTER_MAKE_MODEL));
}

/**
 * @tc.name: PrintCupsClientTest_0043
 * @tc.desc: UpdateJobStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0043_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.StartMonitor();
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    printCupsClient.StartMonitor();
    EXPECT_EQ(printCupsClient.jobMonitorList_.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0047
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0047_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.IsPrinterStopped(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    EXPECT_FALSE(printCupsClient.IsPrinterStopped(param));
}

/**
 * @tc.name: PrintCupsClientTest_0048
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0048_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.IfContinueToHandleJobState(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    EXPECT_TRUE(printCupsClient.IfContinueToHandleJobState(param));
    param->isCanceled = true;
    EXPECT_FALSE(printCupsClient.IfContinueToHandleJobState(param));
}

/**
 * @tc.name: PrintCupsClientTest_0049
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0049_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_COMPLETED;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0050
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0050_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_PROCESSING;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0051
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0051_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_CANCELED;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0052
 * @tc.desc: JobStatusCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0052_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_ABORTED;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0053
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0053_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_STOPPED;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0054
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0054_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_PENDING;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    char jobState[] = "printer-stopped";
    strlcpy(param->job_state_reasons, jobState, sizeof(param->job_state_reasons));
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0055
 * @tc.desc: ReportBlockedReason
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0055_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.JobStatusCallback(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->job_state = IPP_JOB_HELD;
    param->isBlock = false;
    param->timesOfSameState = 0;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->isBlock = true;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_TRUE(printCupsClient.JobStatusCallback(param));
}

/**
 * @tc.name: PrintCupsClientTest_0056
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0056_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.ParseStateReasons(nullptr);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->isPrinterStopped = false;
    printCupsClient.ParseStateReasons(param);
    EXPECT_EQ(param->substate, 0);
    param->isPrinterStopped = true;
    printCupsClient.ParseStateReasons(param);
    EXPECT_EQ(param->substate, 99);
}

/**
 * @tc.name: PrintCupsClientTest_0057
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0057_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.GetBlockedAndUpdateSubstate(
        nullptr, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->isBlock = false;
    param->timesOfSameState = 0;
    std::string reason = "media-jam-error";
    reason.copy(param->job_printer_state_reasons, reason.length() + 1);
    EXPECT_TRUE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_TRUE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_BLOCK, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_HINT, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_TRUE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
}

/**
 * @tc.name: PrintCupsClientTest_0058
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0058_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.GetBlockedAndUpdateSubstate(
        nullptr, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->isBlock = false;
    param->timesOfSameState = 0;
    std::string reason = "media-jam-warning";
    reason.copy(param->job_printer_state_reasons, reason.length() + 1);
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_TRUE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_BLOCK, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_HINT, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
}

/**
 * @tc.name: PrintCupsClientTest_0059
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0059_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int num = printCupsClient.jobQueue_.size();
    printCupsClient.CancelCupsJob(GetDefaultJobId());
    if (num > 0) {
        num = num - 1;
    }
    EXPECT_EQ(printCupsClient.jobQueue_.size(), num);
}

/**
 * @tc.name: PrintCupsClientTest_0060
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0060_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->jobOriginatingUserName, JOB_USER_NAME);
    printCupsClient.jobQueue_.push_back(jobParams);
    PRINT_HILOGI("CancelCupsJob(): printCupsClient.jobQueue_.size(): %{public}u", printCupsClient.jobQueue_.size());
    printCupsClient.CancelCupsJob(serviceJobId);
}

/**
 * @tc.name: PrintCupsClientTest_0061
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0061_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->jobOriginatingUserName, JOB_USER_NAME);
    printCupsClient.jobQueue_.push_back(jobParams);
    printCupsClient.CancelCupsJob(serviceJobId);
}

/**
 * @tc.name: PrintCupsClientTest_0062
 * @tc.desc: CancelCupsJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0062_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string serviceJobId = TEST_SERVICE_JOB_ID;
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    printCupsClient.jobMonitorList_ = std::vector<std::shared_ptr<JobMonitorParam>>(1, param);
    printCupsClient.CancelCupsJob("invalidId");
    EXPECT_FALSE(param->isCanceled);
    printCupsClient.CancelCupsJob(TEST_SERVICE_JOB_ID);
    EXPECT_TRUE(param->isCanceled);
}

/**
 * @tc.name: PrintCupsClientTest_0063
 * @tc.desc: QueryJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0063_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    printCupsClient.GetBlockedAndUpdateSubstate(
        nullptr, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED);
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    param->substate = 0;
    param->isBlock = false;
    param->timesOfSameState = 0;
    std::string reason = "null";
    reason.copy(param->job_printer_state_reasons, reason.length() + 1);
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_STANDARD, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_BLOCK, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_HINT, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
    param->timesOfSameState = STATE_UPDATE_STEP;
    EXPECT_FALSE(printCupsClient.GetBlockedAndUpdateSubstate(
        param, STATE_POLICY_DELAY, PRINTER_STATE_MEDIA_JAM, PRINT_JOB_BLOCKED_JAMMED));
}

/**
 * @tc.name: PrintCupsClientTest_0066
 * @tc.desc: BuildJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0066_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);

    testJob.SetOption("test");
    printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0067
 * @tc.desc: BuildJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0067_NeedRename, TestSize.Level1)
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
    testJob.SetIsLandscape(true);
    testJob.SetOption(R"({"key": "value"})");
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);

    Json::Value optionJson;
    PrintJsonUtil::Parse(testJob.GetOption(), optionJson);
    optionJson["printerUri"] = "ipp://192.168.0.1:111/ipp/print";
    optionJson["printerName"] = "printer1";
    optionJson["documentFormat"] = "application/pdf";
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->printerUri, optionJson["printerUri"].asString());
    EXPECT_EQ(jobParams->printerName, PrintUtil::StandardizePrinterName(optionJson["printerName"].asString()));
    EXPECT_EQ(jobParams->documentFormat, optionJson["documentFormat"].asString());

    optionJson["cupsOptions"] = "testCupsOptions";
    optionJson["printQuality"] = "printQuality";
    optionJson["jobName"] = "jobName";
    optionJson["mediaType"] = "mediaType";
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->printerAttrsOptionCupsOption, optionJson["cupsOptions"].asString());
    EXPECT_EQ(jobParams->printQuality, optionJson["printQuality"].asString());
    EXPECT_EQ(jobParams->jobName, optionJson["jobName"].asString());
    EXPECT_EQ(jobParams->mediaType, optionJson["mediaType"].asString());

    optionJson["printQuality"] = 1;
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->printQuality, CUPS_PRINT_QUALITY_NORMAL);

    EXPECT_EQ(jobParams->isAutoRotate, true);  // default true
    optionJson["isAutoRotate"] = false;
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams->isAutoRotate, optionJson["isAutoRotate"].asBool());
}

/**
 * @tc.name: PrintCupsClientTest_0068
 * @tc.desc: DumpJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0068_NeedRename, TestSize.Level1)
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
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    std::string option = testJob.GetOption();
    Json::Value optionJson;
    PrintJsonUtil::Parse(option, optionJson);
    EXPECT_EQ(jobParams->jobName, optionJson["jobName"].asString());
    EXPECT_EQ(jobParams->mediaType, optionJson["mediaType"].asString());
    EXPECT_EQ(jobParams->printQuality, optionJson["printQuality"].asString());
    EXPECT_EQ(jobParams->printerName, optionJson["printerName"].asString());
    EXPECT_EQ(jobParams->printerUri, optionJson["printerUri"].asString());
    EXPECT_EQ(jobParams->documentFormat, optionJson["documentFormat"].asString());
    EXPECT_EQ(jobParams->isAutoRotate, optionJson["isAutoRotate"].asBool());
    printCupsClient.DumpJobParameters(jobParams);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0069
 * @tc.desc: GetMedieSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0069_NeedRename, TestSize.Level1)
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
    std::string pageSizeName = printCupsClient.GetMedieSize(testJob);
    EXPECT_EQ("PrintPageSize", pageSizeName);
}

/**
 * @tc.name: PrintCupsClientTest_0070
 * @tc.desc: GetDulpexString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0070_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t duplexCode = 0;
    std::string ret0 = printCupsClient.GetDulpexString(duplexCode);
    EXPECT_EQ(ret0, CUPS_SIDES_ONE_SIDED);

    duplexCode = 1;
    std::string ret1 = printCupsClient.GetDulpexString(duplexCode);
    EXPECT_EQ(ret1, CUPS_SIDES_TWO_SIDED_PORTRAIT);

    duplexCode = 2;
    std::string ret2 = printCupsClient.GetDulpexString(duplexCode);
    EXPECT_EQ(ret2, CUPS_SIDES_TWO_SIDED_LANDSCAPE);

    duplexCode = 3;
    std::string ret3 = printCupsClient.GetDulpexString(duplexCode);
    EXPECT_EQ(ret3, CUPS_SIDES_ONE_SIDED);
}

/**
 * @tc.name: PrintCupsClientTest_0071
 * @tc.desc: GetColorString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0071_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    uint32_t colorCode = 0;
    std::string ret0 = printCupsClient.GetColorString(colorCode);
    EXPECT_EQ(ret0, CUPS_PRINT_COLOR_MODE_MONOCHROME);

    colorCode = 1;
    std::string ret1 = printCupsClient.GetColorString(colorCode);
    EXPECT_EQ(ret1, CUPS_PRINT_COLOR_MODE_COLOR);

    colorCode = 2;
    std::string ret2 = printCupsClient.GetColorString(colorCode);
    EXPECT_EQ(ret2, CUPS_PRINT_COLOR_MODE_AUTO);
}

/**
 * @tc.name: PrintCupsClientTest_0073
 * @tc.desc: IsPrinterExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0073_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    const char *printerUri = "ipp://192.168.186.1:631/ipp/print";
    const char *printerName = "DIRECT-PixLab_V1-0105";
    const char *ppdName = "DIRECT-PixLab_V1-0105.ppd";
    EXPECT_EQ(printCupsClient.IsPrinterExist(printerUri, printerName, ppdName), E_PRINT_NONE);
}

/**
 * @tc.name: PrintCupsClientTest_0074
 * @tc.desc: ConvertInchTo100MM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0074_NeedRename, TestSize.Level1)
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
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0075_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerId = "com.ohos.spooler:usb://DIRECT-PixLab_V1-1620";
    std::string nic = "";
    bool ret1 = printCupsClient.IsIpConflict(printerId, nic);
    EXPECT_EQ(ret1, false);

    printerId = "com.ohos.spooler:p2p://DIRECT-PixLab_V1-1620";
    bool ret2 = printCupsClient.IsIpConflict(printerId, nic);
    EXPECT_EQ(ret2, false);
}

/**
 * @tc.name: PrintCupsClientTest_0077
 * @tc.desc: DiscoverUsbPrinters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0077_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<PrinterInfo> printers;
    printCupsClient.DiscoverUsbPrinters(printers);
    EXPECT_EQ(printers.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0078
 * @tc.desc: BuildJobParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0078_NeedRename, TestSize.Level1)
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

    Json::Value optionJson;
    PrintJsonUtil::Parse(testJob.GetOption(), optionJson);
    optionJson["printerUri"] = 1;
    optionJson["printerName"] = "printer1";
    optionJson["documentFormat"] = "application/pdf";
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);

    optionJson["printerUri"] = "ipp://192.168.0.1:111/ipp/print";
    optionJson["printerName"] = 1;
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);

    optionJson["printerName"] = "printer1";
    optionJson["documentFormat"] = 1;
    testJob.SetOption(PrintJsonUtil::WriteString(optionJson));
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    EXPECT_EQ(jobParams, nullptr);
}

/**
 * @tc.name: PrintCupsClientTest_0079
 * @tc.desc: HandleFiles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0079_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    http_t *http = nullptr;
    JobParameters *jobParams = nullptr;
    int32_t numFiles = 1;
    int32_t jobId = 1;
    EXPECT_EQ(printCupsClient.HandleFiles(jobParams, numFiles, http, jobId), false);
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
    jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    delete http;
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0081
 * @tc.desc: UpdateJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0081_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    EXPECT_FALSE(printCupsClient.UpdateJobState(nullptr, nullptr));
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    EXPECT_FALSE(printCupsClient.UpdateJobState(param, nullptr));
}

/**
 * @tc.name: PrintCupsClientTest_0082
 * @tc.desc: ResumePrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0082_NeedRename, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string printerName = "testPrinterName";
    EXPECT_EQ(printCupsClient.ResumePrinter(printerName), false);
    printCupsClient.printAbility_ = nullptr;
    EXPECT_EQ(printCupsClient.ResumePrinter(printerName), false);
}

/**
 * @tc.name: PrintCupsClientTest_0083
 * @tc.desc: FillLandscapeOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0083_NeedRename, TestSize.Level1)
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
    testJob.SetIsLandscape(true);
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->isAutoRotate = true;
    jobParams->isLandscape = true;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillLandscapeOptions(jobParams, numOptions, &options), 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0084
 * @tc.desc: FillLandscapeOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0084_NeedRename, TestSize.Level1)
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
    testJob.SetIsLandscape(true);
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->isAutoRotate = true;
    jobParams->isLandscape = false;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillLandscapeOptions(jobParams, numOptions, &options), 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0085
 * @tc.desc: FillLandscapeOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillTwoOptions_When_SetNotLandscape, TestSize.Level1)
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
    testJob.SetIsLandscape(true);
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->isAutoRotate = false;
    jobParams->isLandscape = false;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillLandscapeOptions(jobParams, numOptions, &options), 2);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0086
 * @tc.desc: FillLandscapeOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillTwoOptions_When_SetLandscape, TestSize.Level1)
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
    testJob.SetIsLandscape(true);
    testJob.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(testJob, JOB_USER_NAME);
    jobParams->isAutoRotate = false;
    jobParams->isLandscape = true;
    int numOptions = 0;
    cups_option_t *options = nullptr;
    EXPECT_EQ(printCupsClient.FillLandscapeOptions(jobParams, numOptions, &options), 2);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0087
 * @tc.desc: DeviceCb_ShouldAddPrinterInfo_WhenDeviceUriStartsWithUSBAndPrinterMakeIsNotUnknown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, DeviceCb_WhenUsbDevice_ShouldAdd, TestSize.Level0)
{
    // Arrange
    std::string deviceUri = "usb://printer";
    std::string deviceClass = "printer";
    std::string deviceId = "model123";
    std::string deviceInfo = "model123";
    std::string deviceMakeAndModel = "model123";
    std::string deviceLocation = "location123";
    void *userData = nullptr;
    // Act
    ClearUsbPrinters();
    ClearBackendPrinters();
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        nullptr,
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        "usb://printer_serial=123&111",
        deviceLocation.c_str(),
        userData);
    // Assert
    auto usbPrinters = GetUsbPrinters();
    EXPECT_EQ(usbPrinters.size(), 3);
    EXPECT_STREQ(usbPrinters[0].GetUri().c_str(), deviceUri.c_str());
    EXPECT_STREQ(usbPrinters[0].GetPrinterMake().c_str(), deviceMakeAndModel.c_str());
    auto backendPrinters = GetBackendPrinters();
    EXPECT_EQ(backendPrinters.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0088
 * @tc.desc: DeviceCb_ShouldNotAddPrinterInfo_WhenDeviceUriDoesNotStartWithUSB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, DeviceCb_WhenVendorDevice_ShouldAdd, TestSize.Level0)
{
    // Arrange
    std::string deviceUri = "vendor://printer";
    std::string deviceClass = "printer";
    std::string deviceId = "model123";
    std::string deviceInfo = "model123";
    std::string deviceMakeAndModel = "model123";
    std::string deviceLocation = "location123";
    void *userData = nullptr;
    // Act
    ClearUsbPrinters();
    ClearBackendPrinters();
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        nullptr,
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        "vendor://printer_serial=123&111",
        deviceLocation.c_str(),
        userData);
    // Assert
    auto usbPrinters = GetUsbPrinters();
    EXPECT_EQ(usbPrinters.size(), 0);
    auto backendPrinters = GetBackendPrinters();
    EXPECT_EQ(backendPrinters.size(), 3);
}

/**
 * @tc.name: PrintCupsClientTest_0089
 * @tc.desc: DeviceCb_ShouldNotAddPrinterInfo_WhenPrinterMakeIsUnknown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, DeviceCb_WhenUnknownMake_ShouldIgnore, TestSize.Level1)
{
    // Arrange
    std::string deviceUri = "usb://printer";
    std::string deviceClass = "printer";
    std::string deviceId = "model123";
    std::string deviceInfo = "model123";
    std::string deviceMakeAndModel = "Unknown";
    std::string deviceLocation = "location123";
    void *userData = nullptr;
    // Act
    ClearUsbPrinters();
    ClearBackendPrinters();
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    deviceUri = "vendor://printer";
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    // Assert
    auto usbPrinters = GetUsbPrinters();
    EXPECT_EQ(usbPrinters.size(), 0);
    auto backendPrinters = GetBackendPrinters();
    EXPECT_EQ(backendPrinters.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0090
 * @tc.desc: DeviceCb_ShouldNotAddPrinterInfo_WhenParamNull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0090_NeedRename, TestSize.Level1)
{
    // Arrange
    std::string deviceUri = "usb://printer";
    std::string deviceClass = "printer";
    std::string deviceId = "model123";
    std::string deviceInfo = "model123";
    std::string deviceMakeAndModel = "Unknown";
    std::string deviceLocation = "location123";
    void *userData = nullptr;
    // Act
    DeviceCb(nullptr,
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        nullptr,
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        nullptr,
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        nullptr,
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        nullptr,
        deviceLocation.c_str(),
        userData);
    // Assert
    auto usbPrinters = GetUsbPrinters();
    EXPECT_EQ(usbPrinters.size(), 0);
}

/**
 * @tc.name: PrintCupsClientTest_0091
 * @tc.desc: DeviceCb_Serial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0091_NeedRename, TestSize.Level1)
{
    // Arrange
    std::string deviceUri = "usb://printer_serial=123&111";
    std::string deviceClass = "printer";
    std::string deviceId = "model123";
    std::string deviceInfo = "model123";
    std::string deviceMakeAndModel = "model123";
    std::string deviceLocation = "1234-";
    void *userData = nullptr;
    // Act
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    deviceLocation = "1234-5678";
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        deviceLocation.c_str(),
        userData);
    DeviceCb(deviceClass.c_str(),
        deviceId.c_str(),
        deviceInfo.c_str(),
        deviceMakeAndModel.c_str(),
        deviceUri.c_str(),
        nullptr,
        userData);
    // Assert
    auto usbPrinters = GetUsbPrinters();
    EXPECT_EQ(usbPrinters.size(), 3);
    EXPECT_STREQ(usbPrinters[0].GetUri().c_str(), deviceUri.c_str());
    EXPECT_STREQ(usbPrinters[0].GetPrinterMake().c_str(), deviceMakeAndModel.c_str());
    EXPECT_STREQ(usbPrinters[0].GetPrinterId().c_str(), "USB-model123-123");
    ClearUsbPrinters();
}

/**
 * @tc.name: PrintCupsClientTest_0092
 * @tc.desc: GetUsbPrinterSerial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0092_NeedRename, TestSize.Level1)
{
    std::string usb = "usb://";
    std::string serial = "serial=";
    std::string num = "11";
    std::string deviceUri = usb;
    EXPECT_STREQ(GetUsbPrinterSerial(deviceUri).c_str(), "");
    deviceUri = usb + serial;
    EXPECT_STREQ(GetUsbPrinterSerial(deviceUri).c_str(), "");
    deviceUri = usb + serial + num;
    EXPECT_STREQ(GetUsbPrinterSerial(deviceUri).c_str(), num.c_str());
    deviceUri = usb + serial + num + "&postfix";
    EXPECT_STREQ(GetUsbPrinterSerial(deviceUri).c_str(), num.c_str());
    deviceUri = usb + serial + "1234567890" + "&postfix";
    EXPECT_STREQ(GetUsbPrinterSerial(deviceUri).c_str(), "567890");
}

/**
 * @tc.name: PrintCupsClientTest_0093
 * @tc.desc: StandardizePrinterUri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_0093_NeedRename, TestSize.Level1)
{
    std::string printerUri = "test";
    EXPECT_STREQ(StandardizePrinterUri(printerUri, "").c_str(), printerUri.c_str());
    EXPECT_STREQ(StandardizePrinterUri(printerUri, BSUNI_PPD_NAME).c_str(), printerUri.c_str());
    EXPECT_STREQ(StandardizePrinterUri("ipp://test", BSUNI_PPD_NAME).c_str(), "bsUniBackend://test");
}

/**
 * @tc.name: PrintCupsClientTest_0094
 * @tc.desc: FillAdvancedOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillAdvancedOptions_SetAdvancedOpsJson_NumOptionsReturnOne, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo, JOB_USER_NAME);
    Json::Value advancedOpsJson;
    advancedOpsJson["key"] = "value";
    jobParams->advancedOpsJson = advancedOpsJson;
    int ret = printCupsClient.FillAdvancedOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 1);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0095
 * @tc.desc: FillAdvancedOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, FillAdvancedOptions_SetNullAdvancedOpsJson_ReturnCorrectNumOptions, TestSize.Level1)
{
    int num = 0;
    cups_option_t *options = nullptr;
    OHOS::Print::PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    jobInfo.SetCopyNumber(2);
    jobInfo.SetDuplexMode(1);
    jobInfo.SetColorMode(0);
    jobInfo.SetOption(JOB_OPTIONS);
    JobParameters *jobParams = printCupsClient.BuildJobParameters(jobInfo, JOB_USER_NAME);
    Json::Value advancedOpsJson;
    jobParams->advancedOpsJson = advancedOpsJson;
    int ret = printCupsClient.FillAdvancedOptions(jobParams, num, &options);
    EXPECT_EQ(ret, 0);
    delete jobParams;
    delete options;
}

/**
 * @tc.name: PrintCupsClientTest_0096
 * @tc.desc: UpdateJobParameterByBoolOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByBoolOption_SetCorrectValue_ReturnSameParamValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    optionJson["isBorderless"] = false;
    optionJson["isAutoRotate"] = false;
    optionJson["isReverse"] = false;
    optionJson["isCollate"] = false;
    printCupsClient.UpdateJobParameterByBoolOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->borderless, optionJson["isBorderless"].asBool());
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0097
 * @tc.desc: UpdateJobParameterByBoolOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByBoolOption_SetWrongTypeValue_ReturndefaultValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    optionJson["isBorderless"] = 1;
    optionJson["isAutoRotate"] = 1;
    optionJson["isReverse"] = 1;
    optionJson["isCollate"] = 1;
    printCupsClient.UpdateJobParameterByBoolOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->borderless, 1);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0098
 * @tc.desc: UpdateJobParameterByBoolOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByBoolOption_NoValueSet_ReturndefaultValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    printCupsClient.UpdateJobParameterByBoolOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->borderless, 1);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0099
 * @tc.desc: UpdateJobParameterByOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByOption_SetCorrectValue_ReturnSameParamValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    optionJson["cupsOptions"] = "1";
    optionJson["printQuality"] = "4";
    optionJson["jobName"] = "1";
    optionJson["mediaType"] = "1";
    Json::Value advancedOptions;
    advancedOptions["key"] = "value";
    optionJson["advancedOptions"] = advancedOptions;
    printCupsClient.UpdateJobParameterByOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->printQuality, optionJson["printQuality"].asString());
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0100
 * @tc.desc: UpdateJobParameterByOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByOption_SetWrongTypeValue_ReturndefaultValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    optionJson["cupsOptions"] = 1;
    optionJson["printQuality"] = 4;
    optionJson["jobName"] = 1;
    optionJson["mediaType"] = 1;
    optionJson["advancedOptions"] = 1;
    printCupsClient.UpdateJobParameterByOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->printQuality, CUPS_PRINT_QUALITY_NORMAL);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_0101
 * @tc.desc: UpdateJobParameterByOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, UpdateJobParameterByOption_NoValueSet_ReturndefaultValue, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    Json::Value optionJson;
    JobParameters *jobParams = new JobParameters();
    printCupsClient.UpdateJobParameterByOption(optionJson, jobParams);
    EXPECT_EQ(jobParams->printQuality, CUPS_PRINT_QUALITY_NORMAL);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsClientTest_HandleSystemAuthInfo
 * @tc.desc: HandleSystemAuthInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_HandleSystemAuthInfo, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string userName = "userName";
    char userPassword[] = "userPassword";
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);
    printCupsClient.jobMonitorList_ = std::vector<std::shared_ptr<JobMonitorParam>>(1, param);
    EXPECT_EQ(printCupsClient.HandleSystemAuthInfo("invalidId",
        PRINTER_URI, userName, userPassword), E_PRINT_INVALID_PRINTJOB);
    EXPECT_EQ(printCupsClient.HandleSystemAuthInfo(TEST_SERVICE_JOB_ID, PRINTER_URI, userName, userPassword),
        TEST_CUPS_JOB_ID);
}

/**
 * @tc.name: PrintCupsClientTest_AuthCupsPrintJob
 * @tc.desc: AuthCupsPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsClientTest, PrintCupsClientTest_AuthCupsPrintJob, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string userName = "userName";
    char userPassword[] = "userPassword";
    auto param = std::make_shared<JobMonitorParam>(PrintServiceAbility::GetInstance(),
        TEST_SERVICE_JOB_ID,
        TEST_CUPS_JOB_ID,
        PRINTER_URI,
        PRINTER_PRINTER_NAME,
        PRINTER_PRINTER_ID,
        nullptr);

    printCupsClient.jobMonitorList_ = std::vector<std::shared_ptr<JobMonitorParam>>(1, param);
    printCupsClient.AuthCupsPrintJob(TEST_SERVICE_JOB_ID, PRINTER_URI, userName, userPassword);
    EXPECT_EQ(printCupsClient.StartCupsdService(), E_PRINT_NONE);
}

HWTEST_F(PrintCupsClientTest, AddPrintCupsJobId_ShouldAddJobId_WhenCalled, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    uint32_t cupsJobId = 12345;
    printCupsClient.AddPrintCupsJobId(jobId, cupsJobId);
    auto iter = printCupsClient.cupsJobIdMap_.find(jobId);
    EXPECT_NE(iter, printCupsClient.cupsJobIdMap_.end());
    EXPECT_EQ(iter->second, cupsJobId);
}

HWTEST_F(PrintCupsClientTest, RemovePrintCupsJobId_ShouldRemoveJobId_WhenJobIdExist, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    uint32_t cupsJobId = 12345;
    printCupsClient.AddPrintCupsJobId(jobId, cupsJobId);
    EXPECT_NE(printCupsClient.cupsJobIdMap_.find(jobId), printCupsClient.cupsJobIdMap_.end());
    printCupsClient.RemovePrintCupsJobId(jobId);
    EXPECT_EQ(printCupsClient.cupsJobIdMap_.find(jobId), printCupsClient.cupsJobIdMap_.end());
}

HWTEST_F(PrintCupsClientTest, GetPrintCupsJobId_ShouldReturnZero_WhenJobIdNotExist, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    EXPECT_EQ(printCupsClient.GetPrintCupsJobId(jobId), 0);
}

HWTEST_F(PrintCupsClientTest, GetPrintCupsJobId_ShouldReturnJobId_WhenJobIdExist, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    uint32_t cupsJobId = 12345;
    printCupsClient.AddPrintCupsJobId(jobId, cupsJobId);
    EXPECT_EQ(printCupsClient.GetPrintCupsJobId(jobId), cupsJobId);
}

#ifdef VIRTUAL_PRINTER_ENABLE
HWTEST_F(PrintCupsClientTest, CopyJobOutputFile_InvalidJobId_Test, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    uint32_t fd = 1;
    int32_t ret = printCupsClient.CopyJobOutputFile(jobId, fd, false);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTJOB);
}

HWTEST_F(PrintCupsClientTest, CopyJobOutputFile_RealPathError_Test, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::string jobId = "test_job_id";
    uint32_t fd = 1;
    printCupsClient.AddPrintCupsJobId(jobId, 1);
    int32_t ret = printCupsClient.CopyJobOutputFile(jobId, fd, false);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}
#endif

HWTEST_F(PrintCupsClientTest, CheckPreferencesConflicts_InvalidPpdName_Test, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    PrinterPreferences preferences;
    std::string ppdName = "test_ppdName";
    std::vector<std::string> conflictTypes;

    int32_t ret = printCupsClient.CheckPreferencesConflicts(ppdName, preferences, "", conflictTypes);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
    EXPECT_TRUE(conflictTypes.empty());
}

HWTEST_F(PrintCupsClientTest, CheckPrintJobConflicts_InvalidPpdName_Test, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    PrintJob printJob;
    std::string ppdName = "test_ppdName";
    std::vector<std::string> conflictTypes;

    int32_t ret = printCupsClient.CheckPrintJobConflicts(ppdName, printJob, "", conflictTypes);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    EXPECT_TRUE(conflictTypes.empty());

    printJob.SetOption(JOB_OPTIONS);
    ret = printCupsClient.CheckPrintJobConflicts(ppdName, printJob, "", conflictTypes);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
    EXPECT_TRUE(conflictTypes.empty());
}

HWTEST_F(PrintCupsClientTest, BuildCupsOptionParamsByPreferences_Test, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    PrinterPreferences preferences;
    std::map<std::string, std::string> mapParams;

    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.empty());

    preferences.SetDefaultPageSizeId(PAGE_SIZE_ID_ISO_A4);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_PAGE_SIZE) != mapParams.end());

    preferences.SetDefaultDuplexMode(DUPLEX_MODE_NONE);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_DUPLEX_MODE) != mapParams.end());

    preferences.SetDefaultPrintQuality(PRINT_QUALITY_NORMAL);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_QUALITY) != mapParams.end());

    preferences.SetDefaultColorMode(PRINT_COLOR_MODE_MONOCHROME);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_COLOR_MODE) != mapParams.end());

    preferences.SetDefaultMediaType(CUPS_MEDIA_TYPE_PLAIN);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_MEDIA_TYPE) != mapParams.end());

    preferences.SetDefaultCollate(true);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.find(PRINT_PARAM_TYPE_DELIVERY_ORDER) != mapParams.end());

    mapParams.clear();
    preferences.Reset();
    preferences.SetOption("");
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_TRUE(mapParams.empty());

    preferences.SetOption(JOB_OPTIONS);
    printCupsClient.BuildCupsOptionParamsByPreferences(preferences, mapParams);
    EXPECT_FALSE(mapParams.empty());
}

HWTEST_F(PrintCupsClientTest, BuildCupsOptionParamsByPrintJob_Test, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    PrintJob jobInfo;
    JobParameters jobParams;
    std::map<std::string, std::string> mapParams;
    printCupsClient.BuildCupsOptionParamsByPrintJob(jobInfo, jobParams, mapParams);
    EXPECT_FALSE(mapParams.empty());
}

HWTEST_F(PrintCupsClientTest, CheckOptionConflicts_Test, TestSize.Level1)
{
    std::map<std::string, std::string> mapParams;
    std::vector<std::string> conflictTypes;
    PrintCupsClient printCupsClient;

    int32_t ret = printCupsClient.CheckOptionConflicts(nullptr, mapParams, PRINT_PARAM_TYPE_PAGE_SIZE, conflictTypes);
    EXPECT_EQ(ret, 0);

    mapParams.emplace(PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    ret = printCupsClient.CheckOptionConflicts(nullptr, mapParams, PRINT_PARAM_TYPE_PAGE_SIZE, conflictTypes);
    EXPECT_EQ(ret, 0);

    printCupsClient.DumpCupsConflicts(mapParams, PRINT_PARAM_TYPE_PAGE_SIZE, conflictTypes);
    conflictTypes.emplace_back(PRINT_PARAM_TYPE_PAGE_SIZE);
    printCupsClient.DumpCupsConflicts(mapParams, PRINT_PARAM_TYPE_PAGE_SIZE, conflictTypes);

    mapParams.emplace(PRINT_PARAM_TYPE_QUALITY, "Normal");
    ret = printCupsClient.CheckOptionConflicts(nullptr, mapParams, PRINT_PARAM_TYPE_PAGE_SIZE, conflictTypes);
    EXPECT_EQ(ret, 0);
}

}  // namespace Print
}  // namespace OHOS