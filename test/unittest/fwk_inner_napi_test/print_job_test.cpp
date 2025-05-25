/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "print_job.h"
#undef private
#include "print_page_size.h"
#include "print_range.h"
#define private public
#include "print_margin.h"
#undef private
#define private public
#include "print_preview_attribute.h"
#undef private
#include "print_log.h"
#include "print_constant.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintJobTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintJobTest::SetUpTestCase(void) {}

void PrintJobTest::TearDownTestCase(void) {}

void PrintJobTest::SetUp(void) {}

void PrintJobTest::TearDown(void) {}

/**
 * @tc.name: PrintJobTest_0002_NeedRename
 * @tc.desc: Verify the PrintExtensionInfo function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0002_NeedRename, TestSize.Level1)
{
    PrintJob job;
    OHOS::Print::PrintPreviewAttribute attr;
    OHOS::Print::PrintMargin margin;

    attr.SetResult(1);
    EXPECT_EQ(attr.hasResult_, true);
    EXPECT_EQ(attr.result_, 1);

    job.SetPreview(attr);
    EXPECT_EQ(job.hasPreview_, true);

    margin.SetBottom(1);
    EXPECT_EQ(margin.hasBottom_, true);
    EXPECT_EQ(margin.bottom_, 1);

    job.SetMargin(margin);
    EXPECT_EQ(job.hasMargin_, true);

    job.SetOption("option");
    EXPECT_EQ(job.hasOption_, true);
    EXPECT_EQ(job.option_, "option");

    job.Dump();
}

/**
 * @tc.name: PrintJobTest_0003_NeedRename
 * @tc.desc: Verify the SetExtensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0003_NeedRename, TestSize.Level1)
{
    PrintJob job;
    std::vector<uint32_t> files = {1, 2, 3};
    std::vector<uint32_t> getFiles;
    job.SetFdList(files);
    job.GetFdList(getFiles);
    EXPECT_EQ(files.size(), getFiles.size());
    for (size_t index = 0; index < files.size(); index++) {
        EXPECT_EQ(files[index], getFiles[index]);
    }
}

/**
 * @tc.name: DupFdlist_ShouldReturnSameFd
 * @tc.desc: Verify the DupFdlist function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, DupFdlist_WhenBadfd_ShouldReturnSameFd, TestSize.Level1)
{
    PrintJob job;
    std::vector<uint32_t> fdList = { 997, 998, 999 };
    std::vector<uint32_t> dupFdList;
    job.SetFdList(fdList);
    job.DupFdList(dupFdList);
    EXPECT_EQ(fdList.size(), dupFdList.size());
    for (size_t index = 0; index < fdList.size(); index++) {
        EXPECT_EQ(fdList[index], dupFdList[index]);
    }
}

/**
 * @tc.name: PrintJobTest_0004_NeedRename
 * @tc.desc: Verify the SetVendorId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0004_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobId("jobid-1234");
    EXPECT_EQ(job.GetJobId(), "jobid-1234");
}

/**
 * @tc.name: PrintJobTest_0005_NeedRename
 * @tc.desc: Verify the SetVendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0005_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetPrinterId("printid-1234");
    EXPECT_EQ(job.GetPrinterId(), "printid-1234");
}

/**
 * @tc.name: PrintJobTest_0006_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0006_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_BLOCKED);
    EXPECT_EQ(job.GetJobState(), PRINT_JOB_BLOCKED);
}

/**
 * @tc.name: PrintJobTest_0007_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0007_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_UNKNOWN + 1);
    EXPECT_EQ(job.GetJobState(), PRINT_JOB_PREPARED);
}

/**
 * @tc.name: PrintJobTest_0008_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0008_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_COMPLETED);
    job.SetSubState(PRINT_JOB_COMPLETED_FILE_CORRUPT);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_COMPLETED_FILE_CORRUPT);
}

/**
 * @tc.name: PrintJobTest_0009_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0009_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_COMPLETED);
    job.SetSubState(PRINT_JOB_BLOCKED_OFFLINE);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_BLOCKED_OFFLINE);
}

/**
 * @tc.name: PrintJobTest_0010_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0010_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_BLOCKED);
    job.SetSubState(PRINT_JOB_BLOCKED_OFFLINE);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_BLOCKED_OFFLINE);
}

/**
 * @tc.name: PrintJobTest_0011_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0011_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_BLOCKED);
    job.SetSubState(PRINT_JOB_COMPLETED_FILE_CORRUPT);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_COMPLETED_FILE_CORRUPT);
}

/**
 * @tc.name: PrintJobTest_0012_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0012_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_RUNNING);
    job.SetSubState(PRINT_JOB_COMPLETED_FILE_CORRUPT);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_COMPLETED_FILE_CORRUPT);
}

/**
 * @tc.name: PrintJobTest_0013_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0013_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetJobState(PRINT_JOB_RUNNING);
    job.SetSubState(PRINT_JOB_BLOCKED_OFFLINE);
    EXPECT_EQ(job.GetSubState(), PRINT_JOB_BLOCKED_OFFLINE);
}

/**
 * @tc.name: PrintJobTest_0014_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0014_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetCopyNumber(2);
    EXPECT_EQ(job.GetCopyNumber(), 2);
}

/**
 * @tc.name: PrintJobTest_0015_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0015_NeedRename, TestSize.Level1)
{
    PrintJob job;
    OHOS::Print::PrintRange range, getRange;
    range.SetStartPage(1);
    job.SetPageRange(range);
    job.GetPageRange(getRange);
    EXPECT_EQ(getRange.GetStartPage(), 1);
}

/**
 * @tc.name: PrintJobTest_0016_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0016_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetIsSequential(true);
    EXPECT_EQ(job.GetIsSequential(), true);
}

/**
 * @tc.name: PrintJobTest_0017_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0017_NeedRename, TestSize.Level1)
{
    PrintJob job;
    OHOS::Print::PrintPageSize pageSize, getPageSize;
    pageSize.SetId("pgid-1234");
    job.SetPageSize(pageSize);
    job.GetPageSize(getPageSize);
    EXPECT_EQ(getPageSize.GetId(), "pgid-1234");
}

/**
 * @tc.name: PrintJobTest_0018_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0018_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetIsLandscape(true);
    EXPECT_EQ(job.GetIsLandscape(), true);
}

/**
 * @tc.name: PrintJobTest_0019_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0019_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetColorMode(1);
    EXPECT_EQ(job.GetColorMode(), 1);
}

/**
 * @tc.name: PrintJobTest_0020_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0020_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetDuplexMode(1);
    EXPECT_EQ(job.GetDuplexMode(), 1);
}

/**
 * @tc.name: PrintJobTest_0021_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0021_NeedRename, TestSize.Level1)
{
    PrintJob job, getJob;
    OHOS::Print::PrintMargin margin, getMargin;
    margin.SetBottom(1);
    job.SetMargin(margin);
    job.GetMargin(getMargin);
    EXPECT_EQ(job.HasMargin(), true);
    EXPECT_EQ(getMargin.GetBottom(), 1);
}

/**
 * @tc.name: PrintJobTest_0022_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0022_NeedRename, TestSize.Level1)
{
    PrintJob job;
    job.SetOption("option-123");
    EXPECT_EQ(job.HasOption(), true);
    EXPECT_EQ(job.GetOption(), "option-123");
}

/**
 * @tc.name: PrintJobTest_0023_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0023_NeedRename, TestSize.Level1)
{
    PrintJob job, getJob;
    OHOS::Print::PrintPreviewAttribute attr, getAttr;
    attr.SetResult(1);
    job.SetPreview(attr);
    job.GetPreview(getAttr);
    EXPECT_EQ(job.HasPreview(), true);
    EXPECT_EQ(getAttr.GetResult(), 1);
}

/**
 * @tc.name: PrintJobTest_0024_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0024_NeedRename, TestSize.Level1)
{
    PrintJob job, updateJob;
    job.SetColorMode(1);
    job.SetCopyNumber(1);
    job.SetIsLandscape(true);
    job.SetIsSequential(true);
    job.SetJobId("jobId-123");
    updateJob.UpdateParams(job);
    EXPECT_EQ(updateJob.GetColorMode(), 1);
}

/**
 * @tc.name: PrintJobTest_0025_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0025_NeedRename, TestSize.Level1)
{
    PrintJob job, jobInfo;
    Parcel parcel;

    job.SetIsSequential(true);
    job.Marshalling(parcel);
    EXPECT_EQ(job.GetIsSequential(), true);
}

/**
 * @tc.name: PrintJobTest_0026_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0026_NeedRename, TestSize.Level1)
{
    PrintJob job, jobInfo;
    Parcel parcel;
    OHOS::Print::PrintPreviewAttribute attr;
    OHOS::Print::PrintMargin margin;

    attr.SetResult(1);
    job.SetPreview(attr);
    margin.SetBottom(1);
    job.SetMargin(margin);
    job.SetOption("option");
    job.Marshalling(parcel);
    jobInfo.Unmarshalling(parcel);
    EXPECT_EQ(jobInfo.GetIsSequential(), false);
}

/**
 * @tc.name: PrintJobTest_0027_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0027_NeedRename, TestSize.Level1)
{
    PrintJob job;
    std::vector<uint32_t> files = {1, 2, 3};
    OHOS::Print::PrintRange range;
    OHOS::Print::PrintPageSize pageSize;

    job.SetIsSequential(true);
    PrintJob getJob(job);
    EXPECT_EQ(getJob.GetIsSequential(), true);
}

/**
 * @tc.name: PrintJobTest_0028_NeedRename
 * @tc.desc: Verify the SetVendorName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0028_NeedRename, TestSize.Level1)
{
    PrintJob job;
    std::vector<uint32_t> files = {1, 2, 3};
    OHOS::Print::PrintRange range;
    OHOS::Print::PrintPageSize pageSize;

    job.SetIsSequential(true);
    PrintJob getJob = job;
    EXPECT_EQ(getJob.GetIsSequential(), true);
}
} // namespace Print
} // namespace OHOS
