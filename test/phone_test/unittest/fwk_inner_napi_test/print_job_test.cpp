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
};

void PrintJobTest::SetUpTestCase(void)
{}

void PrintJobTest::TearDownTestCase(void)
{}

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

/**
 * @tc.name: PrintJobTest_NumberUpArgs_001
 * @tc.desc: Verify the SetNumberUpArgs and GetNumberUpArgs function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_001, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    args.numberUp = 4;
    args.numberUpLayout = NUMBER_UP_LAYOUT_TBLR;
    args.mirror = 1;
    args.pageBorder = 1;

    job.SetNumberUpArgs(args);
    NumberUpArgs result = job.GetNumberUpArgs();
    EXPECT_EQ(result.numberUp, 4);
    EXPECT_EQ(result.numberUpLayout, NUMBER_UP_LAYOUT_TBLR);
    EXPECT_EQ(result.mirror, 1);
    EXPECT_EQ(result.pageBorder, 1);
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_002
 * @tc.desc: Verify the SetNumberUpArgs with valid numberUp values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_002, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    // Test valid number-up values: 1, 2, 4, 6, 9, 16
    uint32_t validNumberUps[] = {1, 2, 4, 6, 9, 16};
    for (auto numberUp : validNumberUps) {
        args.numberUp = numberUp;
        job.SetNumberUpArgs(args);
        EXPECT_EQ(job.GetNumberUpArgs().numberUp, numberUp);
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_Marshalling_001
 * @tc.desc: Verify the Marshalling and Unmarshalling for NumberUpArgs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_Marshalling_001, TestSize.Level1)
{
    PrintJob job;
    Parcel parcel;
    NumberUpArgs args;
    args.numberUp = 4;
    args.numberUpLayout = NUMBER_UP_LAYOUT_TBLR;
    args.mirror = 1;
    args.pageBorder = 1;
    job.SetNumberUpArgs(args);
    job.SetJobId("job-001");
    job.SetPrinterId("printer-001");

    EXPECT_TRUE(job.Marshalling(parcel));

    auto unmarshalledJob = PrintJob::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledJob, nullptr);
    NumberUpArgs result = unmarshalledJob->GetNumberUpArgs();
    EXPECT_EQ(result.numberUp, 4);
    EXPECT_EQ(result.numberUpLayout, NUMBER_UP_LAYOUT_TBLR);
    EXPECT_EQ(result.mirror, 1);
    EXPECT_EQ(result.pageBorder, 1);
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_UpdateParams_001
 * @tc.desc: Verify the UpdateParams for NumberUpArgs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_UpdateParams_001, TestSize.Level1)
{
    PrintJob job;
    PrintJob updateJob;

    NumberUpArgs args;
    args.numberUp = 9;
    args.numberUpLayout = NUMBER_UP_LAYOUT_BTLR;
    args.mirror = 1;
    args.pageBorder = 1;
    job.SetNumberUpArgs(args);
    job.SetJobId("job-001");
    job.SetPrinterId("printer-001");
    job.SetCopyNumber(2);
    job.SetColorMode(1);

    updateJob.UpdateParams(job);
    NumberUpArgs result = updateJob.GetNumberUpArgs();
    EXPECT_EQ(result.numberUp, 9);
    EXPECT_EQ(result.numberUpLayout, NUMBER_UP_LAYOUT_BTLR);
    EXPECT_EQ(result.mirror, 1);
    EXPECT_EQ(result.pageBorder, 1);
    EXPECT_EQ(updateJob.GetJobId(), "job-001");
    EXPECT_EQ(updateJob.GetCopyNumber(), 2);
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_CopyConstructor_001
 * @tc.desc: Verify the copy constructor for NumberUpArgs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_CopyConstructor_001, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    args.numberUp = 6;
    args.numberUpLayout = NUMBER_UP_LAYOUT_RLBT;
    args.mirror = 1;
    args.pageBorder = 1;
    job.SetNumberUpArgs(args);
    job.SetJobId("job-copy-test");

    PrintJob copyJob(job);
    NumberUpArgs result = copyJob.GetNumberUpArgs();
    EXPECT_EQ(result.numberUp, 6);
    EXPECT_EQ(result.numberUpLayout, NUMBER_UP_LAYOUT_RLBT);
    EXPECT_EQ(result.mirror, 1);
    EXPECT_EQ(result.pageBorder, 1);
    EXPECT_EQ(copyJob.GetJobId(), "job-copy-test");
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_AssignmentOperator_001
 * @tc.desc: Verify the assignment operator for NumberUpArgs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_AssignmentOperator_001, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    args.numberUp = 16;
    args.numberUpLayout = NUMBER_UP_LAYOUT_BTRL;
    args.mirror = 1;
    args.pageBorder = 1;
    job.SetNumberUpArgs(args);
    job.SetJobId("job-assign-test");

    PrintJob assignJob = job;
    NumberUpArgs result = assignJob.GetNumberUpArgs();
    EXPECT_EQ(result.numberUp, 16);
    EXPECT_EQ(result.numberUpLayout, NUMBER_UP_LAYOUT_BTRL);
    EXPECT_EQ(result.mirror, 1);
    EXPECT_EQ(result.pageBorder, 1);
    EXPECT_EQ(assignJob.GetJobId(), "job-assign-test");
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_003
 * @tc.desc: Verify all valid numberUpLayout values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_003, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    // Data table: test all valid numberUpLayout values
    uint32_t validLayouts[] = {
        NUMBER_UP_LAYOUT_LRTB, NUMBER_UP_LAYOUT_RLTB,
        NUMBER_UP_LAYOUT_TBLR, NUMBER_UP_LAYOUT_TBRL,
        NUMBER_UP_LAYOUT_LRBT, NUMBER_UP_LAYOUT_RLBT,
        NUMBER_UP_LAYOUT_BTLR, NUMBER_UP_LAYOUT_BTRL
    };
    for (auto layout : validLayouts) {
        args.numberUpLayout = layout;
        job.SetNumberUpArgs(args);
        EXPECT_EQ(job.GetNumberUpArgs().numberUpLayout, layout);
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_004
 * @tc.desc: Verify mirror values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_004, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    // Data table: test mirror values
    uint32_t validMirrors[] = {PRINT_MIRROR_DISABLED, PRINT_MIRROR_ENABLED};
    for (auto mirror : validMirrors) {
        args.mirror = mirror;
        job.SetNumberUpArgs(args);
        EXPECT_EQ(job.GetNumberUpArgs().mirror, mirror);
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_005
 * @tc.desc: Verify pageBorder values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_005, TestSize.Level1)
{
    PrintJob job;
    NumberUpArgs args;
    // Data table: test pageBorder values
    uint32_t validBorders[] = {
        PRINT_PAGE_BORDER_NONE,
        PRINT_PAGE_BORDER_SINGLE,
        PRINT_PAGE_BORDER_DOUBLE
    };
    for (auto border : validBorders) {
        args.pageBorder = border;
        job.SetNumberUpArgs(args);
        EXPECT_EQ(job.GetNumberUpArgs().pageBorder, border);
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_006
 * @tc.desc: Verify combined NumberUpArgs values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_006, TestSize.Level1)
{
    // Data table: combined test cases
    struct TestCase {
        uint32_t numberUp;
        uint32_t numberUpLayout;
        uint32_t mirror;
        uint32_t pageBorder;
    };
    
    std::vector<TestCase> testCases = {
        {1, NUMBER_UP_LAYOUT_LRTB, PRINT_MIRROR_DISABLED, PRINT_PAGE_BORDER_NONE},
        {2, NUMBER_UP_LAYOUT_RLTB, PRINT_MIRROR_ENABLED, PRINT_PAGE_BORDER_SINGLE},
        {4, NUMBER_UP_LAYOUT_TBLR, PRINT_MIRROR_DISABLED, PRINT_PAGE_BORDER_DOUBLE},
        {6, NUMBER_UP_LAYOUT_TBRL, PRINT_MIRROR_ENABLED, PRINT_PAGE_BORDER_NONE},
        {9, NUMBER_UP_LAYOUT_LRBT, PRINT_MIRROR_DISABLED, PRINT_PAGE_BORDER_SINGLE},
        {16, NUMBER_UP_LAYOUT_BTRL, PRINT_MIRROR_ENABLED, PRINT_PAGE_BORDER_DOUBLE}
    };
    
    int index = 0;
    for (const auto& tc : testCases) {
        PrintJob job;
        NumberUpArgs args;
        args.numberUp = tc.numberUp;
        args.numberUpLayout = tc.numberUpLayout;
        args.mirror = tc.mirror;
        args.pageBorder = tc.pageBorder;
        job.SetNumberUpArgs(args);
        
        NumberUpArgs result = job.GetNumberUpArgs();
        EXPECT_EQ(result.numberUp, tc.numberUp) << "Failed at index " << index;
        EXPECT_EQ(result.numberUpLayout, tc.numberUpLayout) << "Failed at index " << index;
        EXPECT_EQ(result.mirror, tc.mirror) << "Failed at index " << index;
        EXPECT_EQ(result.pageBorder, tc.pageBorder) << "Failed at index " << index;
        index++;
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_Marshalling_002
 * @tc.desc: Verify Marshalling with all valid numberUp values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_Marshalling_002, TestSize.Level1)
{
    // Data table: test marshalling with all valid numberUp values
    uint32_t validNumberUps[] = {1, 2, 4, 6, 9, 16};
    
    for (auto numberUp : validNumberUps) {
        PrintJob job;
        Parcel parcel;
        NumberUpArgs args;
        args.numberUp = numberUp;
        args.numberUpLayout = NUMBER_UP_LAYOUT_LRTB;
        args.mirror = 0;
        args.pageBorder = 0;
        job.SetNumberUpArgs(args);
        job.SetJobId("job-" + std::to_string(numberUp));
        job.SetPrinterId("printer-001");

        EXPECT_TRUE(job.Marshalling(parcel));

        auto unmarshalledJob = PrintJob::Unmarshalling(parcel);
        ASSERT_NE(unmarshalledJob, nullptr);
        NumberUpArgs result = unmarshalledJob->GetNumberUpArgs();
        EXPECT_EQ(result.numberUp, numberUp);
    }
}

/**
 * @tc.name: PrintJobTest_NumberUpArgs_Marshalling_003
 * @tc.desc: Verify Marshalling with all numberUpLayout values (data table).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_NumberUpArgs_Marshalling_003, TestSize.Level1)
{
    // Data table: test marshalling with all numberUpLayout values
    uint32_t layouts[] = {
        NUMBER_UP_LAYOUT_LRTB, NUMBER_UP_LAYOUT_RLTB,
        NUMBER_UP_LAYOUT_TBLR, NUMBER_UP_LAYOUT_TBRL,
        NUMBER_UP_LAYOUT_LRBT, NUMBER_UP_LAYOUT_RLBT,
        NUMBER_UP_LAYOUT_BTLR, NUMBER_UP_LAYOUT_BTRL
    };
    
    for (auto layout : layouts) {
        PrintJob job;
        Parcel parcel;
        NumberUpArgs args;
        args.numberUp = 4;
        args.numberUpLayout = layout;
        args.mirror = 0;
        args.pageBorder = 0;
        job.SetNumberUpArgs(args);
        job.SetJobId("job-layout-" + std::to_string(layout));
        job.SetPrinterId("printer-001");

        EXPECT_TRUE(job.Marshalling(parcel));

        auto unmarshalledJob = PrintJob::Unmarshalling(parcel);
        ASSERT_NE(unmarshalledJob, nullptr);
        NumberUpArgs result = unmarshalledJob->GetNumberUpArgs();
        EXPECT_EQ(result.numberUpLayout, layout);
    }
}

}  // namespace Print
}  // namespace OHOS
