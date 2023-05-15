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
#include "napi/native_api.h"
#include "print_job.h"
#include "print_page_size.h"

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
 * @tc.name: PrintJobTest_0001
 * @tc.desc: Verify the Setfile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    std::vector<uint32_t> fdList = {1, 2};
    std::vector<uint32_t> getFdList;
    job.SetFdList(fdList);
    job.GetFdList(getFdList);
}

/**
 * @tc.name: PrintJobTest_0002
 * @tc.desc: Verify the Setfile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    std::vector<uint32_t> fdList = {1, 2};
    std::vector<uint32_t> getFdList;
    EXPECT_EQ(2, getFdList[1]);
}

/**
 * @tc.name: PrintJobTest_0003
 * @tc.desc: Verify the Setfile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::vector<uint32_t> getFdList;
    job.SetFdList(fdList);
    job.GetFdList(getFdList);
    EXPECT_EQ(3, getFdList[2]);
}

/**
 * @tc.name: PrintJobTest_0004
 * @tc.desc: Verify the Setfile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    std::vector<uint32_t> fdList = {1, 2, 3, 4};
    std::vector<uint32_t> getFdList;
    job.SetFdList(fdList);
    job.GetFdList(getFdList);
    EXPECT_EQ(4, getFdList[3]);
}

/**
 * @tc.name: PrintJobTest_0005
 * @tc.desc: Verify the SetJobId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobId("10010");
    EXPECT_EQ("10010", job.GetJobId());
}

/**
 * @tc.name: PrintJobTest_006
 * @tc.desc: Verify the SetJobId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobId("abs1711");
    EXPECT_EQ("abs1711", job.GetJobId());
}

/**
 * @tc.name: PrintJobTest_007
 * @tc.desc: Verify the SetJobId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobId("*123#$%");
    EXPECT_EQ("*123#$%", job.GetJobId());
}

/**
 * @tc.name: PrintJobTest_008
 * @tc.desc: Verify the SetJobId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobId("");
    EXPECT_EQ("", job.GetJobId());
}

/**
 * @tc.name: PrintJobTest_0009
 * @tc.desc: Verify the SetPrinterId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetPrinterId("20221104");
    EXPECT_EQ("20221104", job.GetPrinterId());
}

/**
 * @tc.name: PrintJobTest_0010
 * @tc.desc: Verify the SetPrinterId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetPrinterId("abs1711");
    EXPECT_EQ("abs1711", job.GetPrinterId());
}

/**
 * @tc.name: PrintJobTest_0011
 * @tc.desc: Verify the SetPrinterId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetPrinterId("*123#$%");
    EXPECT_EQ("*123#$%", job.GetPrinterId());
}

/**
 * @tc.name: PrintJobTest_0011
 * @tc.desc: Verify the SetPrinterId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetPrinterId("/123");
    EXPECT_EQ("/123", job.GetPrinterId());
}

/**
 * @tc.name: PrintJobTest_0013
 * @tc.desc: Verify the SetJobState function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    EXPECT_EQ(1, job.GetJobState());
}

/**
 * @tc.name: PrintJobTest_0014
 * @tc.desc: Verify the SetJobState function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(0);
    EXPECT_EQ(0, job.GetJobState());
}

/**
 * @tc.name: PrintJobTest_0015
 * @tc.desc: Verify the SetJobState function with illegal printstate number.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(10);
    EXPECT_EQ(0, job.GetJobState());
}

/**
 * @tc.name: PrintJobTest_0016
 * @tc.desc: Verify the SetJobState function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0016, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(3);
    EXPECT_EQ(3, job.GetJobState());
}

/**
 * @tc.name: PrintJobTest_0017
 * @tc.desc: Verify the SetSubState function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(4);
    job.SetSubState(2);
    EXPECT_EQ(2, job.GetSubState());
}

/**
 * @tc.name: PrintJobTest_0018
 * @tc.desc: Verify the SetSubState function with illegal param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0018, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(4);
    job.SetSubState(5);
    EXPECT_EQ(17, job.GetSubState());
}

/**
 * @tc.name: PrintJobTest_0019
 * @tc.desc: Verify the SetSubState function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0019, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(3);
    job.SetSubState(5);
    EXPECT_EQ(5, job.GetSubState());
}

/**
 * @tc.name: PrintJobTest_0020
 * @tc.desc: Verify the SetSubState function with illegal param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0020, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetJobState(3);
    job.SetSubState(2);
    EXPECT_EQ(17, job.GetSubState());
}

/**
 * @tc.name: PrintJobTest_0021
 * @tc.desc: Verify the SetCopyNumber function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0021, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetCopyNumber(3);
    EXPECT_EQ(3, job.GetCopyNumber());
}

/**
 * @tc.name: PrintJobTest_0022
 * @tc.desc: Verify the SetCopyNumber function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetCopyNumber(3);
    EXPECT_EQ(3, job.GetCopyNumber());
}

/**
 * @tc.name: PrintJobTest_0023
 * @tc.desc: Verify the SetCopyNumber function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetCopyNumber(001122);
    EXPECT_EQ(001122, job.GetCopyNumber());
}

/**
 * @tc.name: PrintJobTest_0024
 * @tc.desc: Verify the SetCopyNumber function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0024, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetCopyNumber(00000000000000000);
    EXPECT_EQ(00000000000000000, job.GetCopyNumber());
}

/**
 * @tc.name: PrintJobTest_0025
 * @tc.desc: Verify the SetPageRange function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0025, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintRange range;
    OHOS::Print::PrintRange getRange;
    job.SetPageRange(range);
    job.GetPageRange(getRange);
    EXPECT_EQ(0, getRange.GetStartPage());
}

/**
 * @tc.name: PrintJobTest_0026
 * @tc.desc: Verify the SetPageRange function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0026, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintRange range;
    OHOS::Print::PrintRange getRange;
    job.SetPageRange(range);
    job.GetPageRange(getRange);
    EXPECT_EQ(0, getRange.GetEndPage());
}

/**
 * @tc.name: PrintJobTest_0027
 * @tc.desc: Verify the SetIsLandscape function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0027, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetIsLandscape(true);
    EXPECT_EQ(true, job.GetIsLandscape());
}

/**
 * @tc.name: PrintJobTest_0028
 * @tc.desc: Verify the SetIsLandscape function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0028, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetIsLandscape(false);
    EXPECT_EQ(false, job.GetIsLandscape());
}

/**
 * @tc.name: PrintJobTest_0029
 * @tc.desc: Verify the SetColorMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0029, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetColorMode(1);
    EXPECT_EQ(1, job.GetColorMode());
}

/**
 * @tc.name: PrintJobTest_0030
 * @tc.desc: Verify the SetColorMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0030, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetColorMode(0);
    EXPECT_EQ(0, job.GetColorMode());
}

/**
 * @tc.name: PrintJobTest_0031
 * @tc.desc: Verify the SetColorMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0031, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetColorMode(000000000);
    EXPECT_EQ(000000000, job.GetColorMode());
}

/**
 * @tc.name: PrintJobTest_0032
 * @tc.desc: Verify the SetColorMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0032, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetColorMode(2345);
    EXPECT_EQ(2345, job.GetColorMode());
}

/**
 * @tc.name: PrintJobTest_0033
 * @tc.desc: Verify the SetDuplexMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0033, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetDuplexMode(0);
    EXPECT_EQ(0, job.GetDuplexMode());
}

/**
 * @tc.name: PrintJobTest_0034
 * @tc.desc: Verify the SetDuplexMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0034, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetDuplexMode(23);
    EXPECT_EQ(23, job.GetDuplexMode());
}

/**
 * @tc.name: PrintJobTest_0035
 * @tc.desc: Verify the SetDuplexMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0035, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetDuplexMode(11001100);
    EXPECT_EQ(11001100, job.GetDuplexMode());
}

/**
 * @tc.name: PrintJobTest_0036
 * @tc.desc: Verify the SetDuplexMode function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0036, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetDuplexMode(0000000000);
    EXPECT_EQ(0000000000, job.GetDuplexMode());
}

/**
 * @tc.name: PrintJobTest_0037
 * @tc.desc: Verify the SetMargin function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0037, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintMargin margin, getMargin;
    job.SetMargin(margin);
    job.GetMargin(getMargin);
    EXPECT_EQ(0, getMargin.GetBottom());
}

/**
 * @tc.name: PrintJobTest_0038
 * @tc.desc: Verify the SetMargin function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0038, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintMargin margin, getMargin;
    job.SetMargin(margin);
    job.GetMargin(getMargin);
    EXPECT_EQ(0, getMargin.GetLeft());
}

/**
 * @tc.name: PrintJobTest_0039
 * @tc.desc: Verify the SetMargin function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0039, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintMargin margin, getMargin;
    job.SetMargin(margin);
    job.GetMargin(getMargin);
    EXPECT_EQ(0, getMargin.GetRight());
}

/**
 * @tc.name: PrintJobTest_0040
 * @tc.desc: Verify the SetMargin function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0040, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintMargin margin, getMargin;
    job.SetMargin(margin);
    job.GetMargin(getMargin);
    EXPECT_EQ(0, getMargin.GetTop());
}

/**
 * @tc.name: PrintJobTest_0041
 * @tc.desc: Verify the SetOption function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0041, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetOption("option!");
    EXPECT_EQ("option!", job.GetOption());
}

/**
 * @tc.name: PrintJobTest_0042
 * @tc.desc: Verify the SetOption function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0042, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetOption("%^&");
    EXPECT_EQ("%^&", job.GetOption());
}

/**
 * @tc.name: PrintJobTest_0043
 * @tc.desc: Verify the SetOption function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0043, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetOption("*/526dfg");
    EXPECT_EQ("*/526dfg", job.GetOption());
}

/**
 * @tc.name: PrintJobTest_0044
 * @tc.desc: Verify the SetOption function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0044, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    job.SetOption("@#$56");
    EXPECT_EQ("@#$56", job.GetOption());
}

/**
 * @tc.name: PrintJobTest_0045
 * @tc.desc: Verify the SetPreview function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0045, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.SetPreview(preview);
    job.GetPreview(getPreview);
    EXPECT_EQ(preview.GetResult(), getPreview.GetResult());
}

/**
 * @tc.name: PrintJobTest_0046
 * @tc.desc: Verify the SetPreview function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0046, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.SetPreview(preview);
    job.GetPreview(getPreview);
    EXPECT_EQ(0xFFFFFFFF, getPreview.GetResult());
}

/**
 * @tc.name: PrintJobTest_0046
 * @tc.desc: Verify the UpdateParams function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0047, TestSize.Level1)
{
    OHOS::Print::PrintJob job, jobInfo;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.UpdateParams(jobInfo);
    EXPECT_EQ("", job.GetJobId());
}

/**
 * @tc.name: PrintJobTest_0048
 * @tc.desc: Verify the UpdateParams function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0048, TestSize.Level1)
{
    OHOS::Print::PrintJob job, jobInfo;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.UpdateParams(jobInfo);
    EXPECT_EQ("", job.GetPrinterId());
}

/**
 * @tc.name: PrintJobTest_0049
 * @tc.desc: Verify the UpdateParams function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0049, TestSize.Level1)
{
    OHOS::Print::PrintJob job, jobInfo;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.UpdateParams(jobInfo);
    EXPECT_EQ(0, job.GetJobState());
}

/**
 * @tc.name: PrintJobTest_0050
 * @tc.desc: Verify the UpdateParams function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0050, TestSize.Level1)
{
    OHOS::Print::PrintJob job, jobInfo;
    OHOS::Print::PrintPreviewAttribute preview, getPreview;
    job.UpdateParams(jobInfo);
    EXPECT_EQ(17, job.GetSubState());
}

/**
 * @tc.name: PrintJobTest_0051
 * @tc.desc: Verify the UpdateParams function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobTest, PrintJobTest_0051, TestSize.Level1)
{
    OHOS::Print::PrintJob job;
    OHOS::Print::PrintJob(job_);
    OHOS::Print::PrintJob jobValue = job;
    PrintPageSize pagesize, getPagesize;
    napi_env env = nullptr;
    job.SetIsSequential(true);
    job.SetPageSize(pagesize);
    job.GetPageSize(getPagesize);
    job.ToJsObject(env);
    job.Dump();
}
} // namespace Print
} // namespace OHOS