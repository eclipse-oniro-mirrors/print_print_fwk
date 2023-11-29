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
#include "print_cups_client.h"
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
} // namespace Print
} // namespace OHOS