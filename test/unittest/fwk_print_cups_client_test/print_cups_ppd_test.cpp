/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <cups/ppd.h>
#include <cups/ppd-private.h>
#include "print_cups_ppd.h"
#include "printer_capability.h"
#include "print_log.h"
#include "print_json_util.h"
#include <fstream>
#include <sys/stat.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

static const std::string TEST_PPD_DIR = "/data/service/el1/public/print_service/test_ppd";

class PrintCupsPpdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string CreateTestPpdFile(const std::string &content);
    void RemoveTestPpdFile(const std::string &filePath);
};

void PrintCupsPpdTest::SetUpTestCase(void)
{
    system(("mkdir -p " + TEST_PPD_DIR).c_str());
}

void PrintCupsPpdTest::TearDownTestCase(void)
{
    system(("rm -rf " + TEST_PPD_DIR).c_str());
}

void PrintCupsPpdTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCupsPpdTest_%{public}d", ++testNo);
}

void PrintCupsPpdTest::TearDown(void)
{}

std::string PrintCupsPpdTest::CreateTestPpdFile(const std::string &content)
{
    std::string filePath = TEST_PPD_DIR + "/test_" + std::to_string(std::rand()) + ".ppd";
    std::ofstream file(filePath);
    if (file.is_open()) {
        file << content;
        file.close();
        return filePath;
    }
    return "";
}

void PrintCupsPpdTest::RemoveTestPpdFile(const std::string &filePath)
{
    if (!filePath.empty()) {
        remove(filePath.c_str());
    }
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_001
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with invalid file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_001, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string invalidPath = "/invalid/path/to/nonexistent.ppd";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, invalidPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_002
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with empty file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_002, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string emptyPath = "";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, emptyPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

/**
 * @tc.name: MarkPpdOption_001
 * @tc.desc: MarkPpdOption with null ppd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_001, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: CheckPpdConflicts_001
 * @tc.desc: CheckPpdConflicts with null ppd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_001, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    std::vector<std::string> conflictTypes;
    int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4, conflictTypes);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(conflictTypes.empty());
}

}  // namespace Print
}  // namespace OHOS
