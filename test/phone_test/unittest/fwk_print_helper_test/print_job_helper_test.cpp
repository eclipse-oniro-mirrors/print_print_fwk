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
#include <gmock/gmock.h>
#include <sys/stat.h>
#include <unistd.h>
#define private public
#define protected public
#include "print_job_helper.h"
#undef protected
#undef private
#include "mock_application_context.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintJobHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintJobHelperTest::SetUpTestCase(void)
{}

void PrintJobHelperTest::TearDownTestCase(void)
{}

void PrintJobHelperTest::SetUp(void)
{}

void PrintJobHelperTest::TearDown(void)
{}

/**
 * @tc.name: ConvertParamsToPrintJob_Test
 * @tc.desc: Verify the ConvertParamsToPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, ConvertParamsToPrintJob_Test, TestSize.Level2)
{
    PrintJobParams params;
    auto result = PrintJobHelper::ConvertParamsToPrintJob(params);
    params.printerId = "printerId";
    EXPECT_EQ(result, nullptr);
    params.docFlavor = 1;
    params.binaryData = (uint8_t *)"text data";
    params.dataLength = 0;
    result = PrintJobHelper::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.dataLength = 10;
    result = PrintJobHelper::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.docFlavor = 0;
    params.printFdList = std::vector<uint32_t>();
    result = PrintJobHelper::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.printFdList.emplace_back(0);
    result = PrintJobHelper::ConvertParamsToPrintJob(params);
    EXPECT_NE(result, nullptr);

    params.hasMargin = true;
    params.hasPreview = true;
    params.isSequential = 0;
    result = PrintJobHelper::ConvertParamsToPrintJob(params);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetDocumentFormatToString_Test
 * @tc.desc: Verify the GetDocumentFormatToString function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, GetDocumentFormatToString_Test, TestSize.Level2)
{
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(0), "application/octet-stream");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(1), "image/jpeg");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(2), "application/pdf");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(3), "application/postscript");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(4), "text/plain");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(5), "application/vnd.cups-raw");
    EXPECT_EQ(PrintJobHelper::GetDocumentFormatToString(6), "application/octet-stream");
}

/**
 * @tc.name: CreateTempFileWithData_Test
 * @tc.desc: Verify the CreateTempFileWithData function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, CreateTempFileWithData_Test, TestSize.Level2)
{
    void *data = (uint8_t *)"test data";
    size_t length = 10;
    std::string tmpPath;
    int fd = PrintJobHelper::CreateTempFileWithData(data, length, tmpPath);
    EXPECT_EQ(fd, -1);
}

/**
 * @tc.name: CreateTempFileWithData_FilesDirEmpty
 * @tc.desc: Verify the CreateTempFileWithData function when appContext != nullptr but filesDir is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, CreateTempFileWithData_FilesDirEmpty, TestSize.Level2)
{
    auto mockContext = std::make_shared<AbilityRuntime::MockApplicationContext>();
    AbilityRuntime::Context::applicationContext_ = mockContext;
    EXPECT_CALL(*mockContext, GetFilesDir()).WillOnce(Return(""));
    void *data = (uint8_t*)"test data";
    size_t length = 10;
    std::string tmpPath;
    int fd = PrintJobHelper::CreateTempFileWithData(data, length, tmpPath);
    EXPECT_EQ(fd, -1);
    EXPECT_TRUE(tmpPath.empty());
    AbilityRuntime::Context::applicationContext_ = nullptr;
}

/**
 * @tc.name: CreateTempFileWithData_InvalidPath
 * @tc.desc: Verify the CreateTempFileWithData function when filesDir is a non-existent path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, CreateTempFileWithData_InvalidPath, TestSize.Level2)
{
    auto mockContext = std::make_shared<AbilityRuntime::MockApplicationContext>();
    AbilityRuntime::Context::applicationContext_ = mockContext;
    EXPECT_CALL(*mockContext, GetFilesDir()).WillOnce(Return("/nonexistent_dir_for_test"));
    void *data = (uint8_t*)"test data";
    size_t length = 10;
    std::string tmpPath;
    int fd = PrintJobHelper::CreateTempFileWithData(data, length, tmpPath);
    EXPECT_EQ(fd, -1);
    AbilityRuntime::Context::applicationContext_ = nullptr;
}

/**
 * @tc.name: CreateTempFileWithData_Success
 * @tc.desc: Verify the CreateTempFileWithData function success path with valid writable filesDir.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, CreateTempFileWithData_Success, TestSize.Level2)
{
    std::string testDir = "/data/local/tmp/print_test";
    mkdir(testDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    auto mockContext = std::make_shared<AbilityRuntime::MockApplicationContext>();
    AbilityRuntime::Context::applicationContext_ = mockContext;
    EXPECT_CALL(*mockContext, GetFilesDir()).WillOnce(Return(testDir));
    void *data = (uint8_t*)"test data";
    size_t length = 10;
    std::string tmpPath;
    int fd = PrintJobHelper::CreateTempFileWithData(data, length, tmpPath);
    EXPECT_GE(fd, 0);
    EXPECT_FALSE(tmpPath.empty());
    if (fd >= 0) {
        close(fd);
    }
    if (!tmpPath.empty()) {
        std::remove(tmpPath.c_str());
    }
    AbilityRuntime::Context::applicationContext_ = nullptr;
}

/**
 * @tc.name: GenerateTempFilePath_Test
 * @tc.desc: Verify the GenerateTempFilePath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, GenerateTempFilePath_Test, TestSize.Level2)
{
    std::string result = PrintJobHelper::GenerateTempFilePath("/data");
    EXPECT_TRUE(result.find("/data") == 0);
    EXPECT_TRUE(result.find("/job_") != std::string::npos);

    result = PrintJobHelper::GenerateTempFilePath("");
    EXPECT_TRUE(result.empty());

    result = PrintJobHelper::GenerateTempFilePath("/nonexistent_dir");
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: SetOptionInPrintJob_Test
 * @tc.desc: Verify the SetOptionInPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintJobHelperTest, SetOptionInPrintJob_Test, TestSize.Level2)
{
    PrintJobParams params;
    auto printJob = std::make_shared<PrintJob>();

    params.jobName = "test_job";
    params.docFlavor = 0;
    params.documentFormat = 0;
    params.printQuality = 0;
    params.mediaType = "stationery";
    params.isBorderless = 0;
    params.isAutoRotate = 0;
    params.isReverse = 0;
    params.isCollate = 0;
    params.cupsOptions = "test_cupsOptions";

    PrintJobHelper::SetOptionInPrintJob(params, printJob);
    std::string option = printJob->GetOption();
    Json::Value json;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(option, json));
    EXPECT_TRUE(json.isMember("jobName"));
    EXPECT_TRUE(json.isMember("jobDesArr"));
    EXPECT_TRUE(json.isMember("isDocument"));
    EXPECT_TRUE(json.isMember("printQuality"));
    EXPECT_TRUE(json.isMember("mediaType"));
    EXPECT_TRUE(json.isMember("borderless"));
    EXPECT_TRUE(json.isMember("isAutoRotate"));
    EXPECT_TRUE(json.isMember("isReverse"));
    EXPECT_TRUE(json.isMember("isCollate"));
    EXPECT_TRUE(json.isMember("cupsOptions"));

    EXPECT_EQ(json["jobName"].asString(), "test_job");
    EXPECT_EQ(json["jobDesArr"].size(), 3);
    EXPECT_EQ(json["isDocument"].asBool(), true);
    EXPECT_EQ(json["printQuality"].asInt(), 4);
    EXPECT_EQ(json["mediaType"].asString(), "stationery");
    EXPECT_EQ(json["borderless"].asBool(), false);
    EXPECT_EQ(json["isAutoRotate"].asBool(), false);
    EXPECT_EQ(json["isReverse"].asBool(), false);
    EXPECT_EQ(json["isCollate"].asBool(), false);
    EXPECT_EQ(json["cupsOptions"].asString(), "test_cupsOptions");
}

/**
 * @tc.name: SetOptionInPrintJob_002
 * @tc.desc: Verify SetOptionInPrintJob with printQuality out of range.
 * @tc.type: FUNC
 */
HWTEST_F(PrintJobHelperTest, SetOptionInPrintJob_002, TestSize.Level2)
{
    PrintJobParams params;
    auto printJob = std::make_shared<PrintJob>();

    params.printQuality = 100;  // Out of range
    PrintJobHelper::SetOptionInPrintJob(params, printJob);
    std::string option = printJob->GetOption();
    Json::Value json;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(option, json));
    EXPECT_EQ(json["printQuality"].asInt(), 4);  // Should be normalized to PRINT_QUALITY_NORMAL
}

/**
 * @tc.name: SetOptionInPrintJob_003
 * @tc.desc: Verify SetOptionInPrintJob with negative printQuality.
 * @tc.type: FUNC
 */
HWTEST_F(PrintJobHelperTest, SetOptionInPrintJob_003, TestSize.Level2)
{
    PrintJobParams params;
    auto printJob = std::make_shared<PrintJob>();

    params.printQuality = -10;  // Negative value
    PrintJobHelper::SetOptionInPrintJob(params, printJob);
    std::string option = printJob->GetOption();
    Json::Value json;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(option, json));
    EXPECT_EQ(json["printQuality"].asInt(), 4);  // Should be normalized to PRINT_QUALITY_NORMAL
}

/**
 * @tc.name: SetOptionInPrintJob_004
 * @tc.desc: Verify SetOptionInPrintJob with PRINT_FILE_DESCRIPTOR docFlavor.
 * @tc.type: FUNC
 */
HWTEST_F(PrintJobHelperTest, SetOptionInPrintJob_004, TestSize.Level2)
{
    PrintJobParams params;
    auto printJob = std::make_shared<PrintJob>();

    params.docFlavor = PRINT_FILE_DESCRIPTOR;
    PrintJobHelper::SetOptionInPrintJob(params, printJob);
    std::string option = printJob->GetOption();
    Json::Value json;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(option, json));
    EXPECT_TRUE(json.isMember("isDocument"));
    EXPECT_EQ(json["isDocument"].asBool(), true);
}

}  // namespace Print
}  // namespace OHOS