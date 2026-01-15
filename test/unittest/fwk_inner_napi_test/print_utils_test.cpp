/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applipcable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "iservice_registry.h"
#define private public
#include "print_utils.h"
#undef private
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_job.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"
#include "print_json_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintUtilsTest::SetUpTestCase(void)
{}

void PrintUtilsTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PrintUtilsTest_0001
 * @tc.desc: Verify the toLower function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0001_NeedRename, TestSize.Level2)
{
    std::string testResult = "test";
    std::string result = PrintUtils::ToLower("TEST");
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0002
 * @tc.desc: Verify the getExtensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0002_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext";
    std::string testResult = "";
    std::string result = PrintUtils::GetExtensionId(gid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0003
 * @tc.desc: Verify the getExtensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0003_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext:1234";
    std::string testResult = "com.sample.ext";
    std::string result = PrintUtils::GetExtensionId(gid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0004
 * @tc.desc: Verify the getGlobalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetGlobalId_NotIncludeExtensionId_ReturnWithExtensionId, TestSize.Level2)
{
    std::string id = "com.sample.ext";
    std::string localId = "1234";
    std::string testResult = "com.sample.ext:1234";
    std::string result = PrintUtils::GetGlobalId(id, localId);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0005
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0005_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext";
    std::string id = "com.sample.ext";
    std::string testResult = "";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0006
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0006_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext:1234";
    std::string id = "com.sample.extt";
    std::string testResult = "";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0007
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0007_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext:1234";
    std::string id = "com.sample.ext4";
    std::string testResult = "1234";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_NE(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0008
 * @tc.desc: Verify the encodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0008_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext";
    uint32_t cid = 1;
    std::string testResult = "com.sample.ext:1";
    std::string result = PrintUtils::EncodeExtensionCid(gid, cid);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0009
 * @tc.desc: Verify the decodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0009_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext";
    std::string extensionId = "com.sample.ext";
    uint32_t callbackId;
    EXPECT_FALSE(PrintUtils::DecodeExtensionCid(gid, extensionId, callbackId));
}

/**
 * @tc.name: PrintUtilsTest_0010
 * @tc.desc: Verify the decodeExtensionCid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0010_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext:1";
    std::string extensionId = "com.sample.ext";
    uint32_t testCid = 1;
    uint32_t callbackId = 0;
    EXPECT_TRUE(PrintUtils::DecodeExtensionCid(gid, extensionId, callbackId));
    EXPECT_EQ(testCid, callbackId);
}

/**
 * @tc.name: PrintUtilsTest_0011
 * @tc.desc: Verify the getTaskEventId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0011_NeedRename, TestSize.Level2)
{
    std::string taskId = "1234";
    std::string type = "block";
    std::string testResult = "block-1234";
    std::string result = PrintUtils::GetTaskEventId(taskId, type);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0012
 * @tc.desc: Verify the openFile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0012_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::OpenFile("/error");
    EXPECT_EQ(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0013
 * @tc.desc: Verify the openFile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0013_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::OpenFile("/data/e11");
    EXPECT_EQ(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0014
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0014_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11/data/service/ \
    e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11/data/service/ \
    e11/data/service/e11/data/service/e11/data/service/e11/data/service/e11");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0015
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0015_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11//data/service/e11");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0016
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0016_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::IsPathValid("/data/service/e11");
    EXPECT_NE(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0017
 * @tc.desc: Verify the getIdFromFdPath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0017_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::GetIdFromFdPath("/data/service");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0018
 * @tc.desc: Verify the getIdFromFdPath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0018_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::GetIdFromFdPath("/data/service/e11");
    EXPECT_NE(PRINT_INVALID_ID, result);
}

/**
 * @tc.name: PrintUtilsTest_0019
 * @tc.desc: Verify the getJobStateChar function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0019_NeedRename, TestSize.Level2)
{
    std::string testResult = "PRINT_JOB_PREPARED";
    std::string result = PrintUtils::GetJobStateChar(PRINT_JOB_PREPARED);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0020
 * @tc.desc: Verify the getJobStateChar function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0020_NeedRename, TestSize.Level2)
{
    std::string testResult = "PRINT_JOB_UNKNOWN";
    std::string result = PrintUtils::GetJobStateChar(PRINT_JOB_PREPARED + 100);
    EXPECT_EQ(testResult, result);
}

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0021_NeedRename, TestSize.Level2)
{
    PrintUtils printUtils;
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    AAFwk::Want want;
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    adapterParam->printAttributes.SetCopyNumber(1);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasCopyNumber_, true);
    EXPECT_EQ(adapterParam->printAttributes.copyNumber_, 1);

    adapterParam->printAttributes.SetIsSequential(true);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasSequential_, true);
    EXPECT_EQ(adapterParam->printAttributes.isSequential_, true);

    adapterParam->printAttributes.SetIsLandscape(false);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasLandscape_, true);
    EXPECT_EQ(adapterParam->printAttributes.isLandscape_, false);

    adapterParam->printAttributes.SetDirectionMode(0);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasDirectionMode_, true);
    EXPECT_EQ(adapterParam->printAttributes.directionMode_, 0);

    adapterParam->printAttributes.SetColorMode(0);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasColorMode_, true);
    EXPECT_EQ(adapterParam->printAttributes.colorMode_, 0);

    adapterParam->printAttributes.SetDuplexMode(0);
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasDuplexMode_, true);
    EXPECT_EQ(adapterParam->printAttributes.duplexMode_, 0);

    adapterParam->printAttributes.SetOption("123");
    printUtils.BuildPrintAttributesParam(adapterParam, want);
    EXPECT_EQ(adapterParam->printAttributes.hasOption_, true);
    EXPECT_EQ(adapterParam->printAttributes.option_, "123");
}

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0022_NeedRename, TestSize.Level2)
{
    PrintUtils printUtils;
    PrintAttributes attrParam;
    Json::Value attrJson;
    printUtils.ParseAttributesObjectParamForJson(attrParam, attrJson);
    EXPECT_EQ(PrintJsonUtil::WriteString(attrJson), "null");

    PrintRange range;
    range.SetStartPage(1);
    range.SetEndPage(1);
    std::vector<uint32_t> pages;
    pages.push_back(1);
    range.SetPages(pages);
    attrParam.SetPageRange(range);
    printUtils.ParseAttributesObjectParamForJson(attrParam, attrJson);
    EXPECT_EQ(PrintJsonUtil::WriteString(attrJson), "{\"pageRange\":{\"endPage\":1,\"pages\":[1],\"startPage\":1}}");

    PrintPageSize pageSize("11", "123", 400, 600);
    attrParam.SetPageSize(pageSize);
    printUtils.ParseAttributesObjectParamForJson(attrParam, attrJson);
    EXPECT_EQ(PrintJsonUtil::WriteString(attrJson),
        "{\"pageRange\":{\"endPage\":1,\"pages\":[1],\"startPage\":1},"
        "\"pageSize\":{\"height\":600,\"id\":\"11\",\"name\":\"123\","
        "\"width\":400}}");

    PrintMargin margin;
    margin.SetTop(100);
    margin.SetBottom(100);
    margin.SetLeft(100);
    margin.SetRight(100);
    attrParam.SetMargin(margin);
    printUtils.ParseAttributesObjectParamForJson(attrParam, attrJson);
    EXPECT_EQ(PrintJsonUtil::WriteString(attrJson),
        "{\"margin\":{\"bottom\":100,\"left\":100,\"right\":100,"
        "\"top\":100},\"pageRange\":{\"endPage\":1,\"pages\":[1],\"startPage\":1},"
        "\"pageSize\":{\"height\":600,\"id\":\"11\",\"name\":\"123\",\"width\":400}}");
}

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0023_NeedRename, TestSize.Level2)
{
    PrintUtils printUtils;
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    AAFwk::Want want;
    printUtils.BuildAdapterParam(adapterParam, want);
    AAFwk::Want preWant = want;
    adapterParam->isCheckFdList = false;
    printUtils.BuildAdapterParam(adapterParam, want);
    EXPECT_EQ(want.IsEquals(preWant), true);
}

/**
 * @tc.name: PrintUtilsTest_0024
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0024_NeedRename, TestSize.Level2)
{
    std::string gid = "com.sample.ext:1234";
    std::string id = "com.sample.ext";
    std::string testResult = "1234";
    std::string result = PrintUtils::GetLocalId(gid, id);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0025
 * @tc.desc: Verify the getLocalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0025_NeedRename, TestSize.Level2)
{
    int32_t result = PrintUtils::OpenFile("content://test/test1");
    EXPECT_EQ(99, result);
}

/**
 * @tc.name: PrintUtilsTest_0026
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0026_NeedRename, TestSize.Level2)
{
    string testString(2048, '1');
    int32_t result = PrintUtils::IsPathValid("testString");
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0027
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0027_NeedRename, TestSize.Level2)
{
    std::string result = PrintUtils::GetBundleNameForUid(123);
    EXPECT_EQ("", result);
}

/**
 * @tc.name: PrintUtilsTest_0028
 * @tc.desc: Verify the CheckUserIdInEventType function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0028_NeedRename, TestSize.Level2)
{
    std::string type = "test";
    int32_t callerUserId = 100;  // defaute test user id
    EXPECT_FALSE(PrintUtils::CheckUserIdInEventType(type, callerUserId));
    type = "test:";
    EXPECT_FALSE(PrintUtils::CheckUserIdInEventType(type, callerUserId));
    type = "999:test";
    EXPECT_FALSE(PrintUtils::CheckUserIdInEventType(type, callerUserId));
    type = "100:test";
    EXPECT_TRUE(PrintUtils::CheckUserIdInEventType(type, callerUserId));
}

/**
 * @tc.name: PrintUtilsTest_0029
 * @tc.desc: Verify the getGlobalId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetGlobalId_IncludeExtensionId_ReturnLocalId, TestSize.Level2)
{
    std::string id = "com.sample.ext";
    std::string localId = "com.sample.ext:1234";
    std::string testResult = "com.sample.ext:1234";
    std::string result = PrintUtils::GetGlobalId(id, localId);
    EXPECT_EQ(testResult, result);
}

/**
 * @tc.name: PrintUtilsTest_0030
 * @tc.desc: Verify the IsUsbPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, IsUsbPrinter_NotIncludeUSBString_Returnfalse, TestSize.Level2)
{
    std::string printerId = "com.sample.ext:1234";
    bool result = PrintUtils::IsUsbPrinter(printerId);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: PrintUtilsTest_0031
 * @tc.desc: Verify the IsUsbPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, IsUsbPrinter_IncludeUSBString_ReturnTrue, TestSize.Level2)
{
    std::string printerId = "com.sample.ext:USB-printer-1234";
    bool result = PrintUtils::IsUsbPrinter(printerId);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: ConvertParamsToPrintJob_Test
 * @tc.desc: Verify the ConvertParamsToPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, ConvertParamsToPrintJob_Test, TestSize.Level2)
{
    PrintJobParams params;
    auto result = PrintUtils::ConvertParamsToPrintJob(params);
    params.printerId = "printerId";
    EXPECT_EQ(result, nullptr);
    params.docFlavor = 1;
    params.binaryData = (uint8_t*)"text data";
    params.dataLength = 0;
    result = PrintUtils::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.dataLength = 10;
    result = PrintUtils::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.docFlavor = 0;
    params.printFdList = std::vector<uint32_t>();
    result = PrintUtils::ConvertParamsToPrintJob(params);
    EXPECT_EQ(result, nullptr);

    params.printFdList.emplace_back(0);
    result = PrintUtils::ConvertParamsToPrintJob(params);
    EXPECT_NE(result, nullptr);

    params.hasMargin = true;
    params.hasPreview = true;
    params.isSequential = 0;
    result = PrintUtils::ConvertParamsToPrintJob(params);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GetDocumentFormatToString_Test
 * @tc.desc: Verify the GetDocumentFormatToString function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetDocumentFormatToString_Test, TestSize.Level2)
{
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(0), "application/octet-stream");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(1), "image/jpeg");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(2), "application/pdf");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(3), "application/postscript");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(4), "text/plain");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(5), "application/vnd.cups-raw");
    EXPECT_EQ(PrintUtils::GetDocumentFormatToString(6), "application/octet-stream");
}

/**
 * @tc.name: CreateTempFileWithData_Test
 * @tc.desc: Verify the CreateTempFileWithData function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, CreateTempFileWithData_Test, TestSize.Level2)
{
    void *data = (uint8_t*)"test data";
    size_t length = 10;
    std::string tmpPath;
    int fd = PrintUtils::CreateTempFileWithData(data, length, tmpPath);
    EXPECT_EQ(fd, -1);
}

/**
 * @tc.name: GenerateTempFilePath_Test
 * @tc.desc: Verify the GenerateTempFilePath function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GenerateTempFilePath_Test, TestSize.Level2)
{
    const std::string testDir = "/tmp/test_files";
    std::string result = PrintUtils::GenerateTempFilePath(testDir);
    EXPECT_TRUE(result.find(testDir) == 0);
    EXPECT_TRUE(result.find("/job_") != std::string::npos);
    result = PrintUtils::GenerateTempFilePath("");
    EXPECT_TRUE(result.find("/job_") == 0);
}

/**
 * @tc.name: SetOptionInPrintJob_Test
 * @tc.desc: Verify the SetOptionInPrintJob function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, SetOptionInPrintJob_Test, TestSize.Level2)
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

    PrintUtils::SetOptionInPrintJob(params, printJob);
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

}  // namespace Print
}  // namespace OHOS
