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

#include "iservice_registry.h"
#include <gtest/gtest.h>
#define private public
#include "print_utils.h"
#undef private
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_job.h"
#include "print_json_util.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "print_util.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintUtilsTest : public testing::Test {
public:
  static void SetUpTestCase(void);
  static void TearDownTestCase(void);
  void SetUp();
  void TearDown();
};

void PrintUtilsTest::SetUpTestCase(void) {}

void PrintUtilsTest::TearDownTestCase(void) {}

void PrintUtilsTest::SetUp(void) {}

void PrintUtilsTest::TearDown(void) {}

/**
 * @tc.name: PrintUtilsTest_0001
 * @tc.desc: Verify the toLower function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0001, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0002, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0003, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest,
         GetGlobalId_NotIncludeExtensionId_ReturnWithExtensionId,
         TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0005, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0006, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0007, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0008, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0009, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0010, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0011, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0012, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0013, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0014, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0015, TestSize.Level2)
{
  int32_t result =
      PrintUtils::IsPathValid("/data/service/e11//data/service/e11");
  EXPECT_EQ(E_PRINT_NONE, result);
}

/**
 * @tc.name: PrintUtilsTest_0016
 * @tc.desc: Verify the isPathValid function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0016, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0017, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0018, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0019, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0020, TestSize.Level2)
{
  std::string testResult = "PRINT_JOB_UNKNOWN";
  std::string result = PrintUtils::GetJobStateChar(PRINT_JOB_PREPARED + 100);
  EXPECT_EQ(testResult, result);
}

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0021, TestSize.Level2)
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

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0022, TestSize.Level2)
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
  EXPECT_EQ(PrintJsonUtil::WriteString(attrJson),
            "{\"pageRange\":{\"endPage\":1,\"pages\":[1],\"startPage\":1}}");

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
            "\"top\":100},\"pageRange\":{\"endPage\":1,\"pages\":[1],"
            "\"startPage\":1},"
            "\"pageSize\":{\"height\":600,\"id\":\"11\",\"name\":\"123\","
            "\"width\":400}}");
}

HWTEST_F(PrintUtilsTest, PrintUtilsTest_0023, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0024, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0025, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0026, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0027, TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, PrintUtilsTest_0028, TestSize.Level2)
{
  std::string type = "test";
  int32_t callerUserId = 100; // defaute test user id
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
HWTEST_F(PrintUtilsTest, GetGlobalId_IncludeExtensionId_ReturnLocalId,
         TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, IsUsbPrinter_NotIncludeUSBString_Returnfalse,
         TestSize.Level2)
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
HWTEST_F(PrintUtilsTest, IsUsbPrinter_IncludeUSBString_ReturnTrue,
         TestSize.Level2)
{
  std::string printerId = "com.sample.ext:USB-printer-1234";
  bool result = PrintUtils::IsUsbPrinter(printerId);
  EXPECT_EQ(result, true);
}

/**
 * @tc.name: MakeExtensionStateKey_001
 * @tc.desc: Verify MakeExtensionStateKey with valid userId and bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, MakeExtensionStateKey_001, TestSize.Level1)
{
  int32_t userId = 100;
  std::string bundleName = "com.example.print";
  std::string result = PrintUtils::MakeExtensionStateKey(userId, bundleName);
  EXPECT_EQ(result, "100_com.example.print");
}

/**
 * @tc.name: MakeExtensionStateKey_002
 * @tc.desc: Verify MakeExtensionStateKey with different userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, MakeExtensionStateKey_002, TestSize.Level1)
{
  int32_t userId = 0;
  std::string bundleName = "com.test.extension";
  std::string result = PrintUtils::MakeExtensionStateKey(userId, bundleName);
  EXPECT_EQ(result, "0_com.test.extension");
}

/**
 * @tc.name: GetUserIdFromKey_001
 * @tc.desc: Verify GetUserIdFromKey with valid key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetUserIdFromKey_001, TestSize.Level1)
{
  std::string key = "100_com.example.print";
  int32_t result = PrintUtils::GetUserIdFromKey(key);
  EXPECT_EQ(result, 100);
}

/**
 * @tc.name: GetUserIdFromKey_002
 * @tc.desc: Verify GetUserIdFromKey with invalid key (no underscore).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetUserIdFromKey_002, TestSize.Level1)
{
  std::string key = "com.example.print";
  int32_t result = PrintUtils::GetUserIdFromKey(key);
  EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetUserIdFromKey_003
 * @tc.desc: Verify GetUserIdFromKey with empty key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetUserIdFromKey_003, TestSize.Level1)
{
  std::string key = "";
  int32_t result = PrintUtils::GetUserIdFromKey(key);
  EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetBundleNameFromKey_001
 * @tc.desc: Verify GetBundleNameFromKey with valid key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetBundleNameFromKey_001, TestSize.Level1)
{
  std::string key = "100_com.example.print";
  std::string result = PrintUtils::GetBundleNameFromKey(key);
  EXPECT_EQ(result, "com.example.print");
}

/**
 * @tc.name: GetBundleNameFromKey_002
 * @tc.desc: Verify GetBundleNameFromKey with invalid key (no underscore).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetBundleNameFromKey_002, TestSize.Level1)
{
  std::string key = "com.example.print";
  std::string result = PrintUtils::GetBundleNameFromKey(key);
  EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetBundleNameFromKey_003
 * @tc.desc: Verify GetBundleNameFromKey with empty key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, GetBundleNameFromKey_003, TestSize.Level1)
{
  std::string key = "";
  std::string result = PrintUtils::GetBundleNameFromKey(key);
  EXPECT_EQ(result, "");
}

/**
 * @tc.name: ExtensionStateKey_RoundTrip_001
 * @tc.desc: Verify key creation and parsing round trip.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUtilsTest, ExtensionStateKey_RoundTrip_001, TestSize.Level1)
{
  int32_t originalUserId = 100;
  std::string originalBundleName = "com.ohos.printservice";

  std::string key =
      PrintUtils::MakeExtensionStateKey(originalUserId, originalBundleName);
  int32_t parsedUserId = PrintUtils::GetUserIdFromKey(key);
  std::string parsedBundleName = PrintUtils::GetBundleNameFromKey(key);

  EXPECT_EQ(parsedUserId, originalUserId);
  EXPECT_EQ(parsedBundleName, originalBundleName);
}

// IsPathValidForCreate parameterized test structure
struct IsPathValidForCreateTestCase {
  std::string testName;
  std::string parentDir;
  std::string fileName;
  bool expectedResult;
  std::string description;
};

class IsPathValidForCreateCommon {
public:
  static void SetUpTestCase(void) {}
  static void TearDownTestCase(void) {}
};

class IsPathValidForCreateTest
    : public IsPathValidForCreateCommon,
      public testing::TestWithParam<IsPathValidForCreateTestCase> {
public:
  using IsPathValidForCreateCommon::SetUpTestCase;
  using IsPathValidForCreateCommon::TearDownTestCase;
};

INSTANTIATE_TEST_SUITE_P(
    IsPathValidForCreateTest, IsPathValidForCreateTest,
    testing::Values(
        // Normal cases
        IsPathValidForCreateTestCase{
            "ValidPath", "/data", "file.txt", true,
            "Normal: valid parent directory and file name"},
        IsPathValidForCreateTestCase{"ValidSubDir", "/data/local/tmp",
                                     "config.json", true,
                                     "Normal: valid subdirectory as parent"},
        IsPathValidForCreateTestCase{
            "FileNameStartsWithDots", "/data", "..file.txt", true,
            "Normal: fileName starts with .. but is not path traversal"},
        IsPathValidForCreateTestCase{
            "FileNameContainsBackslash", "/data", "sub\\config.json", true,
            "Error: fileName contains backslash (Windows path separator)"},

        // Parameter empty
        IsPathValidForCreateTestCase{"EmptyParentDir", "", "file.txt", false,
                                     "Error: empty parent directory"},
        IsPathValidForCreateTestCase{"EmptyFileName", "/data", "", false,
                                     "Error: empty file name"},
        IsPathValidForCreateTestCase{
            "BothEmpty", "", "", false,
            "Error: empty parent directory and file name"},

        // Parent directory not exist (IsPathValid returns false)
        IsPathValidForCreateTestCase{"ParentNotExist", "/nonexistent",
                                     "file.txt", false,
                                     "Error: parent directory does not exist"},

        // Invalid fileName
        IsPathValidForCreateTestCase{"FileNameContainsSlash", "/data",
                                     "sub/file.txt", false,
                                     "Error: fileName contains /"},
        IsPathValidForCreateTestCase{"FileNameContainsNullByte", "/data",
                                     std::string("file\0.txt", 9), false,
                                     "Error: fileName contains null byte"},
        IsPathValidForCreateTestCase{
            "FileNameIsDot", "/data", ".", false,
            "Error: fileName is . (current directory marker)"},
        IsPathValidForCreateTestCase{
            "PathTraversal", "/data", "..", false,
            "Security: fileName is .. causes path traversal"},

        // Invalid parentDir
        IsPathValidForCreateTestCase{
            "ParentDirTraversal", "/data/..", "config.json", false,
            "Error: parentDir contains path traversal"},
        IsPathValidForCreateTestCase{"RelativeParentDir", "./", "config.json",
                                     false, "Error: relative path not allowed"},
        IsPathValidForCreateTestCase{
            "WindowsStylePath", "\\data\\local\\tmp", "config.json", false,
            "Error: Windows-style path not supported on Linux"}));

/**
 * @tc.name: PrintUtilsTest_IsPathValidForCreate_001
 * @tc.desc: IsPathValidForCreate parameterized test for path validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_P(IsPathValidForCreateTest, IsPathValidForCreate_Parameterized_Test,
         TestSize.Level1)
{
  const IsPathValidForCreateTestCase &testCase = GetParam();
  bool result =
      PrintUtils::IsPathValidForCreate(testCase.parentDir, testCase.fileName);

  EXPECT_EQ(result, testCase.expectedResult)
      << "Test: " << testCase.testName
      << ", Description: " << testCase.description
      << ", ParentDir: " << testCase.parentDir
      << ", FileName: " << testCase.fileName;
}

} // namespace Print
} // namespace OHOS
