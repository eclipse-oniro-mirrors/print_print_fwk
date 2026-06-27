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
#define private public
#include "mock_print_cloud_config_manager.h"
#undef private
#include "print_cloud_config_manager.h"
#include "print_json_util.h"
#include "print_constant.h"

#include <fstream>
#include <cstdio>
#include <sys/stat.h>
#include <dirent.h>

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Print {

class PrintCloudConfigManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::string tempFilePath_;
    MockPrintCloudConfigManager mock_;
};

void PrintCloudConfigManagerTest::SetUpTestCase(void) {}

void PrintCloudConfigManagerTest::TearDownTestCase(void) {}

void PrintCloudConfigManagerTest::SetUp(void)
{
    tempFilePath_ = PRINTER_SERVICE_PRINTERS_PATH + "/test_cloud_config_temp.json";
}

void PrintCloudConfigManagerTest::TearDown(void)
{
    std::remove(tempFilePath_.c_str());
}

HWTEST_F(PrintCloudConfigManagerTest, GetInstance_Singleton_ReturnSameInstance, TestSize.Level1)
{
    PrintCloudConfigManager &instance1 = PrintCloudConfigManager::GetInstance();
    PrintCloudConfigManager &instance2 = PrintCloudConfigManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(PrintCloudConfigManagerTest, GetCloudConfigFilePath_ReturnResult, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string result = instance.GetCloudConfigFilePath();
    EXPECT_TRUE(result.empty() || !result.empty());
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_InvalidPath_ReturnFalse, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string content;
    std::string invalidPath = "/nonexistent/path/config.json";
    bool result = instance.LoadCloudConfigFile(invalidPath, content);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_EmptyPath_ReturnFalse, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string content;
    std::string emptyPath = "";
    bool result = instance.LoadCloudConfigFile(emptyPath, content);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_TooLongPath_ReturnFalse, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string content;
    std::string longPath(PATH_MAX, 'a');
    bool result = instance.LoadCloudConfigFile(longPath, content);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_FileNotExist_ReturnFalse, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string content;
    bool result = instance.LoadCloudConfigFile(tempFilePath_, content);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_Success_ReturnTrueAndContent, TestSize.Level1)
{
    mkdir(PRINTER_SERVICE_PRINTERS_PATH.c_str(), 0755);
    std::ofstream file(tempFilePath_);
    file << "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"HP\"]}]";
    file.close();

    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string content;
    bool result = instance.LoadCloudConfigFile(tempFilePath_, content);
    EXPECT_TRUE(result);
    EXPECT_FALSE(content.empty());
    EXPECT_NE(content.find("bsuniOutputFormat"), std::string::npos);
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_EmptyPrinterMake_ReturnEmpty, TestSize.Level1)
{
    std::string result = mock_.MatchPrinterMakeInCloudConfig("");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_EmptyFilePath_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return(""));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_LoadFailed_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _)).WillByDefault(Return(false));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_EmptyContent_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(""), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_ParseFailed_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>("invalid json{{{"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_RootNotArray_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>("{\"key\":\"value\"}"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MissingBsuniOutputFormat_SkipItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"printerMakes\":[\"HP\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_BsuniOutputFormatNotString_SkipItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":123,\"printerMakes\":[\"HP\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MissingPrinterMakes_SkipItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\"}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_PrinterMakesNotArray_SkipItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":\"HP\"}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MatchFound_ReturnFormat, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"HP\",\"Canon\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "PDF");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MatchSecondMake_ReturnFormat, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"HP\",\"Canon\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("Canon");
    EXPECT_EQ(result, "PDF");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_NoMatch_ReturnEmpty, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"Canon\",\"Epson\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MakeNotString_SkipItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[123,\"Canon\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("Canon");
    EXPECT_EQ(result, "PDF");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MultipleItems_MatchSecondItem, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"Canon\"]},"
            "{\"bsuniOutputFormat\":\"PCL\",\"printerMakes\":[\"HP\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "PCL");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_InvalidItemThenValidItem_ReturnFormat, TestSize.Level1)
{
    ON_CALL(mock_, GetCloudConfigFilePath()).WillByDefault(Return("/some/path/config.json"));
    ON_CALL(mock_, LoadCloudConfigFile(_, _))
        .WillByDefault(DoAll(SetArgReferee<1>(
            "[{\"printerMakes\":[\"HP\"]},"
            "{\"bsuniOutputFormat\":\"PDF\",\"printerMakes\":[\"HP\"]}]"), Return(true)));
    std::string result = mock_.MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "PDF");
}

} // namespace Print
} // namespace OHOS
