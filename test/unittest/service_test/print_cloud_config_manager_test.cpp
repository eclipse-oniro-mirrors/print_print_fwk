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
#include "mock_print_cloud_config_manager.h"
#include "print_cloud_config_manager.h"
#include "print_json_util.h"
#include "print_constant.h"

#include <fstream>
#include <cstdio>

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

HWTEST_F(PrintCloudConfigManagerTest, GetInstance_ReturnsSameSingleton, TestSize.Level1)
{
    PrintCloudConfigManager &inst1 = PrintCloudConfigManager::GetInstance();
    PrintCloudConfigManager &inst2 = PrintCloudConfigManager::GetInstance();
    EXPECT_EQ(&inst1, &inst2);
}

HWTEST_F(PrintCloudConfigManagerTest, SetInstance_MockInjected_GetInstanceReturnsMock, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_EQ(&PrintCloudConfigManager::GetInstance(), &mock);
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, ResetInstance_GetInstanceReturnsDefault, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    PrintCloudConfigManager::ResetInstance();
    EXPECT_NE(&PrintCloudConfigManager::GetInstance(), &mock);
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_EmptyPrinterMake_ReturnsEmpty, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string result = instance.MatchPrinterMakeInCloudConfig("");
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_FilePathEmpty_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(""));
    EXPECT_CALL(mock, LoadCloudConfigFile(_, _)).Times(0);

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_LoadCloudConfigFileFails_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(Return(false));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_ContentEmpty_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(""), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_ParseFails_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>("not valid json{{{"), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_RootNotArray_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>("{\"key\": \"value\"}"), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MatchFound_ReturnsFormatValue, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string validContent = "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": [\"HP\"]}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(validContent), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "PDF");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_NoMatchFound_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string validContent = "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": [\"Canon\"]}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(validContent), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_InvalidItemSkipped_ReturnsEmpty, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string invalidContent = "[{\"wrongField\": \"PDF\"}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(invalidContent), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_InvalidItemThenValidMatch_ReturnsFormatValue, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string mixedContent =
        "[{\"wrongField\": \"PDF\"},"
        "{\"bsuniOutputFormat\": \"PCL\", \"printerMakes\": [\"HP\"]}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(mixedContent), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "PCL");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_BsuniOutputFormatNotString_Skipped, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string content = "[{\"bsuniOutputFormat\": 123, \"printerMakes\": [\"HP\"]}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(content), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_PrinterMakesNotArray_Skipped, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string content = "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": \"HP\"}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(content), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, MatchPrinterMakeInCloudConfig_MakeNotString_Skipped, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    PrintCloudConfigManager::SetInstance(&mock);
    std::string content = "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": [123]}]";
    EXPECT_CALL(mock, MatchPrinterMakeInCloudConfig("HP"))
        .WillOnce(Invoke([&mock](const std::string &make) -> std::string {
            return mock.PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(make);
        }));
    EXPECT_CALL(mock, GetCloudConfigFilePath())
        .WillOnce(Return(tempFilePath_));
    EXPECT_CALL(mock, LoadCloudConfigFile(tempFilePath_, _))
        .WillOnce(DoAll(SetArgReferee<1>(content), Return(true)));

    std::string result = PrintCloudConfigManager::GetInstance().MatchPrinterMakeInCloudConfig("HP");
    EXPECT_EQ(result, "");
    PrintCloudConfigManager::ResetInstance();
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_FileNotFound_ReturnsFalse, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    std::string content;
    bool result = mock.PrintCloudConfigManager::LoadCloudConfigFile("/nonexistent/path/config.json", content);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintCloudConfigManagerTest, LoadCloudConfigFile_FileExists_ReturnsTrueAndContent, TestSize.Level1)
{
    MockPrintCloudConfigManager mock;
    std::ofstream file(tempFilePath_);
    file << "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": [\"HP\"]}]";
    file.close();
    std::string content;
    bool result = mock.PrintCloudConfigManager::LoadCloudConfigFile(tempFilePath_, content);
    EXPECT_TRUE(result);
    EXPECT_EQ(content, "[{\"bsuniOutputFormat\": \"PDF\", \"printerMakes\": [\"HP\"]}]");
}

HWTEST_F(PrintCloudConfigManagerTest, GetCloudConfigFilePath_ReturnsEmptyInTestEnv, TestSize.Level1)
{
    PrintCloudConfigManager &instance = PrintCloudConfigManager::GetInstance();
    std::string result = instance.GetCloudConfigFilePath();
    EXPECT_TRUE(result.empty() || result.find("bsuni_output_format.json") != std::string::npos);
}

} // namespace Print
} // namespace OHOS
