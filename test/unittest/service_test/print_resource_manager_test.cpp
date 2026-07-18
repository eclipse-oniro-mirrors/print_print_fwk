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
#include <string>
#include <memory>
#define private public
#include "print_resource_manager.h"
#undef private
#include "print_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintResourceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    PrintResourceManager& printResourceManager = PrintResourceManager::GetInstance();
};

void PrintResourceManagerTest::SetUpTestCase(void)
{}

void PrintResourceManagerTest::TearDownTestCase(void)
{}

void PrintResourceManagerTest::SetUp(void)
{}

void PrintResourceManagerTest::TearDown(void)
{}

HWTEST_F(PrintResourceManagerTest, GetInstance_Singleton_ReturnSameInstance, TestSize.Level1)
{
    PrintResourceManager& instance1 = PrintResourceManager::GetInstance();
    PrintResourceManager& instance2 = PrintResourceManager::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_ValidName_ReturnString, TestSize.Level1)
{
    std::string name = "app_name";
    std::string result = printResourceManager.GetStringByName(name);
    
    EXPECT_FALSE(result.empty());
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_EmptyName_ReturnEmpty, TestSize.Level1)
{
    std::string name = "";
    std::string result = printResourceManager.GetStringByName(name);
    
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_InvalidName_ReturnEmpty, TestSize.Level1)
{
    std::string name = "invalid_resource_name_12345";
    std::string result = printResourceManager.GetStringByName(name);
    
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_MultipleCalls_ReturnConsistent, TestSize.Level1)
{
    std::string name = "app_name";
    std::string result1 = printResourceManager.GetStringByName(name);
    std::string result2 = printResourceManager.GetStringByName(name);
    
    EXPECT_EQ(result1, result2);
}

HWTEST_F(PrintResourceManagerTest, GetPixelMapByName_ValidName_ReturnPixelMap, TestSize.Level1)
{
    std::string name = "logo";
    auto pixelMap = printResourceManager.GetPixelMapByName(name);
    
    EXPECT_NE(pixelMap, nullptr);
}

HWTEST_F(PrintResourceManagerTest, GetPixelMapByName_EmptyName_ReturnNullptr, TestSize.Level1)
{
    std::string name = "";
    auto pixelMap = printResourceManager.GetPixelMapByName(name);
    
    EXPECT_EQ(pixelMap, nullptr);
}

HWTEST_F(PrintResourceManagerTest, GetPixelMapByName_InvalidName_ReturnNullptr, TestSize.Level1)
{
    std::string name = "invalid_image_name_12345";
    auto pixelMap = printResourceManager.GetPixelMapByName(name);
    
    EXPECT_EQ(pixelMap, nullptr);
}

HWTEST_F(PrintResourceManagerTest, GetPixelMapByName_MultipleCalls_ReturnValid, TestSize.Level1)
{
    std::string name = "logo";
    auto pixelMap1 = printResourceManager.GetPixelMapByName(name);
    auto pixelMap2 = printResourceManager.GetPixelMapByName(name);
    
    EXPECT_NE(pixelMap1, nullptr);
    EXPECT_NE(pixelMap2, nullptr);
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_KnownResourceKeys_ReturnStrings, TestSize.Level2)
{
    std::vector<std::string> resourceKeys = {
        "printer_door_open",
        "printer_out_of_paper",
        "printer_out_of_ink",
        "printer_out_of_toner",
        "printer_jammed",
        "printer_offline",
        "printer_busy",
        "printer_low_on_ink",
        "printer_low_on_toner",
        "printer_really_low_on_ink",
        "printer_bad_certificate",
        "printer_driver_exception",
        "printer_account_error",
        "printer_permission_error",
        "printer_color_permission_error",
        "printer_network_error",
        "printer_server_connection_error",
        "printer_large_file_error",
        "printer_file_parsing_error",
        "printer_slow_file_conversion",
        "printer_driver_missing",
        "printer_interrupt",
        "printer_authentication",
        "printer_banned",
        "printer_smb_error",
        "printer_unavailable"
    };
    
    int successCount = 0;
    for (const auto& key : resourceKeys) {
        std::string result = printResourceManager.GetStringByName(key);
        if (!result.empty()) {
            successCount++;
        }
    }
    
    EXPECT_GT(successCount, 0);
}

HWTEST_F(PrintResourceManagerTest, RefreshResConfig_CallMultipleTimes_NoCrash, TestSize.Level1)
{
    for (int i = 0; i < 10; i++) {
        printResourceManager.RefreshResConfig();
    }
    
    EXPECT_TRUE(true);
}

HWTEST_F(PrintResourceManagerTest, GetStringByName_AfterRefreshConfig_ReturnValid, TestSize.Level1)
{
    printResourceManager.RefreshResConfig();
    
    std::string name = "app_name";
    std::string result = printResourceManager.GetStringByName(name);
    
    EXPECT_FALSE(result.empty());
}

HWTEST_F(PrintResourceManagerTest, GetPixelMapByName_AfterRefreshConfig_ReturnValid, TestSize.Level1)
{
    printResourceManager.RefreshResConfig();
    
    std::string name = "logo";
    auto pixelMap = printResourceManager.GetPixelMapByName(name);
    
    EXPECT_NE(pixelMap, nullptr);
}

HWTEST_F(PrintResourceManagerTest, ResourcePath_IsCorrect, TestSize.Level1)
{
    std::string expectedPath = "/system/app/Spooler/Spooler.hap";
    
    EXPECT_EQ(printResourceManager.resourcePath_, expectedPath);
}

HWTEST_F(PrintResourceManagerTest, ResourceManager_IsInitialized, TestSize.Level1)
{
    EXPECT_NE(printResourceManager.resourceManager_, nullptr);
}

HWTEST_F(PrintResourceManagerTest, ResConfig_IsInitialized, TestSize.Level1)
{
    EXPECT_NE(printResourceManager.resConfig_, nullptr);
}

}  // namespace Print
}  // namespace OHOS