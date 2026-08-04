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

#include "print_service_ability_test_common.h"

namespace OHOS {
namespace Print {

HWTEST_F(PrintServiceAbilityTest, MergeVendorOptionsForPrintJob_JobVendorOptionsNonEmpty_UsesJobWholly,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"paperSize":"A4","colorMode":"color"})");

    PrinterUserPreferences userPrefs;
    userPrefs.SetVendorOptions(R"({"user_username":"admin"})");

    PrintJob printJob;
    printJob.SetVendorOptions(R"({"duplex":"on"})");

    service->MergeVendorOptionsForPrintJob(preferences, userPrefs, printJob);

    EXPECT_TRUE(printJob.HasVendorOptions());
    Json::Value resultJson;
    PrintJsonUtil::Parse(printJob.GetVendorOptions(), resultJson);
    EXPECT_TRUE(resultJson.isMember("duplex"));
    EXPECT_EQ(resultJson["duplex"].asString(), "on");
    EXPECT_FALSE(resultJson.isMember("paperSize"));
    EXPECT_FALSE(resultJson.isMember("colorMode"));
    EXPECT_FALSE(resultJson.isMember("user_username"));
}

HWTEST_F(PrintServiceAbilityTest, MergeVendorOptionsForPrintJob_JobVendorOptionsEmpty_UsesMergedPreference,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"paperSize":"A4"})");

    PrinterUserPreferences userPrefs;
    userPrefs.SetVendorOptions(R"({"user_username":"admin"})");

    PrintJob printJob;

    service->MergeVendorOptionsForPrintJob(preferences, userPrefs, printJob);

    EXPECT_TRUE(printJob.HasVendorOptions());
    Json::Value resultJson;
    PrintJsonUtil::Parse(printJob.GetVendorOptions(), resultJson);
    EXPECT_TRUE(resultJson.isMember("paperSize"));
    EXPECT_EQ(resultJson["paperSize"].asString(), "A4");
    EXPECT_TRUE(resultJson.isMember("user_username"));
    EXPECT_EQ(resultJson["user_username"].asString(), "admin");
}

HWTEST_F(PrintServiceAbilityTest, MergeVendorOptionsForPrintJob_BothEmpty_NoVendorOptionsSet, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    PrinterPreferences preferences;
    PrinterUserPreferences userPrefs;
    PrintJob printJob;

    service->MergeVendorOptionsForPrintJob(preferences, userPrefs, printJob);

    EXPECT_FALSE(printJob.HasVendorOptions());
    EXPECT_TRUE(printJob.GetVendorOptions().empty());
}

HWTEST_F(PrintServiceAbilityTest, MergeVendorOptionsForPrintJob_JobNonEmptyPrefEmpty_UsesJobWholly,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    PrinterPreferences preferences;
    PrinterUserPreferences userPrefs;

    PrintJob printJob;
    printJob.SetVendorOptions(R"({"duplex":"on"})");

    service->MergeVendorOptionsForPrintJob(preferences, userPrefs, printJob);

    EXPECT_TRUE(printJob.HasVendorOptions());
    Json::Value resultJson;
    PrintJsonUtil::Parse(printJob.GetVendorOptions(), resultJson);
    EXPECT_TRUE(resultJson.isMember("duplex"));
    EXPECT_EQ(resultJson["duplex"].asString(), "on");
}

}  // namespace Print
}  // namespace OHOS
