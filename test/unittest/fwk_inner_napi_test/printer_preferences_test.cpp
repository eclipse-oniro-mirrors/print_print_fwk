/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "printer_preferences.h"
#include "print_json_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrinterPreferencesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrinterPreferencesTest::SetUpTestCase(void) {}

void PrinterPreferencesTest::TearDownTestCase(void) {}

void PrinterPreferencesTest::SetUp(void) {}

void PrinterPreferencesTest::TearDown(void) {}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0001_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(0);
    EXPECT_EQ(true, preferences.HasDefaultDuplexMode());
    EXPECT_EQ(0, preferences.GetDefaultDuplexMode());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0002_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultPrintQuality(4);
    EXPECT_EQ(true, preferences.HasDefaultPrintQuality());
    EXPECT_EQ(4, preferences.GetDefaultPrintQuality());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0003_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultMediaType("stationery");
    EXPECT_EQ(true, preferences.HasDefaultMediaType());
    EXPECT_EQ("stationery", preferences.GetDefaultMediaType());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0004_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultPageSizeId("ISO_A4");
    EXPECT_EQ(true, preferences.HasDefaultPageSizeId());
    EXPECT_EQ("ISO_A4", preferences.GetDefaultPageSizeId());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0005_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultOrientation(0);
    EXPECT_EQ(true, preferences.HasDefaultOrientation());
    EXPECT_EQ(0, preferences.GetDefaultOrientation());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0006_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetBorderless(true);
    EXPECT_EQ(true, preferences.HasBorderless());
    EXPECT_EQ(true, preferences.GetBorderless());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0007_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetOption("test");
    EXPECT_EQ(true, preferences.HasOption());
    EXPECT_EQ("test", preferences.GetOption());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0008_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.Dump();
    Parcel parcel;
    EXPECT_EQ(true, preferences.Marshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0009_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(0);
    preferences.SetDefaultPrintQuality(4);
    preferences.SetDefaultMediaType("stationery");
    preferences.SetDefaultPageSizeId("ISO_A4");
    preferences.SetDefaultOrientation(0);
    preferences.SetBorderless(true);
    preferences.SetOption("test");
    preferences.Dump();
    Parcel parcel;
    EXPECT_EQ(true, preferences.Marshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0010_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(0);
    preferences.SetDefaultPrintQuality(4);
    preferences.SetDefaultMediaType("stationery");
    preferences.SetDefaultPageSizeId("ISO_A4");
    preferences.SetDefaultOrientation(0);
    preferences.SetBorderless(true);
    preferences.SetOption("test");
    Parcel parcel;
    preferences.Marshalling(parcel);
    EXPECT_NE(nullptr, OHOS::Print::PrinterPreferences::Unmarshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0011_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Parcel parcel;
    preferences.Marshalling(parcel);
    EXPECT_NE(nullptr, OHOS::Print::PrinterPreferences::Unmarshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0012_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Json::Value preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(false, Print::PrintJsonUtil::IsMember(preferencesJson, "options"));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0013_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(0);
    preferences.SetDefaultPrintQuality(0);
    preferences.SetDefaultMediaType("plain");
    preferences.SetDefaultPageSizeId("ISO_A4");
    preferences.SetDefaultOrientation(0);
    preferences.SetBorderless(false);
    preferences.SetOption("test");
    Json::Value preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(true, Print::PrintJsonUtil::IsMember(preferencesJson, "defaultPageSizeId"));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0014_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Json::Value opsJson;
    opsJson["testKey"] = "testValue";
    preferences.SetOption(PrintJsonUtil::WriteString(opsJson));
    Json::Value preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(true, Print::PrintJsonUtil::IsMember(preferencesJson, "options"));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0015_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Json::Value preferencesJson;
    preferences.ConvertJsonToPrinterPreferences(preferencesJson);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), false);
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0016_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Json::Value preferencesJson;
    preferencesJson["defaultPageSizeId"] = 123;
    preferencesJson["defaultOrientation"] = "123";
    preferencesJson["defaultDuplexMode"] = "123";
    preferencesJson["defaultPrintQuality"] = "123";
    preferencesJson["defaultMediaType"] = 123;
    preferencesJson["borderless"] = "123";
    preferencesJson["options"] = "123";
    preferences.ConvertJsonToPrinterPreferences(preferencesJson);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), false);
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0017_NeedRename, TestSize.Level2)
{
    OHOS::Print::PrinterPreferences preferences;
    Json::Value preferencesJson;
    preferencesJson["defaultPageSizeId"] = "123";
    preferencesJson["defaultOrientation"] = 123;
    preferencesJson["defaultDuplexMode"] = 123;
    preferencesJson["defaultPrintQuality"] = 123;
    preferencesJson["defaultMediaType"] = "123";
    preferencesJson["borderless"] = true;
    Json::Value optionJson;
    preferencesJson["options"] = optionJson;
    preferences.ConvertJsonToPrinterPreferences(preferencesJson);
    EXPECT_EQ(preferences.HasDefaultDuplexMode(), true);
}
} // namespace Print
} // namespace OHOS
