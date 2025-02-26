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
#include <nlohmann/json.hpp>

using namespace testing::ext;
using json = nlohmann::json;

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

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0001, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultDuplexMode(0);
    EXPECT_EQ(true, preferences.HasDefaultDuplexMode());
    EXPECT_EQ(0, preferences.GetDefaultDuplexMode());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0002, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultPrintQuality(4);
    EXPECT_EQ(true, preferences.HasDefaultPrintQuality());
    EXPECT_EQ(4, preferences.GetDefaultPrintQuality());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0003, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultMediaType("stationery");
    EXPECT_EQ(true, preferences.HasDefaultMediaType());
    EXPECT_EQ("stationery", preferences.GetDefaultMediaType());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0004, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultPageSizeId("ISO_A4");
    EXPECT_EQ(true, preferences.HasDefaultPageSizeId());
    EXPECT_EQ("ISO_A4", preferences.GetDefaultPageSizeId());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0005, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetDefaultOrientation(0);
    EXPECT_EQ(true, preferences.HasDefaultOrientation());
    EXPECT_EQ(0, preferences.GetDefaultOrientation());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0006, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetBorderless(true);
    EXPECT_EQ(true, preferences.HasBorderless());
    EXPECT_EQ(true, preferences.GetBorderless());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0007, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetOption("test");
    EXPECT_EQ(true, preferences.HasOption());
    EXPECT_EQ("test", preferences.GetOption());
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0008, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.Dump();
    Parcel parcel;
    EXPECT_EQ(true, preferences.Marshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0009, TestSize.Level1)
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

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0010, TestSize.Level1)
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

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0011, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    Parcel parcel;
    preferences.Marshalling(parcel);
    EXPECT_NE(nullptr, OHOS::Print::PrinterPreferences::Unmarshalling(parcel));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0012, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    nlohmann::json preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(false, preferencesJson.contains("options"));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0013, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    preferences.SetOption("test");
    nlohmann::json preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(false, preferencesJson.contains("options"));
}

HWTEST_F(PrinterPreferencesTest, PrinterPreferencesTest_0014, TestSize.Level1)
{
    OHOS::Print::PrinterPreferences preferences;
    nlohmann::json opsJson;
    opsJson["testKey"] = "testValue";
    preferences.SetOption(opsJson.dump());
    nlohmann::json preferencesJson = preferences.ConvertToJson();
    EXPECT_EQ(true, preferencesJson.contains("options"));
}
} // namespace Print
} // namespace OHOS
