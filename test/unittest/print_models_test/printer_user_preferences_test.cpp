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
#include "printer_user_preferences.h"
#include "print_json_util.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrinterUserPreferencesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void PrinterUserPreferencesTest::SetUpTestCase(void) {}

void PrinterUserPreferencesTest::TearDownTestCase(void) {}

void PrinterUserPreferencesTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrinterUserPreferencesTest_%{public}d", ++testNo);
}

HWTEST_F(PrinterUserPreferencesTest, DefaultConstructor_AllFieldsDefault, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    EXPECT_EQ(userPrefs.GetUserId(), 0);
    EXPECT_EQ(userPrefs.GetPrinterId(), "");
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
    EXPECT_FALSE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, CopyConstructor_AllFieldsCopied, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetUserId(100);
    original.SetPrinterId("printer_001");
    original.SetVendorOptions("{\"user_username\":\"admin\"}");

    PrinterUserPreferences copy(original);

    EXPECT_EQ(copy.GetUserId(), 100);
    EXPECT_EQ(copy.GetPrinterId(), "printer_001");
    EXPECT_EQ(copy.GetVendorOptions(), "{\"user_username\":\"admin\"}");
    EXPECT_TRUE(copy.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, SetAndGetUserId_NormalValue_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetUserId(200);
    EXPECT_EQ(userPrefs.GetUserId(), 200);

    userPrefs.SetUserId(300);
    EXPECT_EQ(userPrefs.GetUserId(), 300);
}

HWTEST_F(PrinterUserPreferencesTest, SetAndGetUserId_ZeroValue_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);

    userPrefs.SetUserId(0);
    EXPECT_EQ(userPrefs.GetUserId(), 0);
}

HWTEST_F(PrinterUserPreferencesTest, SetAndGetPrinterId_NormalValue_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetPrinterId("com.vendor.driver_Printer_001");
    EXPECT_EQ(userPrefs.GetPrinterId(), "com.vendor.driver_Printer_001");
}

HWTEST_F(PrinterUserPreferencesTest, SetAndGetPrinterId_EmptyString_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetPrinterId("printer_001");

    userPrefs.SetPrinterId("");
    EXPECT_EQ(userPrefs.GetPrinterId(), "");
}

HWTEST_F(PrinterUserPreferencesTest, SetAndGetPrinterId_LongString_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    std::string longPrinterId = "com.vendor.driver_" + std::string(100, 'a');
    userPrefs.SetPrinterId(longPrinterId);
    EXPECT_EQ(userPrefs.GetPrinterId(), longPrinterId);
}

HWTEST_F(PrinterUserPreferencesTest, SetVendorOptions_NonEmptyString_HasVendorOptionsTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetVendorOptions("{\"user_username\":\"admin\",\"user_password\":\"123456\"}");

    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), "{\"user_username\":\"admin\",\"user_password\":\"123456\"}");
}

HWTEST_F(PrinterUserPreferencesTest, SetVendorOptions_EmptyString_HasVendorOptionsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetVendorOptions("{\"user_field\":\"value\"}");

    userPrefs.SetVendorOptions("");

    EXPECT_FALSE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
}

HWTEST_F(PrinterUserPreferencesTest, SetVendorOptions_OverridePreviousValue_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetVendorOptions("{\"old_field\":\"old_value\"}");
    EXPECT_TRUE(userPrefs.HasVendorOptions());

    userPrefs.SetVendorOptions("{\"new_field\":\"new_value\"}");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), "{\"new_field\":\"new_value\"}");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_AllFieldsSet_JsonComplete, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    userPrefs.SetPrinterId("printer_001");
    userPrefs.SetVendorOptions("{\"user_username\":\"admin\"}");

    Json::Value json = userPrefs.ConvertToJson();

    EXPECT_TRUE(json.isMember("userId"));
    EXPECT_TRUE(json.isMember("printerId"));
    EXPECT_TRUE(json.isMember("vendorOptions"));
    EXPECT_EQ(json["userId"].asInt(), 100);
    EXPECT_EQ(json["printerId"].asString(), "printer_001");
    EXPECT_EQ(json["vendorOptions"].asString(), "{\"user_username\":\"admin\"}");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_NoVendorOptions_JsonWithoutVendorOptions, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    userPrefs.SetPrinterId("printer_001");

    Json::Value json = userPrefs.ConvertToJson();

    EXPECT_TRUE(json.isMember("userId"));
    EXPECT_TRUE(json.isMember("printerId"));
    EXPECT_FALSE(json.isMember("vendorOptions"));
    EXPECT_EQ(json["userId"].asInt(), 100);
    EXPECT_EQ(json["printerId"].asString(), "printer_001");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_AllFieldsEmpty_JsonWithDefaults, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    Json::Value json = userPrefs.ConvertToJson();

    EXPECT_TRUE(json.isMember("userId"));
    EXPECT_TRUE(json.isMember("printerId"));
    EXPECT_FALSE(json.isMember("vendorOptions"));
    EXPECT_EQ(json["userId"].asInt(), 0);
    EXPECT_EQ(json["printerId"].asString(), "");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CompleteJson_AllFieldsSet, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 200;
    json["printerId"] = "printer_002";
    json["vendorOptions"] = "{\"user_token\":\"abc123\"}";

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 200);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_002");
    EXPECT_EQ(userPrefs.GetVendorOptions(), "{\"user_token\":\"abc123\"}");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_PartialJson_OnlySetPresentFields, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 300;
    json["printerId"] = "printer_003";

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 300);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_003");
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
    EXPECT_FALSE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_InvalidUserIdType_FieldNotSet, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = "invalid_string";
    json["printerId"] = "printer_004";

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 0);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_004");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_InvalidPrinterIdType_FieldNotSet, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 400;
    json["printerId"] = 12345;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 400);
    EXPECT_EQ(userPrefs.GetPrinterId(), "");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_InvalidVendorOptionsType_FieldNotSet, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 500;
    json["printerId"] = "printer_005";
    json["vendorOptions"] = 12345;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 500);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_005");
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
    EXPECT_FALSE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_MissingAllFields_AllFieldsDefault, TestSize.Level1)
{
    Json::Value json;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 0);
    EXPECT_EQ(userPrefs.GetPrinterId(), "");
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
    EXPECT_FALSE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJsonAndFromJson_RoundTrip_ValuesPreserved, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetUserId(600);
    original.SetPrinterId("printer_006");
    original.SetVendorOptions("{\"user_session\":\"xyz789\"}");

    Json::Value json = original.ConvertToJson();

    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);

    EXPECT_EQ(restored.GetUserId(), original.GetUserId());
    EXPECT_EQ(restored.GetPrinterId(), original.GetPrinterId());
    EXPECT_EQ(restored.GetVendorOptions(), original.GetVendorOptions());
    EXPECT_EQ(restored.HasVendorOptions(), original.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJsonAndFromJson_NoVendorOptionsRoundTrip_ValuesPreserved, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetUserId(700);
    original.SetPrinterId("printer_007");

    Json::Value json = original.ConvertToJson();

    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);

    EXPECT_EQ(restored.GetUserId(), original.GetUserId());
    EXPECT_EQ(restored.GetPrinterId(), original.GetPrinterId());
    EXPECT_EQ(restored.GetVendorOptions(), "");
    EXPECT_FALSE(restored.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, MultipleSetOperations_AllFieldsUpdated, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetUserId(100);
    userPrefs.SetPrinterId("printer_100");
    userPrefs.SetVendorOptions("{\"field1\":\"value1\"}");

    EXPECT_EQ(userPrefs.GetUserId(), 100);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_100");
    EXPECT_TRUE(userPrefs.HasVendorOptions());

    userPrefs.SetUserId(200);
    userPrefs.SetPrinterId("printer_200");
    userPrefs.SetVendorOptions("{\"field2\":\"value2\"}");

    EXPECT_EQ(userPrefs.GetUserId(), 200);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_200");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), "{\"field2\":\"value2\"}");
}

HWTEST_F(PrinterUserPreferencesTest, VendorOptionsWithUserPrefix_ValidJson_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    std::string vendorOptions = "{\"user_username\":\"admin\",\"user_password\":\"secret\",\"color\":\"color\"}";
    userPrefs.SetVendorOptions(vendorOptions);

    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), vendorOptions);
}

HWTEST_F(PrinterUserPreferencesTest, VendorOptionsWithNestedJson_ValidJson_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    Json::Value nestedJson;
    nestedJson["user_settings"]["username"] = "admin";
    nestedJson["user_settings"]["password"] = "secret";
    nestedJson["global_settings"]["paperSize"] = "A4";

    std::string vendorOptions = PrintJsonUtil::WriteString(nestedJson);
    userPrefs.SetVendorOptions(vendorOptions);

    EXPECT_TRUE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, Dump_AllFieldsSet_LogsCorrectly, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(800);
    userPrefs.SetPrinterId("printer_008");
    userPrefs.SetVendorOptions("{\"user_field\":\"value\"}");

    userPrefs.Dump();

    EXPECT_EQ(userPrefs.GetUserId(), 800);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_008");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, Dump_AllFieldsEmpty_LogsCorrectly, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.Dump();

    EXPECT_EQ(userPrefs.GetUserId(), 0);
    EXPECT_EQ(userPrefs.GetPrinterId(), "");
    EXPECT_FALSE(userPrefs.HasVendorOptions());
}

} // namespace Print
} // namespace OHOS