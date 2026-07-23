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
#include "print_constant.h"
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
    original.SetVendorOptions(R"({"user_username":"admin"})");

    PrinterUserPreferences copy(original);

    EXPECT_EQ(copy.GetUserId(), 100);
    EXPECT_EQ(copy.GetPrinterId(), "printer_001");
    EXPECT_EQ(copy.GetVendorOptions(), R"({"user_username":"admin"})");
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

    userPrefs.SetVendorOptions(R"({"user_username":"admin","user_password":"123456"})");

    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), R"({"user_username":"admin","user_password":"123456"})");
}

HWTEST_F(PrinterUserPreferencesTest, SetVendorOptions_EmptyString_HasVendorOptionsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetVendorOptions(R"({"user_field":"value"})");

    userPrefs.SetVendorOptions("");

    EXPECT_FALSE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), "");
}

HWTEST_F(PrinterUserPreferencesTest, SetVendorOptions_OverridePreviousValue_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    userPrefs.SetVendorOptions(R"({"old_field":"old_value"})");
    EXPECT_TRUE(userPrefs.HasVendorOptions());

    userPrefs.SetVendorOptions(R"({"new_field":"new_value"})");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), R"({"new_field":"new_value"})");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_AllFieldsSet_JsonComplete, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    userPrefs.SetPrinterId("printer_001");
    userPrefs.SetVendorOptions(R"({"user_username":"admin"})");

    Json::Value json = userPrefs.ConvertToJson();

    EXPECT_TRUE(json.isMember("userId"));
    EXPECT_TRUE(json.isMember("printerId"));
    EXPECT_TRUE(json.isMember("vendorOptions"));
    EXPECT_EQ(json["userId"].asInt(), 100);
    EXPECT_EQ(json["printerId"].asString(), "printer_001");
    EXPECT_EQ(json["vendorOptions"].asString(), R"({"user_username":"admin"})");
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
    json["vendorOptions"] = R"({"user_token":"abc123"})";

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 200);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_002");
    EXPECT_EQ(userPrefs.GetVendorOptions(), R"({"user_token":"abc123"})");
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
    original.SetVendorOptions(R"({"user_session":"xyz789"})");

    Json::Value json = original.ConvertToJson();

    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);

    EXPECT_EQ(restored.GetUserId(), original.GetUserId());
    EXPECT_EQ(restored.GetPrinterId(), original.GetPrinterId());
    EXPECT_EQ(restored.GetVendorOptions(), original.GetVendorOptions());
    EXPECT_EQ(restored.HasVendorOptions(), original.HasVendorOptions());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJsonAndFromJson_NoVendorOptionsRoundTrip_ValuesPreserved,
    TestSize.Level1)
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
    userPrefs.SetVendorOptions(R"({"field1":"value1"})");

    EXPECT_EQ(userPrefs.GetUserId(), 100);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_100");
    EXPECT_TRUE(userPrefs.HasVendorOptions());

    userPrefs.SetUserId(200);
    userPrefs.SetPrinterId("printer_200");
    userPrefs.SetVendorOptions(R"({"field2":"value2"})");

    EXPECT_EQ(userPrefs.GetUserId(), 200);
    EXPECT_EQ(userPrefs.GetPrinterId(), "printer_200");
    EXPECT_TRUE(userPrefs.HasVendorOptions());
    EXPECT_EQ(userPrefs.GetVendorOptions(), R"({"field2":"value2"})");
}

HWTEST_F(PrinterUserPreferencesTest, VendorOptionsWithUserPrefix_ValidJson_Succeeds, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;

    std::string vendorOptions = R"({"user_username":"admin","user_password":"secret","color":"color"})";
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
    userPrefs.SetVendorOptions(R"({"user_field":"value"})");

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

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_HasVendorOptions_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetVendorOptions(R"({"key":"value"})");
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_NoVendorOptions_NoCustomOptions_ReturnsTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    EXPECT_TRUE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_OnlyUnsetCustomOptions_ReturnsTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    SecureBlob value;
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    userPrefs.SetCustomOption("key1", "");
    EXPECT_TRUE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_HasSetCustomOption_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_MixedCustomOptions_HasSet_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    userPrefs.SetCustomOption("key2", "");
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_NonCustomChoice_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetCustomOption("key1", "Standard");
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, SetCustomOption_NonCustomChoice_ClearsValue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    userPrefs.SetCustomOption("key1", "Standard");
    auto opt = userPrefs.GetCustomOption("key1");
    ASSERT_NE(opt, nullptr);
    EXPECT_EQ(opt->choice, "Standard");
    EXPECT_TRUE(opt->value.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, GetCustomOption_ExistingKey_ReturnsCorrectData, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x0A, 0x0B};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);

    auto opt = userPrefs.GetCustomOption("key1");
    ASSERT_NE(opt, nullptr);
    EXPECT_EQ(opt->key, "key1");
    EXPECT_EQ(opt->choice, CUSTOM_OPTION_CHOICE);
    EXPECT_EQ(opt->value.size, 2u);
}

HWTEST_F(PrinterUserPreferencesTest, GetCustomOption_NonExistentKey_ReturnsNullptr, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    EXPECT_EQ(userPrefs.GetCustomOption("nonexistent"), nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, GetCustomOption_EmptyChoice_ReturnsNullptr, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetCustomOption("key1", "");
    EXPECT_EQ(userPrefs.GetCustomOption("key1"), nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, RemoveCustomOption_ExistingKey_RemovesEntry, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    userPrefs.RemoveCustomOption("key1");
    EXPECT_EQ(userPrefs.GetCustomOption("key1"), nullptr);
    EXPECT_TRUE(userPrefs.GetAllCustomOptionKeys().empty());
}

HWTEST_F(PrinterUserPreferencesTest, GetAllCustomOptionKeys_ReturnsAllKeys, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    userPrefs.SetCustomOption("key2", "");
    userPrefs.SetCustomOption("key3", "Standard");

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 3u);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJsonAndFromJson_WithCustomOptions_RoundTripPreserved,
    TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetUserId(100);
    original.SetPrinterId("printer_001");
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob value(sizeof(data), data);
    original.SetCustomOption("opt1", CUSTOM_OPTION_CHOICE, value);
    original.SetCustomOption("opt2", "Standard");

    Json::Value json = original.ConvertToJson();

    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);

    EXPECT_EQ(restored.GetUserId(), 100);
    EXPECT_EQ(restored.GetPrinterId(), "printer_001");

    auto opt1 = restored.GetCustomOption("opt1");
    ASSERT_NE(opt1, nullptr);
    EXPECT_EQ(opt1->choice, CUSTOM_OPTION_CHOICE);
    EXPECT_EQ(opt1->value.size, 3u);

    auto opt2 = restored.GetCustomOption("opt2");
    ASSERT_NE(opt2, nullptr);
    EXPECT_EQ(opt2->choice, "Standard");
    EXPECT_TRUE(opt2->value.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, SetData_NullPtr_RemainsEmpty, TestSize.Level1)
{
    SecureBlob blob;
    blob.SetData(nullptr, 5);
    EXPECT_TRUE(blob.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, SetData_ZeroSize_RemainsEmpty, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02};
    SecureBlob blob;
    blob.SetData(data, 0);
    EXPECT_TRUE(blob.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, MoveAssign_TransfersOwnership, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob blob1;
    blob1.SetData(data, sizeof(data));
    EXPECT_EQ(blob1.size, 3u);

    SecureBlob blob2;
    blob2 = std::move(blob1);
    EXPECT_EQ(blob2.size, 3u);
    EXPECT_TRUE(blob1.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, Allocate_ZeroSize_RemainsEmpty, TestSize.Level1)
{
    SecureBlob blob;
    blob.Allocate(0);
    EXPECT_TRUE(blob.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, ToString_EmptyBlob_ReturnsEmpty, TestSize.Level1)
{
    SecureBlob blob;
    EXPECT_EQ(blob.ToString(), "");
}

HWTEST_F(PrinterUserPreferencesTest, TwoArgConstructor_NullPtr_RemainsEmpty, TestSize.Level1)
{
    SecureBlob blob(5, nullptr);
    EXPECT_TRUE(blob.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, TwoArgConstructor_ZeroSize_RemainsEmpty, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02};
    SecureBlob blob(0, data);
    EXPECT_TRUE(blob.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, CopyFromEmpty_RemainsEmpty, TestSize.Level1)
{
    SecureBlob empty;
    SecureBlob copy(empty);
    EXPECT_TRUE(copy.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_IsSetInsteadOfChoice_NoFallback, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 100;
    json["printerId"] = "printer_001";
    Json::Value customOptionsArr;
    Json::Value optJson;
    optJson["key"] = "CustomPin";
    optJson["isSet"] = true;
    customOptionsArr.append(optJson);
    json["customOptions"] = customOptionsArr;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 1u);
    EXPECT_EQ(keys[0], "CustomPin");
    EXPECT_EQ(userPrefs.GetCustomOption("CustomPin"), nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, SecureBlob_SetData_ValidSrc_DataCopied, TestSize.Level1)
{
    SecureBlob blob;
    uint8_t src[] = {0x41, 0x42, 0x43};
    blob.SetData(src, sizeof(src));
    EXPECT_NE(blob.data, nullptr);
    EXPECT_EQ(blob.size, sizeof(src));
    EXPECT_EQ(blob.data[0], 0x41);
    EXPECT_EQ(blob.data[1], 0x42);
    EXPECT_EQ(blob.data[2], 0x43);
}

HWTEST_F(PrinterUserPreferencesTest, SecureBlob_SetData_OverwritePrevious_NewDataSet, TestSize.Level1)
{
    SecureBlob blob;
    uint8_t src1[] = {0x01, 0x02};
    blob.SetData(src1, sizeof(src1));
    EXPECT_EQ(blob.size, sizeof(src1));

    uint8_t src2[] = {0x03, 0x04, 0x05};
    blob.SetData(src2, sizeof(src2));
    EXPECT_EQ(blob.size, sizeof(src2));
    EXPECT_EQ(blob.data[0], 0x03);
    EXPECT_EQ(blob.data[1], 0x04);
    EXPECT_EQ(blob.data[2], 0x05);
}

HWTEST_F(PrinterUserPreferencesTest, SecureBlob_Allocate_PositiveSize_DataAllocated, TestSize.Level1)
{
    SecureBlob blob;
    blob.Allocate(16);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_EQ(blob.size, 16);
}

HWTEST_F(PrinterUserPreferencesTest, SecureBlob_Allocate_OverwritePrevious_NewAllocated, TestSize.Level1)
{
    SecureBlob blob;
    uint8_t src[] = {0x01, 0x02};
    blob.SetData(src, sizeof(src));
    EXPECT_EQ(blob.size, sizeof(src));

    blob.Allocate(32);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_EQ(blob.size, 32);
}

HWTEST_F(PrinterUserPreferencesTest, SecureBlob_ToString_ValidData_ReturnsString, TestSize.Level1)
{
    SecureBlob blob;
    const char *str = "hello";
    blob.SetData(reinterpret_cast<const uint8_t *>(str), strlen(str));
    EXPECT_EQ(blob.ToString(), "hello");
}

HWTEST_F(PrinterUserPreferencesTest, RemoveCustomOption_KeyNotFound_NoChange, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);

    userPrefs.RemoveCustomOption("nonexistent");
    EXPECT_NE(userPrefs.GetCustomOption("key1"), nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsNonObjectElement_Skipped, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 100;
    json["customOptions"].append(42);

    Json::Value validOpt;
    validOpt["key"] = "size";
    validOpt["choice"] = "A4";
    json["customOptions"].append(validOpt);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 1u);
    EXPECT_EQ(keys[0], "size");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsKeyNotString_DefaultKey, TestSize.Level1)
{
    Json::Value json;
    Json::Value optJson;
    optJson["key"] = 123;
    optJson["choice"] = "Standard";
    json["customOptions"].append(optJson);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 1u);
    EXPECT_EQ(keys[0], "");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsValueString_ValueSet, TestSize.Level1)
{
    Json::Value json;
    Json::Value optJson;
    optJson["key"] = "color";
    optJson["choice"] = "auto";
    optJson["value"] = "red";
    json["customOptions"].append(optJson);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto opt = userPrefs.GetCustomOption("color");
    ASSERT_NE(opt, nullptr);
    EXPECT_EQ(opt->key, "color");
    EXPECT_EQ(opt->choice, "auto");
    EXPECT_EQ(opt->value.ToString(), "red");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsIsSetFalse_BackwardCompat, TestSize.Level1)
{
    Json::Value json;
    Json::Value optJson;
    optJson["key"] = "duplex";
    optJson["isSet"] = false;
    json["customOptions"].append(optJson);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 1u);
    auto opt = userPrefs.GetCustomOption("duplex");
    EXPECT_EQ(opt, nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsChoiceAndIsSetNeitherValid_DefaultChoice,
    TestSize.Level1)
{
    Json::Value json;
    Json::Value optJson;
    optJson["key"] = "media";
    optJson["choice"] = 123;
    optJson["isSet"] = "yes";
    json["customOptions"].append(optJson);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto keys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_EQ(keys.size(), 1u);
    auto opt = userPrefs.GetCustomOption("media");
    EXPECT_EQ(opt, nullptr);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsValueNotString_NoValueSet, TestSize.Level1)
{
    Json::Value json;
    Json::Value optJson;
    optJson["key"] = "media";
    optJson["choice"] = "A4";
    optJson["value"] = 999;
    json["customOptions"].append(optJson);

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    auto opt = userPrefs.GetCustomOption("media");
    ASSERT_NE(opt, nullptr);
    EXPECT_EQ(opt->choice, "A4");
    EXPECT_TRUE(opt->value.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomOptionsNotArray_NotParsed, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 100;
    json["customOptions"] = "not_an_array";

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 100);
    EXPECT_TRUE(userPrefs.GetAllCustomOptionKeys().empty());
}

} // namespace Print
} // namespace OHOS