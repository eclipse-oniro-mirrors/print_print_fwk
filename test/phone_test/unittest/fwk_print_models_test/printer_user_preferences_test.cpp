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

// ===== Custom page size list (customPageSizes) field Tests =====

static std::vector<PrintPageSize> BuildPrefsTestCustomPageSizeList()
{
    std::vector<PrintPageSize> list;
    constexpr uint32_t width = 8268;
    constexpr uint32_t height = 11693;
    list.emplace_back("custom:12345", "MyForm(210x297mm)", width, height);
    return list;
}

HWTEST_F(PrinterUserPreferencesTest, SetCustomPageSizes_Array_HasCustomPageSizesTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    EXPECT_FALSE(userPrefs.HasCustomPageSizes());
    userPrefs.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());
    EXPECT_TRUE(userPrefs.HasCustomPageSizes());
    const auto &got = userPrefs.GetCustomPageSizes();
    EXPECT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].GetId(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, SetCustomPageSizes_EmptyList_HasCustomPageSizesTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> emptyList;
    userPrefs.SetCustomPageSizes(emptyList);
    EXPECT_TRUE(userPrefs.HasCustomPageSizes());
    EXPECT_TRUE(userPrefs.GetCustomPageSizes().empty());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_WithCustomPageSizes_JsonContainsList, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    userPrefs.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());

    Json::Value json = userPrefs.ConvertToJson();
    ASSERT_TRUE(json.isObject());
    ASSERT_TRUE(json.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    ASSERT_TRUE(json[CUSTOM_PAGE_SIZE_LIST_KEY].isArray());
    EXPECT_EQ(json[CUSTOM_PAGE_SIZE_LIST_KEY].size(), 1);
    Json::Value entry = json[CUSTOM_PAGE_SIZE_LIST_KEY][0];
    EXPECT_EQ(entry[CUSTOM_PAGE_SIZE_ITEM_ID].asString(), "custom:12345");
    EXPECT_EQ(entry[CUSTOM_PAGE_SIZE_ITEM_NAME].asString(), "MyForm(210x297mm)");
    EXPECT_EQ(entry[CUSTOM_PAGE_SIZE_ITEM_WIDTH].asUInt(), 8268u);
    EXPECT_EQ(entry[CUSTOM_PAGE_SIZE_ITEM_HEIGHT].asUInt(), 11693u);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_WithoutCustomPageSizes_JsonWithoutList, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(100);
    Json::Value json = userPrefs.ConvertToJson();
    EXPECT_FALSE(json.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_WithCustomPageSizes_ListParsed, TestSize.Level1)
{
    Json::Value json;
    json["userId"] = 100;
    json["printerId"] = "p1";
    Json::Value listJson(Json::arrayValue);
    Json::Value entry;
    entry[CUSTOM_PAGE_SIZE_ITEM_ID] = "custom:12345";
    entry[CUSTOM_PAGE_SIZE_ITEM_NAME] = "MyForm(210x297mm)";
    entry[CUSTOM_PAGE_SIZE_ITEM_WIDTH] = 8268u;
    entry[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = 11693u;
    listJson.append(entry);
    json[CUSTOM_PAGE_SIZE_LIST_KEY] = listJson;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_EQ(userPrefs.GetUserId(), 100);
    EXPECT_TRUE(userPrefs.HasCustomPageSizes());
    const auto &got = userPrefs.GetCustomPageSizes();
    EXPECT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].GetId(), "custom:12345");
    EXPECT_EQ(got[0].GetName(), "MyForm(210x297mm)");
    EXPECT_EQ(got[0].GetWidth(), 8268u);
    EXPECT_EQ(got[0].GetHeight(), 11693u);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomPageSizesInvalidItemSkipped, TestSize.Level1)
{
    Json::Value listJson(Json::arrayValue);
    // invalid entry: id is not a string (numeric) → must be skipped
    Json::Value invalidEntry;
    invalidEntry[CUSTOM_PAGE_SIZE_ITEM_ID] = 123;
    invalidEntry[CUSTOM_PAGE_SIZE_ITEM_NAME] = "BadEntry";
    invalidEntry[CUSTOM_PAGE_SIZE_ITEM_WIDTH] = 1000u;
    invalidEntry[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = 2000u;
    listJson.append(invalidEntry);
    // invalid entry: width missing → must be skipped
    Json::Value invalidEntry2;
    invalidEntry2[CUSTOM_PAGE_SIZE_ITEM_ID] = "custom:67890";
    invalidEntry2[CUSTOM_PAGE_SIZE_ITEM_NAME] = "NoWidth";
    invalidEntry2[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = 2000u;
    listJson.append(invalidEntry2);
    // valid entry: must be retained
    Json::Value validEntry;
    validEntry[CUSTOM_PAGE_SIZE_ITEM_ID] = "custom:12345";
    validEntry[CUSTOM_PAGE_SIZE_ITEM_NAME] = "MyForm(210x297mm)";
    validEntry[CUSTOM_PAGE_SIZE_ITEM_WIDTH] = 8268u;
    validEntry[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = 11693u;
    listJson.append(validEntry);

    Json::Value json;
    json[CUSTOM_PAGE_SIZE_LIST_KEY] = listJson;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    EXPECT_TRUE(userPrefs.HasCustomPageSizes());
    const auto &got = userPrefs.GetCustomPageSizes();
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].GetId(), "custom:12345");
    EXPECT_EQ(got[0].GetName(), "MyForm(210x297mm)");
    EXPECT_EQ(got[0].GetWidth(), 8268u);
    EXPECT_EQ(got[0].GetHeight(), 11693u);
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomPageSizesAllInvalid_EmptyList, TestSize.Level1)
{
    Json::Value listJson(Json::arrayValue);
    // entry not an object (string) → skipped
    listJson.append("not_an_object");
    // object missing name → skipped
    Json::Value missingName;
    missingName[CUSTOM_PAGE_SIZE_ITEM_ID] = "custom:11111";
    missingName[CUSTOM_PAGE_SIZE_ITEM_WIDTH] = 100u;
    missingName[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = 200u;
    listJson.append(missingName);
    // height not uint (negative int) → skipped
    Json::Value negHeight;
    negHeight[CUSTOM_PAGE_SIZE_ITEM_ID] = "custom:22222";
    negHeight[CUSTOM_PAGE_SIZE_ITEM_NAME] = "Neg";
    negHeight[CUSTOM_PAGE_SIZE_ITEM_WIDTH] = 100u;
    negHeight[CUSTOM_PAGE_SIZE_ITEM_HEIGHT] = -1;
    listJson.append(negHeight);

    Json::Value json;
    json[CUSTOM_PAGE_SIZE_LIST_KEY] = listJson;

    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);

    // SetCustomPageSizes always sets hasCustomPageSizes_=true, but list is empty
    EXPECT_TRUE(userPrefs.HasCustomPageSizes());
    EXPECT_TRUE(userPrefs.GetCustomPageSizes().empty());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_CustomPageSizesNotArray_NotParsed, TestSize.Level1)
{
    Json::Value json;
    json[CUSTOM_PAGE_SIZE_LIST_KEY] = "not_an_array";
    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);
    EXPECT_FALSE(userPrefs.HasCustomPageSizes());
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJsonAndFromJson_CustomPageSizesRoundTrip_Preserved, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetUserId(100);
    original.SetPrinterId("p1");
    original.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());

    Json::Value json = original.ConvertToJson();
    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);

    EXPECT_TRUE(restored.HasCustomPageSizes());
    const auto &got = restored.GetCustomPageSizes();
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].GetId(), "custom:12345");
    EXPECT_EQ(got[0].GetName(), "MyForm(210x297mm)");
    EXPECT_EQ(got[0].GetWidth(), 8268u);
    EXPECT_EQ(got[0].GetHeight(), 11693u);
}

HWTEST_F(PrinterUserPreferencesTest, CopyConstructor_CustomPageSizesCopied, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());
    PrinterUserPreferences copy(original);
    EXPECT_TRUE(copy.HasCustomPageSizes());
    EXPECT_EQ(copy.GetCustomPageSizes().size(), 1u);
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_HasCustomPageSizes_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_EmptyCustomPageSizesArray_ReturnsTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> emptyList;
    userPrefs.SetCustomPageSizes(emptyList);
    EXPECT_TRUE(userPrefs.IsEmpty());
}

// ===== DefaultCustomPageSizeId Tests =====

HWTEST_F(PrinterUserPreferencesTest, SetDefaultCustomPageSizeId_NonEmpty_HasDefaultTrue, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    EXPECT_TRUE(userPrefs.HasDefaultCustomPageSizeId());
    EXPECT_EQ(userPrefs.GetDefaultCustomPageSizeId(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, SetDefaultCustomPageSizeId_Empty_HasDefaultFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    ASSERT_TRUE(userPrefs.HasDefaultCustomPageSizeId());
    // set to empty → hasDefaultCustomPageSizeId_ becomes false
    userPrefs.SetDefaultCustomPageSizeId("");
    EXPECT_FALSE(userPrefs.HasDefaultCustomPageSizeId());
    EXPECT_EQ(userPrefs.GetDefaultCustomPageSizeId(), "");
}

HWTEST_F(PrinterUserPreferencesTest, SetDefaultCustomPageSizeId_Overwrite_PreviousReplaced, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetDefaultCustomPageSizeId("custom:11111");
    userPrefs.SetDefaultCustomPageSizeId("custom:22222");
    EXPECT_EQ(userPrefs.GetDefaultCustomPageSizeId(), "custom:22222");
    EXPECT_TRUE(userPrefs.HasDefaultCustomPageSizeId());
}

HWTEST_F(PrinterUserPreferencesTest, DefaultConstructor_DefaultCustomPageSizeIdNotSet, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    EXPECT_FALSE(userPrefs.HasDefaultCustomPageSizeId());
    EXPECT_EQ(userPrefs.GetDefaultCustomPageSizeId(), "");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_WithDefaultCustomPageSizeId_JsonContainsId, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetPrinterId("printer1");
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    Json::Value json = userPrefs.ConvertToJson();
    EXPECT_TRUE(json.isMember(DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY));
    EXPECT_EQ(json[DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY].asString(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_WithoutDefaultCustomPageSizeId_JsonOmitsId, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetPrinterId("printer1");
    Json::Value json = userPrefs.ConvertToJson();
    EXPECT_FALSE(json.isMember(DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY));
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_WithDefaultCustomPageSizeId_IdParsed, TestSize.Level1)
{
    Json::Value json;
    json["printerId"] = "printer1";
    json[DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY] = "custom:12345";
    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);
    EXPECT_TRUE(userPrefs.HasDefaultCustomPageSizeId());
    EXPECT_EQ(userPrefs.GetDefaultCustomPageSizeId(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertFromJson_DefaultCustomPageSizeIdNotString_NotParsed, TestSize.Level1)
{
    Json::Value json;
    json["printerId"] = "printer1";
    json[DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY] = 123;  // not a string
    PrinterUserPreferences userPrefs;
    userPrefs.ConvertFromJson(json);
    EXPECT_FALSE(userPrefs.HasDefaultCustomPageSizeId());
}

HWTEST_F(PrinterUserPreferencesTest,
    ConvertToJsonAndFromJson_DefaultCustomPageSizeIdRoundTrip_Preserved, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetPrinterId("printer1");
    original.SetDefaultCustomPageSizeId("custom:12345");
    Json::Value json = original.ConvertToJson();

    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);
    EXPECT_TRUE(restored.HasDefaultCustomPageSizeId());
    EXPECT_EQ(restored.GetDefaultCustomPageSizeId(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_HasDefaultCustomPageSizeId_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    EXPECT_FALSE(userPrefs.IsEmpty());
}

HWTEST_F(PrinterUserPreferencesTest, CopyConstructor_DefaultCustomPageSizeIdCopied, TestSize.Level1)
{
    PrinterUserPreferences original;
    original.SetDefaultCustomPageSizeId("custom:12345");
    PrinterUserPreferences copy(original);
    EXPECT_TRUE(copy.HasDefaultCustomPageSizeId());
    EXPECT_EQ(copy.GetDefaultCustomPageSizeId(), "custom:12345");
}

HWTEST_F(PrinterUserPreferencesTest, ConvertToJson_BothCustomPageSizesAndDefaultId_JsonComplete, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetPrinterId("printer1");
    userPrefs.SetCustomPageSizes(BuildPrefsTestCustomPageSizeList());
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    Json::Value json = userPrefs.ConvertToJson();
    EXPECT_TRUE(json.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    EXPECT_TRUE(json.isMember(DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY));
    EXPECT_EQ(json[DEFAULT_CUSTOM_PAGE_SIZE_ID_KEY].asString(), "custom:12345");
    EXPECT_EQ(json[CUSTOM_PAGE_SIZE_LIST_KEY].size(), 1u);
}

// ===== Custom options Tests =====

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

HWTEST_F(PrinterUserPreferencesTest, IsEmpty_HasSetCustomOption_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    uint8_t data[] = {0x01, 0x02, 0x03};
    SecureBlob value(sizeof(data), data);
    userPrefs.SetCustomOption("key1", CUSTOM_OPTION_CHOICE, value);
    EXPECT_FALSE(userPrefs.IsEmpty());
}

// Covers: hasCustomPageSizes_=true with empty list falls through line 242,
// then hasDefaultCustomPageSizeId_=true takes the return false branch at 246.
HWTEST_F(PrinterUserPreferencesTest, IsEmpty_EmptyCustomPageSizesWithDefaultId_ReturnsFalse, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> emptyList;
    userPrefs.SetCustomPageSizes(emptyList);
    userPrefs.SetDefaultCustomPageSizeId("custom:12345");
    EXPECT_FALSE(userPrefs.IsEmpty());
}
} // namespace Print
} // namespace OHOS
