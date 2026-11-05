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

HWTEST_F(PrintServiceAbilityTest, DeletePrinterFromUserData_DeletesUserPreferences, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    std::string printerId = "printer_001";
    std::string standardizedPrinterName = "TestPrinter";
    int32_t userId1 = 100;
    int32_t userId2 = 101;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(standardizedPrinterName);
    service->printSystemData_.InsertAddedPrinter(printerId, printerInfo);

    std::shared_ptr<PrintUserData> userData1 = std::make_shared<PrintUserData>();
    userData1->SetUserId(userId1);
    PrinterUserPreferences userPrefs1;
    userPrefs1.SetUserId(userId1);
    userPrefs1.SetPrinterId(printerId);
    userPrefs1.SetVendorOptions(R"({"user_field":"value1"})");
    userData1->SavePrinterUserPreferences(printerId, standardizedPrinterName, userPrefs1);
    userData1->SetDefaultPrinter(printerId, 0);
    service->printUserMap_[userId1] = userData1;

    std::shared_ptr<PrintUserData> userData2 = std::make_shared<PrintUserData>();
    userData2->SetUserId(userId2);
    PrinterUserPreferences userPrefs2;
    userPrefs2.SetUserId(userId2);
    userPrefs2.SetPrinterId(printerId);
    userPrefs2.SetVendorOptions(R"({"user_field":"value2"})");
    userData2->SavePrinterUserPreferences(printerId, standardizedPrinterName, userPrefs2);
    service->printUserMap_[userId2] = userData2;

    EXPECT_TRUE(userData1->printerUserPreferences_.count(printerId) > 0);
    EXPECT_TRUE(userData2->printerUserPreferences_.count(printerId) > 0);

    userData1->DeletePrinterUserPreferences(printerId, standardizedPrinterName);
    userData2->DeletePrinterUserPreferences(printerId, standardizedPrinterName);

    EXPECT_FALSE(userData1->printerUserPreferences_.count(printerId) > 0);
    EXPECT_FALSE(userData2->printerUserPreferences_.count(printerId) > 0);
}

HWTEST_F(PrintServiceAbilityTest, SetPrinterPreference_NoDiscoveredPrinter_InvalidPrinter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    PrinterPreferences preferences;
    preferences.SetBorderless(true);
    EXPECT_EQ(service->SetPrinterPreference(printerId, preferences), E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, SetPrinterPreference_AddedPrinterId_NoError, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerId = "123";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    PrinterPreferences preferences;
    preferences.SetBorderless(true);
    service->printSystemData_.InsertAddedPrinter(printerId, info);
    EXPECT_EQ(service->SetPrinterPreference(printerId, preferences), E_PRINT_NONE);
}

HWTEST_F(
    PrintServiceAbilityTest, UpdatePrintJobOptionWithPrinterPreferences_NoValueSet_NoAdvancedOptions, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    Json::Value jobOptions;
    PrinterPreferences preferences;
    PrinterUserPreferences userPrefs;
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, preferences, userPrefs);
    EXPECT_EQ(jobOptions.isMember("advancedOptions"), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobOptionWithPrinterPreferences_SetWrongTypeValue_NoAdvancedOptions,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    Json::Value jobOptions;
    jobOptions["isReverse"] = "isReverse";
    jobOptions["isCollate"] = "isCollate";
    PrinterPreferences preferences;
    PrinterUserPreferences userPrefs;
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, preferences, userPrefs);
    EXPECT_EQ(jobOptions.isMember("advancedOptions"), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobOptionWithPrinterPreferences_SetCorrectValue_HasAdvancedOptions,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    Json::Value jobOptions;
    jobOptions["isReverse"] = true;
    jobOptions["isCollate"] = true;
    Json::Value preferenceOptions;
    preferenceOptions["key"] = "value";
    PrinterPreferences preferences;
    preferences.SetOption(PrintJsonUtil::WriteString(preferenceOptions));
    PrinterUserPreferences userPrefs;
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, preferences, userPrefs);
    EXPECT_EQ(jobOptions.isMember("advancedOptions"), true);
}

HWTEST_F(PrintServiceAbilityTest, CheckPreferencesConflicts_NoPermission, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    std::string printerId = GetDefaultPrinterId();
    PrinterPreferences printerPreference;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    int32_t ret = service->CheckPreferencesConflicts(
        printerId, PRINT_PARAM_TYPE_PAGE_SIZE, printerPreference, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
#endif
}

HWTEST_F(PrintServiceAbilityTest, CheckPreferencesConflicts_InvalidPrinterId, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    std::string printerId = GetInvalidPrinterId();
    PrinterPreferences printerPreference;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);

    int32_t ret = service->CheckPreferencesConflicts(
        printerId, PRINT_PARAM_TYPE_PAGE_SIZE, printerPreference, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_TRUE(conflictingOptions.empty());
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterDefaultPreferences_NoPermission, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    std::string printerId = GetInvalidPrinterId();
    PrinterPreferences defaultPreferences;
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    int32_t ret = service->GetPrinterDefaultPreferences(printerId, defaultPreferences);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterDefaultPreferences_InvalidPrinterId, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    PrintServiceMockPermission::MockPermission();
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(_, _))
        .WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(*service, QueryPPDInformation(_, _))
        .WillOnce(Return(false))
        .WillOnce([](const std::string &makeModel, std::string &ppdName) {
            ppdName = "TestNone.ppd";
            return true;
        });
    std::string printerId = GetDefaultPrinterId();
    PrinterPreferences defaultPreferences;
    int32_t ret = service->GetPrinterDefaultPreferences(printerId, defaultPreferences);
    EXPECT_NE(ret, E_PRINT_NONE);
    ret = service->GetPrinterDefaultPreferences(printerId, defaultPreferences);
    EXPECT_NE(ret, E_PRINT_NONE);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_NoPermission, TestSize.Level1)
{
    std::string printerId = GetInvalidPrinterId();
    PrinterPreferences printerPreference;
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(false));
    service->SetHelper(mockHelper);

    int32_t ret = service->GetPrinterPreference(printerId, printerPreference);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_InvalidPrinterId, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);

    std::string printerId = GetInvalidPrinterId();
    PrinterPreferences printerPreference;
    int32_t ret = service->GetPrinterPreference(printerId, printerPreference);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_PrinterExists_NoUserData, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);

    std::string printerId = "test_printer_001";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName("Test Printer");
    PrinterPreferences prefs;
    prefs.SetDefaultDuplexMode(DUPLEX_MODE_LONG_EDGE);
    info.SetPreferences(prefs);
    service->printSystemData_.InsertAddedPrinter(printerId, info);
    service->currentUserId_ = 100;
    PrinterPreferences result;
    int32_t ret = service->GetPrinterPreference(printerId, result);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(result.GetDefaultDuplexMode(), DUPLEX_MODE_LONG_EDGE);
    service->printSystemData_.DeleteAddedPrinter(printerId, "Test Printer");
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_PrinterExists_UserDataExists_NoUserPrefs, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_)).WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);

    std::string printerId = "test_printer_002";
    int32_t userId = 100;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName("Test Printer 2");
    PrinterPreferences prefs;
    prefs.SetDefaultColorMode(PRINT_COLOR_MODE_COLOR);
    info.SetPreferences(prefs);
    service->printSystemData_.InsertAddedPrinter(printerId, info);
    service->currentUserId_ = userId;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserMap_[userId] = userData;
    PrinterPreferences result;
    int32_t ret = service->GetPrinterPreference(printerId, result);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(result.GetDefaultColorMode(), PRINT_COLOR_MODE_COLOR);
    service->printSystemData_.DeleteAddedPrinter(printerId, "Test Printer 2");
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferences_EmptyKeys_ReturnsWithoutModify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo printerInfo;
    PrinterPreferences preferences;
    preferences.SetOption(R"({"CustomPin":{"choice":"Custom","value":"1234"}})");
    PrinterUserPreferences userPrefs;

    std::set<std::string> emptyKeys;
    service->ExtractCustomOptionsFromPreferenceJson(emptyKeys, preferences, userPrefs);
    std::string option = preferences.GetOption();
    EXPECT_FALSE(option.empty());
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferences_EmptyOption_ReturnsWithoutModify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    preferences.SetOption("");
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);
    std::string option = preferences.GetOption();
    EXPECT_TRUE(option.empty());
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferences_InvalidJson_ReturnsWithoutModify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    preferences.SetOption("invalid json");
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);
    std::string option = preferences.GetOption();
    EXPECT_EQ(option, "invalid json");
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferences_NonCustomChoice_RemovesKey, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = "Standard";
    pinOption["value"] = "";
    prefJson["CustomPin"] = pinOption;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    auto extractedOpt = userPrefs.GetCustomOption("CustomPin");
    ASSERT_NE(extractedOpt, nullptr);
    EXPECT_EQ(extractedOpt->choice, "Standard");
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferences_CustomChoiceWithValue_ProcessesOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = CUSTOM_OPTION_CHOICE;
    pinOption["value"] = "1234";
    prefJson["CustomPin"] = pinOption;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    auto allKeys = userPrefs.GetAllCustomOptionKeys();
    EXPECT_TRUE(std::find(allKeys.begin(), allKeys.end(), "CustomPin") != allKeys.end());
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferences_JsonObjectValue_ProcessesOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = CUSTOM_OPTION_CHOICE;
    pinOption["value"] = "1234";
    prefJson["CustomPin"] = pinOption;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    EXPECT_TRUE(PrintJsonUtil::Parse(preferences.GetOption(), updatedJson));
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    auto allKeys2 = userPrefs.GetAllCustomOptionKeys();
    EXPECT_TRUE(std::find(allKeys2.begin(), allKeys2.end(), "CustomPin") != allKeys2.end());
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferences_KeyNotInOption_SkipsKey, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    prefJson["OtherKey"] = "value";
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_TRUE(updatedJson.isMember("OtherKey"));
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferences_NoCapability_ReturnsWithoutModify, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo printerInfo;
    PrinterPreferences preferences;
    PrinterUserPreferences userPrefs;

    service->ExtractCustomOptionsFromPreferences(printerInfo, preferences, userPrefs);
    EXPECT_TRUE(userPrefs.GetAllCustomOptionKeys().empty());
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferenceJson_CustomChoiceEmptyValue_SkipsNonObject, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = CUSTOM_OPTION_CHOICE;
    pinOption["value"] = "";
    prefJson["CustomPin"] = PrintJsonUtil::WriteString(pinOption);
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    EXPECT_EQ(userPrefs.GetAllCustomOptionKeys().size(), 0u);
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferenceJson_OptionValueIsString_SkipsAndRemoves,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    prefJson["CustomPin"] = "invalid json string";
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    EXPECT_EQ(userPrefs.GetAllCustomOptionKeys().size(), 0u);
}

HWTEST_F(PrintServiceAbilityTest, ConvertModifiedPreferencesToJson_UserDataNull_ReturnsWithoutDecrypt, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    prefJson["key"] = "value";
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    Json::Value result = service->ConvertModifiedPreferencesToJson(preferences, userPrefs);
    EXPECT_TRUE(result.isObject());
    EXPECT_TRUE(result.isMember("key"));
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferenceJson_KeyIsNotString_SkipsKey, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    prefJson["CustomPin"] = 123;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferenceJson_HasModified_UpdatesPreferences, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = "Standard";
    pinOption["value"] = "";
    prefJson["CustomPin"] = pinOption;
    prefJson["OtherKey"] = "OtherValue";
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    EXPECT_TRUE(updatedJson.isMember("OtherKey"));
}

HWTEST_F(PrintServiceAbilityTest,
    ExtractCustomOptionsFromPreferences_CustomOptionKeysNotEmpty_EmptyPreferenceOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    Json::Value advanceOptionsArr;
    Json::Value advanceOption1;
    advanceOption1["keyword"] = "CustomPin";
    advanceOption1["customParamType"] = 1;
    advanceOptionsArr.append(advanceOption1);

    Json::Value cupsOptions;
    cupsOptions["advanceOptions"] = PrintJsonUtil::WriteString(advanceOptionsArr);

    Json::Value capOptionJson;
    capOptionJson["cupsOptions"] = cupsOptions;

    PrinterCapability capability;
    capability.SetOption(PrintJsonUtil::WriteString(capOptionJson));

    PrinterInfo printerInfo;
    printerInfo.SetCapability(capability);

    PrinterPreferences preferences;
    preferences.SetOption("");

    PrinterUserPreferences userPrefs;

    service->ExtractCustomOptionsFromPreferences(printerInfo, preferences, userPrefs);

    std::string option = preferences.GetOption();
    EXPECT_TRUE(option.empty());
}

HWTEST_F(PrintServiceAbilityTest, ProcessVendorOptionsForPreference_ValidVendorOptions_SplitsCorrectly, TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;

    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    auto userData = std::make_shared<PrintUserData>();
    userData->SetUserId(100);
    userData->printerUserPreferences_.clear();
    service->printUserMap_[100] = userData;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("test_printer");
    printerInfo.SetPrinterName("test_printer");
    service->printSystemData_.InsertAddedPrinter("test_printer", printerInfo);

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"printer_field":"printer_value","user_field":"user_value"})");

    PrinterPreferences printerPrefs;
    int32_t result = service->ProcessVendorOptionsForPreference("test_printer", preferences, printerPrefs);
    EXPECT_EQ(result, E_PRINT_NONE);

    std::string resultVendorOptions = printerPrefs.GetVendorOptions();
    EXPECT_FALSE(resultVendorOptions.empty());
    Json::Value resultJson;
    PrintJsonUtil::Parse(resultVendorOptions, resultJson);
    EXPECT_TRUE(resultJson.isMember("printer_field"));
    EXPECT_FALSE(resultJson.isMember("user_field"));

    auto savedUserPrefs = userData->printerUserPreferences_["test_printer"];
    EXPECT_NE(savedUserPrefs, nullptr);
    EXPECT_TRUE(savedUserPrefs->HasVendorOptions());
    Json::Value userJson;
    PrintJsonUtil::Parse(savedUserPrefs->GetVendorOptions(), userJson);
    EXPECT_TRUE(userJson.isMember("user_field"));
    EXPECT_FALSE(userJson.isMember("printer_field"));
}

HWTEST_F(PrintServiceAbilityTest, ProcessVendorOptionsForPreference_EmptyVendorOptions_ClearsUserPrefs, TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;

    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    auto userData = std::make_shared<PrintUserData>();
    userData->SetUserId(100);
    PrinterUserPreferences existingPrefs;
    existingPrefs.SetUserId(100);
    existingPrefs.SetPrinterId("test_printer");
    existingPrefs.SetVendorOptions(R"({"old_user_field":"old_value"})");
    userData->printerUserPreferences_["test_printer"] = std::make_shared<PrinterUserPreferences>(existingPrefs);
    service->printUserMap_[100] = userData;
    EXPECT_EQ(userData->printerUserPreferences_.size(), 1);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("test_printer");
    printerInfo.SetPrinterName("test_printer");
    service->printSystemData_.InsertAddedPrinter("test_printer", printerInfo);

    PrinterPreferences preferences;
    preferences.SetVendorOptions("");

    PrinterPreferences printerPrefs;
    int32_t result = service->ProcessVendorOptionsForPreference("test_printer", preferences, printerPrefs);
    EXPECT_EQ(result, E_PRINT_NONE);

    EXPECT_EQ(userData->printerUserPreferences_.size(), 0);
}

HWTEST_F(PrintServiceAbilityTest, ProcessVendorOptionsForPreference_OnlyPrinterOptions_NoUserPrefsSaved,
    TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;

    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    auto userData = std::make_shared<PrintUserData>();
    userData->SetUserId(100);
    userData->printerUserPreferences_.clear();
    service->printUserMap_[100] = userData;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("test_printer");
    printerInfo.SetPrinterName("test_printer");
    service->printSystemData_.InsertAddedPrinter("test_printer", printerInfo);

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"printer_field":"value"})");

    PrinterPreferences printerPrefs;
    int32_t result = service->ProcessVendorOptionsForPreference("test_printer", preferences, printerPrefs);
    EXPECT_EQ(result, E_PRINT_NONE);

    EXPECT_EQ(userData->printerUserPreferences_.size(), 0);
    EXPECT_EQ(printerPrefs.GetVendorOptions(), R"({"printer_field":"value"})");
}

HWTEST_F(PrintServiceAbilityTest, ProcessVendorOptionsForPreference_OnlyUserOptions_SavesUserPrefs, TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;

    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    auto userData = std::make_shared<PrintUserData>();
    userData->SetUserId(100);
    userData->printerUserPreferences_.clear();
    service->printUserMap_[100] = userData;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId("test_printer");
    printerInfo.SetPrinterName("test_printer");
    service->printSystemData_.InsertAddedPrinter("test_printer", printerInfo);

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"user_field":"user_value"})");

    PrinterPreferences printerPrefs;
    int32_t result = service->ProcessVendorOptionsForPreference("test_printer", preferences, printerPrefs);
    EXPECT_EQ(result, E_PRINT_NONE);

    EXPECT_EQ(userData->printerUserPreferences_.size(), 1);
    auto savedPrefs = userData->printerUserPreferences_["test_printer"];
    EXPECT_NE(savedPrefs, nullptr);
    EXPECT_EQ(savedPrefs->GetVendorOptions(), R"({"user_field":"user_value"})");
    EXPECT_TRUE(printerPrefs.GetVendorOptions().empty());
}

HWTEST_F(PrintServiceAbilityTest, ProcessVendorOptionsForPreference_InvalidPrinterId_ReturnsInvalidPrinter,
    TestSize.Level1)
{
    OHOS::uid_ = 100 * 200000;

    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    PrinterPreferences preferences;
    preferences.SetVendorOptions(R"({"field":"value"})");

    PrinterPreferences printerPrefs;
    int32_t result = service->ProcessVendorOptionsForPreference("invalid_printer_id", preferences, printerPrefs);
    EXPECT_EQ(result, E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferenceJson_ChoiceNotMember_SkipsKey, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["value"] = "1234";
    prefJson["CustomPin"] = pinOption;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    EXPECT_EQ(userPrefs.GetCustomOption("CustomPin"), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, ExtractCustomOptionsFromPreferenceJson_ChoiceNotString_SkipsKey, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    PrinterPreferences preferences;
    Json::Value prefJson;
    Json::Value pinOption;
    pinOption["choice"] = 123;
    pinOption["value"] = "1234";
    prefJson["CustomPin"] = pinOption;
    preferences.SetOption(PrintJsonUtil::WriteString(prefJson));
    PrinterUserPreferences userPrefs;

    std::set<std::string> keys;
    keys.insert("CustomPin");
    service->ExtractCustomOptionsFromPreferenceJson(keys, preferences, userPrefs);

    Json::Value updatedJson;
    PrintJsonUtil::Parse(preferences.GetOption(), updatedJson);
    EXPECT_FALSE(updatedJson.isMember("CustomPin"));
    EXPECT_EQ(userPrefs.GetCustomOption("CustomPin"), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, ProcessSingleCustomOption_ValueNotMember_SetsEmptyChoice, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    Json::Value optionJson;
    optionJson["choice"] = CUSTOM_OPTION_CHOICE;
    PrinterUserPreferences userPrefs;

    service->ProcessSingleCustomOption("CustomPin", optionJson, userPrefs);

    EXPECT_EQ(userPrefs.GetCustomOption("CustomPin"), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, ProcessSingleCustomOption_ValueNotString_SetsEmptyChoice, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    Json::Value optionJson;
    optionJson["choice"] = CUSTOM_OPTION_CHOICE;
    optionJson["value"] = 123;
    PrinterUserPreferences userPrefs;

    service->ProcessSingleCustomOption("CustomPin", optionJson, userPrefs);

    EXPECT_EQ(userPrefs.GetCustomOption("CustomPin"), nullptr);
}

}  // namespace Print
}  // namespace OHOS
