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
    PrinterInfo printerInfo;
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, printerInfo);
    EXPECT_EQ(jobOptions.isMember("advancedOptions"), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobOptionWithPrinterPreferences_SetWrongTypeValue_NoAdvancedOptions,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    Json::Value jobOptions;
    jobOptions["isReverse"] = "isReverse";
    jobOptions["isCollate"] = "isCollate";
    PrinterInfo printerInfo;
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, printerInfo);
    EXPECT_EQ(jobOptions.isMember("advancedOptions"), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrintJobOptionWithPrinterPreferences_SetCorrectValue_HasAdvancedOptions,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    Json::Value jobOptions;
    jobOptions["isReverse"] = true;
    jobOptions["isCollate"] = true;
    PrinterInfo printerInfo;
    Json::Value preferenceOptions;
    preferenceOptions["key"] = "value";
    PrinterPreferences preferences;
    preferences.SetOption(PrintJsonUtil::WriteString(preferenceOptions));
    printerInfo.SetPreferences(preferences);
    service->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, printerInfo);
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

HWTEST_F(PrintServiceAbilityTest, GetPrinterPreference_PrinterExists, TestSize.Level1)
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
    PrinterPreferences result;
    int32_t ret = service->GetPrinterPreference(printerId, result);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(result.GetDefaultDuplexMode(), DUPLEX_MODE_LONG_EDGE);
    service->printSystemData_.DeleteAddedPrinter(printerId, "Test Printer");
}

}  // namespace Print
}  // namespace OHOS
