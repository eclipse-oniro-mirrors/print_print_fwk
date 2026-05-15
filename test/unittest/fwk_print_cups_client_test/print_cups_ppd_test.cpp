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
#include <cups/ppd.h>
#include <cups/ppd-private.h>
#include <fstream>
#include <unistd.h>
#include "print_cups_ppd.h"
#include "printer_capability.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintCupsPpdTest : public testing::Test {
protected:
    std::string CreateTempPpdFile(const std::string &content)
    {
        std::string tempPath = "/data/local/tmp/test_vendor_" + std::to_string(getpid()) + ".ppd";
        std::ofstream file(tempPath);
        file << content;
        file.close();
        return tempPath;
    }

    void RemoveTempFile(const std::string &path)
    {
        if (!path.empty()) {
            unlink(path.c_str());
        }
    }

    std::string CreatePpdWithVendorAbility(
        const std::string &prefAbility,
        const std::string &jobAbility)
    {
        std::string content = "*PPD-Adobe: \"4.3\"\n"
            "*FileVersion: \"1.0\"\n"
            "*LanguageEncoding: ISOLatin1\n"
            "*LanguageLevel: \"2\"\n"
            "*Manufacturer: \"Test\"\n"
            "*ModelName: \"Test Printer\"\n"
            "*NickName: \"Test Printer\"\n";

        if (!prefAbility.empty()) {
            content += "*vendorPrinterPrefAbility: \"" + prefAbility + "\"\n";
        }
        if (!jobAbility.empty()) {
            content += "*vendorJobAttrAbility: \"" + jobAbility + "\"\n";
        }

        content += "*ColorDevice: True\n"
            "*DefaultColor: Color\n"
            "*OpenUI PageSize: PickOne\n"
            "*DefaultPageSize: A4\n"
            "*PageSize A4/A4: \"<</PageSize>>\"\n"
            "*CloseUI: PageSize\n";

        return CreateTempPpdFile(content);
    }
};

HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_InvalidPath_ReturnsFileIOError, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string invalidPath = "/invalid/path/to/nonexistent.ppd";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, invalidPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_EmptyPath_ReturnsFileIOError, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string emptyPath = "";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, emptyPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_NullPpd_ReturnsZero, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_NullPpd_ReturnsZero, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    std::vector<std::string> conflictTypes;
    int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4, conflictTypes);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(conflictTypes.empty());
}

HWTEST_F(PrintCupsPpdTest, ParseVendorAbilityFromPPD_NullPpd_AbilityFieldsEmpty, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    PrinterCapability printerCaps;

    ParseVendorAbilityFromPPD(ppd, printerCaps);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, ParseVendorAbilityFromPPD_BothAbilitiesPresent_AbilitiesSet, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithVendorAbility(
        "com.vendor.driver.VendorPrinterSettingsAbility",
        "com.vendor.driver.VendorJobAttrAbility");

    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    PrinterCapability printerCaps;
    ParseVendorAbilityFromPPD(ppd, printerCaps);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "com.vendor.driver.VendorPrinterSettingsAbility");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "com.vendor.driver.VendorJobAttrAbility");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseVendorAbilityFromPPD_NoVendorPrefAttr_OnlyJobAbilitySet, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithVendorAbility(
        "",
        "com.vendor.driver.VendorJobAttrAbility");

    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    PrinterCapability printerCaps;
    ParseVendorAbilityFromPPD(ppd, printerCaps);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "com.vendor.driver.VendorJobAttrAbility");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseVendorAbilityFromPPD_NoVendorJobAttr_OnlyPrefAbilitySet, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithVendorAbility(
        "com.vendor.driver.VendorPrinterSettingsAbility",
        "");

    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    PrinterCapability printerCaps;
    ParseVendorAbilityFromPPD(ppd, printerCaps);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "com.vendor.driver.VendorPrinterSettingsAbility");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseVendorAbilityFromPPD_NoVendorAbilities_BothEmpty, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithVendorAbility("", "");

    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    PrinterCapability printerCaps;
    ParseVendorAbilityFromPPD(ppd, printerCaps);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_MatchingBundles_AbilitiesSet, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("com.vendor.driver.VendorPrinterSettingsAbility");
    printerCaps.SetVendorJobAttrAbility("com.vendor.driver.VendorJobAttrAbility");
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "com.vendor.driver.VendorPrinterSettingsAbility");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "com.vendor.driver.VendorJobAttrAbility");
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_MismatchedBundles_AbilitiesCleared, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("com.other.driver.VendorPrinterSettingsAbility");
    printerCaps.SetVendorJobAttrAbility("com.other.driver.VendorJobAttrAbility");
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_PrefMatchJobMismatch_OnlyPrefSet, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("com.vendor.driver.VendorPrinterSettingsAbility");
    printerCaps.SetVendorJobAttrAbility("com.other.driver.VendorJobAttrAbility");
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "com.vendor.driver.VendorPrinterSettingsAbility");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_PrefMismatchJobMatch_OnlyJobSet, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("com.other.driver.VendorPrinterSettingsAbility");
    printerCaps.SetVendorJobAttrAbility("com.vendor.driver.VendorJobAttrAbility");
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "com.vendor.driver.VendorJobAttrAbility");
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_EmptyPpdName_AbilitiesCleared, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("com.vendor.driver.VendorPrinterSettingsAbility");
    printerCaps.SetVendorJobAttrAbility("com.vendor.driver.VendorJobAttrAbility");
    std::string ppdName = "";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, ValidateAndClearVendorAbility_InvalidAbilityFormat_AbilitiesCleared, TestSize.Level1)
{
    PrinterCapability printerCaps;
    printerCaps.SetVendorPrinterPrefAbility("no_dot_ability");
    printerCaps.SetVendorJobAttrAbility("no_dot.job_ability");
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";

    ValidateAndClearVendorAbility(printerCaps, ppdName);

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, PrinterCapability_SetAndGetVendorAbilities_Succeeds, TestSize.Level1)
{
    PrinterCapability printerCaps;

    printerCaps.SetVendorPrinterPrefAbility("com.example.vendor.VendorPrinterSettingsAbility");
    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "com.example.vendor.VendorPrinterSettingsAbility");

    printerCaps.SetVendorJobAttrAbility("com.example.vendor.VendorJobAttrAbility");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "com.example.vendor.VendorJobAttrAbility");
}

HWTEST_F(PrintCupsPpdTest, PrinterCapability_DefaultVendorAbilities_ReturnsEmpty, TestSize.Level1)
{
    PrinterCapability printerCaps;

    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, PrinterCapability_SetEmptyVendorAbilities_ReturnsEmpty, TestSize.Level1)
{
    PrinterCapability printerCaps;

    printerCaps.SetVendorPrinterPrefAbility("");
    EXPECT_EQ(printerCaps.GetVendorPrinterPrefAbility(), "");

    printerCaps.SetVendorJobAttrAbility("");
    EXPECT_EQ(printerCaps.GetVendorJobAttrAbility(), "");
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_BundlesMatch_ReturnsTrue, TestSize.Level1)
{
    EXPECT_TRUE(ValidateVendorAbilityBundle(
        "com.vendor.driver.VendorPrinterSettingsAbility", "com.vendor.driver_Test_LaserJet.ppd"));
    EXPECT_TRUE(ValidateVendorAbilityBundle(
        "com.example.vendor.VendorJobAttrAbility", "com.example.vendor_CustomName.ppd"));
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_BundlesMismatch_ReturnsFalse, TestSize.Level1)
{
    EXPECT_FALSE(ValidateVendorAbilityBundle(
        "com.vendor.driver.VendorPrinterSettingsAbility", "com.other.driver_Printer.ppd"));
    EXPECT_FALSE(ValidateVendorAbilityBundle(
        "com.example.vendor.VendorJobAttrAbility", "com.different.bundle_Printer.ppd"));
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_EmptyAbilityName_ReturnsFalse, TestSize.Level1)
{
    EXPECT_FALSE(ValidateVendorAbilityBundle("", "com.vendor.driver_Test_LaserJet.ppd"));
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_EmptyPpdName_ReturnsFalse, TestSize.Level1)
{
    EXPECT_FALSE(ValidateVendorAbilityBundle("com.vendor.driver.VendorPrinterSettingsAbility", ""));
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_InvalidAbilityFormat_ReturnsFalse, TestSize.Level1)
{
    EXPECT_FALSE(ValidateVendorAbilityBundle("no_dot_ability", "com.vendor.driver_Test_LaserJet.ppd"));
}

HWTEST_F(PrintCupsPpdTest, ValidateVendorAbilityBundle_InvalidPpdFormat_ReturnsFalse, TestSize.Level1)
{
    EXPECT_FALSE(ValidateVendorAbilityBundle(
        "com.vendor.driver.VendorPrinterSettingsAbility", "no_underscore"));
}

HWTEST_F(PrintCupsPpdTest, FindCustomParam_NullCoption_ReturnsNullptr, TestSize.Level1)
{
    ppd_coption_t *coption = nullptr;
    ppd_cparam_t *result = FindCustomParam(coption);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(PrintCupsPpdTest, FindCustomParamLimit_NullCparam_ReturnsEmptyObject, TestSize.Level1)
{
    Json::Value result = FindCustomParamLimit(nullptr);
    EXPECT_TRUE(result.isObject());
    EXPECT_TRUE(result.empty());
}

HWTEST_F(PrintCupsPpdTest, FindCustomParamLimit_ValidParam_ReturnsCorrectJson, TestSize.Level1)
{
    ppd_cparam_t cparam;
    cparam.type = PPD_CUSTOM_STRING;
    cparam.minimum.custom_string = 1;
    cparam.maximum.custom_string = 100;

    Json::Value result = FindCustomParamLimit(&cparam);
    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(result["minimum"].asInt(), 1);
    EXPECT_EQ(result["maximum"].asInt(), 100);
}

HWTEST_F(PrintCupsPpdTest, FindCustomParamLimit_PasscodeType_ReturnsCorrectJson, TestSize.Level1)
{
    ppd_cparam_t cparam;
    cparam.type = PPD_CUSTOM_PASSCODE;
    cparam.minimum.custom_passcode = 4;
    cparam.maximum.custom_passcode = 8;

    Json::Value result = FindCustomParamLimit(&cparam);
    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(result["minimum"].asInt(), 4);
    EXPECT_EQ(result["maximum"].asInt(), 8);
}

HWTEST_F(PrintCupsPpdTest, FindCustomParamLimit_InvalidType_ReturnsFalse, TestSize.Level1)
{
    ppd_cparam_t cparam;
    cparam.type = PPD_CUSTOM_INT;
    cparam.minimum.custom_int = 0;
    cparam.maximum.custom_int = 0;

    Json::Value result = FindCustomParamLimit(&cparam);
    EXPECT_FALSE(result.isObject());
    EXPECT_EQ(result["minimum"].asInt(), 0);
    EXPECT_EQ(result["maximum"].asInt(), 0);
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromPpdName_ValidPpdName_ReturnsBundle, TestSize.Level1)
{
    std::string ppdName = "com.vendor.driver_Test_Printer.ppd";
    std::string bundleName = ExtractBundleNameFromPpdName(ppdName);
    EXPECT_EQ(bundleName, "com.vendor.driver");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromPpdName_EmptyPpdName_ReturnsEmpty, TestSize.Level1)
{
    std::string ppdName = "";
    std::string bundleName = ExtractBundleNameFromPpdName(ppdName);
    EXPECT_EQ(bundleName, "");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromPpdName_NoUnderscore_ReturnsEmpty, TestSize.Level1)
{
    std::string ppdName = "no_underscore_file";
    std::string bundleName = ExtractBundleNameFromPpdName(ppdName);
    EXPECT_EQ(bundleName, "");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromPpdName_MultipleUnderscores_ReturnsFirstPart, TestSize.Level1)
{
    std::string ppdName = "com.vendor.driver_Printer_Model_v1.ppd";
    std::string bundleName = ExtractBundleNameFromPpdName(ppdName);
    EXPECT_EQ(bundleName, "com.vendor.driver");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromAbilityName_ValidAbilityName_ReturnsBundle, TestSize.Level1)
{
    std::string abilityName = "com.vendor.driver.VendorPrinterSettingsAbility";
    std::string bundleName = ExtractBundleNameFromAbilityName(abilityName);
    EXPECT_EQ(bundleName, "com.vendor.driver");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromAbilityName_EmptyAbilityName_ReturnsEmpty, TestSize.Level1)
{
    std::string abilityName = "";
    std::string bundleName = ExtractBundleNameFromAbilityName(abilityName);
    EXPECT_EQ(bundleName, "");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromAbilityName_NoDot_ReturnsEmpty, TestSize.Level1)
{
    std::string abilityName = "no_dot_ability";
    std::string bundleName = ExtractBundleNameFromAbilityName(abilityName);
    EXPECT_EQ(bundleName, "");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromAbilityName_MultipleDots_ReturnsUpToLastDot, TestSize.Level1)
{
    std::string abilityName = "com.vendor.driver.subpackage.VendorAbility";
    std::string bundleName = ExtractBundleNameFromAbilityName(abilityName);
    EXPECT_EQ(bundleName, "com.vendor.driver.subpackage");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFromAbilityName_SingleDot_ReturnsPartBeforeDot, TestSize.Level1)
{
    std::string abilityName = "bundle.Ability";
    std::string bundleName = ExtractBundleNameFromAbilityName(abilityName);
    EXPECT_EQ(bundleName, "bundle");
}

HWTEST_F(PrintCupsPpdTest, ExtractBundleNameFunctions_EdgeCases_HandleCorrectly, TestSize.Level1)
{
    EXPECT_EQ(ExtractBundleNameFromPpdName("_.ppd"), "");
    EXPECT_EQ(ExtractBundleNameFromAbilityName(".Ability"), "");
    EXPECT_EQ(ExtractBundleNameFromPpdName("a_b.ppd"), "a");
    EXPECT_EQ(ExtractBundleNameFromAbilityName("a.Ability"), "a");
}

}  // namespace Print
}  // namespace OHOS
