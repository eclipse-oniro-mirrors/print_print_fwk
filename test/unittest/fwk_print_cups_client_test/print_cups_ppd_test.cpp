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
#include <cups/cups.h>
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

    std::string CreatePpdWithAllOptions()
    {
        std::string content = "*PPD-Adobe: \"4.3\"\n"
            "*FileVersion: \"1.0\"\n"
            "*LanguageEncoding: ISOLatin1\n"
            "*LanguageLevel: \"2\"\n"
            "*Manufacturer: \"Test\"\n"
            "*ModelName: \"Test Printer\"\n"
            "*NickName: \"Test Printer\"\n"
            "*ColorDevice: True\n"
            "*DefaultColor: Color\n"
            "*OpenUI PageSize: PickOne\n"
            "*OrderDependency: 10 AnySetup PageSize\n"
            "*DefaultPageSize: A4\n"
            "*PageSize A4/A4: \"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
            "*PageSize Letter/US Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
            "*CloseUI: PageSize\n"
            "*OpenUI ColorModel: PickOne\n"
            "*OrderDependency: 20 AnySetup ColorModel\n"
            "*DefaultColorModel: RGB\n"
            "*ColorModel RGB/Color: \"<<cupsColorModel 1>>setpagedevice\"\n"
            "*ColorModel Gray/Grayscale: \"<<cupsColorModel 0>>setpagedevice\"\n"
            "*ColorModel CMYK/CMYK: \"<<cupsColorModel 2>>setpagedevice\"\n"
            "*CloseUI: ColorModel\n"
            "*OpenUI cupsPrintQuality: PickOne\n"
            "*OrderDependency: 30 AnySetup cupsPrintQuality\n"
            "*DefaultcupsPrintQuality: Normal\n"
            "*cupsPrintQuality Draft/Draft: \"<<cupsPrintQuality 3>>setpagedevice\"\n"
            "*cupsPrintQuality Normal/Normal: \"<<cupsPrintQuality 4>>setpagedevice\"\n"
            "*cupsPrintQuality High/High: \"<<cupsPrintQuality 5>>setpagedevice\"\n"
            "*CloseUI: cupsPrintQuality\n"
            "*OpenUI Duplex: PickOne\n"
            "*OrderDependency: 40 AnySetup Duplex\n"
            "*DefaultDuplex: None\n"
            "*Duplex None/Off: \"<<Duplex false>>setpagedevice\"\n"
            "*Duplex DuplexNoTumble/Long Edge: \"<<Duplex true/Tumble false>>setpagedevice\"\n"
            "*Duplex DuplexTumble/Short Edge: \"<<Duplex true/Tumble true>>setpagedevice\"\n"
            "*CloseUI: Duplex\n"
            "*OpenUI MediaType: PickOne\n"
            "*OrderDependency: 50 AnySetup MediaType\n"
            "*DefaultMediaType: Plain\n"
            "*MediaType Plain/Plain Paper: \"<<MediaType(Plain)>>setpagedevice\"\n"
            "*MediaType Photo/Photo Paper: \"<<MediaType(Photo)>>setpagedevice\"\n"
            "*CloseUI: MediaType\n";

        return CreateTempPpdFile(content);
    }
};

bool FindDuplexChoiceByPwg(ppd_file_t *ppd, const std::string &duplexId,
    std::string &optName, std::string &choiceName);
bool FindPageSizeChoiceByPwg(ppd_file_t *ppd, const std::string &pageSizeId, std::string &ppdChoiceName);
bool FindMediaTypeChoiceByPwg(ppd_file_t *ppd, const std::string &pwgMediaType, std::string &ppdChoiceName);
bool FindChoiceInPpdOption(ppd_option_t *ppdOption, const std::string &val, std::string &choiceName);
bool ConvertOptionAndChoiceNameToPpd(ppd_file_t *ppd, const std::string &type, const std::string &val,
    std::string &optName, std::string &choiceName);

HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_InvalidPath_ReturnsFileIOError, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string invalidPpdName = "nonexistent.ppd";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, invalidPpdName);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_EmptyPath_ReturnsFileIOError, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string emptyPpdName = "";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, emptyPpdName);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
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
    std::string ppdName = "nounderscorefile";
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

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_ExpandedQualityMappings_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_DRAFT);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Draft"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_NORMAL);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Normal"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_HIGH);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "High"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_ExpandedColorMappings_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, CUPS_PRINT_COLOR_MODE_MONOCHROME);
    EXPECT_TRUE(ppdIsMarked(ppd, "ColorModel", "Gray"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, CUPS_PRINT_COLOR_MODE_COLOR);
    EXPECT_TRUE(ppdIsMarked(ppd, "ColorModel", "RGB"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_DuplexPWGLookup_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);

    if (ppd->cache != nullptr && ppd->cache->sides_option != nullptr) {
        MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_ONE_SIDED);
        EXPECT_TRUE(ppdIsMarked(ppd, ppd->cache->sides_option, ppd->cache->sides_1sided));
        MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_PORTRAIT);
        EXPECT_TRUE(ppdIsMarked(ppd, ppd->cache->sides_option, ppd->cache->sides_2sided_long));
    }

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_CaseInsensitiveChoiceFallback_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, "draft");
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Draft"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, "normal");
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Normal"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, "color");
    EXPECT_TRUE(ppdIsMarked(ppd, "ColorModel", "RGB"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_UnknownType_NotMarked, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, "unknownType", "someValue");
    EXPECT_EQ(ppdConflicts(ppd), 0);

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_PageSizePWGLookup_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_TRUE(ppdIsMarked(ppd, "PageSize", "A4"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_MediaTypePWGLookup_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_MEDIA_TYPE, CUPS_MEDIA_TYPE_PLAIN);
    EXPECT_TRUE(ppdIsMarked(ppd, "MediaType", "Plain"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_DuplexPWGLookup_TwoSidedLandscape, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);

    if (ppd->cache != nullptr && ppd->cache->sides_option != nullptr) {
        MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_LANDSCAPE);
        EXPECT_TRUE(ppdIsMarked(ppd, ppd->cache->sides_option, ppd->cache->sides_2sided_short));
    }

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_DuplexUnrecognizedId_AllFallbacksFail, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE,
        "custom-duplex", optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(choiceName, "custom-duplex");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_NoCache_PwgFallsThroughToMap, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_ONE_SIDED);
    EXPECT_TRUE(ppdIsMarked(ppd, "Duplex", "None"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_TRUE(ppdIsMarked(ppd, "PageSize", "A4"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_MEDIA_TYPE, CUPS_MEDIA_TYPE_PLAIN);
    EXPECT_TRUE(ppdIsMarked(ppd, "MediaType", "Plain"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_AllFallbacksFail_ReturnsFalse, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_QUALITY,
        "superhigh", optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, "cupsPrintQuality");
    EXPECT_EQ(choiceName, "superhigh");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, MarkPpdOption_MatchByText_Succeeds, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, "US Letter");
    EXPECT_TRUE(ppdIsMarked(ppd, "PageSize", "Letter"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, SubFunctions_NullParams_ReturnFalse, TestSize.Level1)
{
    std::string optName, choiceName;
    EXPECT_FALSE(FindDuplexChoiceByPwg(nullptr, CUPS_SIDES_ONE_SIDED, optName, choiceName));
    EXPECT_FALSE(FindPageSizeChoiceByPwg(nullptr, PAGE_SIZE_ID_ISO_A4, choiceName));
    EXPECT_FALSE(FindMediaTypeChoiceByPwg(nullptr, CUPS_MEDIA_TYPE_PLAIN, choiceName));
    EXPECT_FALSE(FindChoiceInPpdOption(nullptr, "test", choiceName));
}

HWTEST_F(PrintCupsPpdTest, FindDuplexChoiceByPwg_UnrecognizedId_ReturnsFalse, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);

    if (ppd->cache != nullptr && ppd->cache->sides_option != nullptr) {
        std::string optName, choiceName;
        EXPECT_FALSE(FindDuplexChoiceByPwg(ppd, "custom-duplex", optName, choiceName));
    }

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

}  // namespace Print
}  // namespace OHOS
