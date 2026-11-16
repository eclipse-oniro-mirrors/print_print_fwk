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
#include <clocale>
#include <cups/ppd.h>
#include <cups/ppd-private.h>
#include <cups/cups.h>
#include <fstream>
#include <unistd.h>
#include "print_cups_ppd.h"
#include "print_ppd_adapter.h"
#include "printer_capability.h"
#include "print_json_util.h"
#define private public
#include "print_cups_client.h"
#undef private

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

    Json::Value QueryOk(const std::string &ppdPath, const std::string &lang)
    {
        std::string resultJson;
        EXPECT_EQ(GetLocalizedStringsFromPpd(ppdPath, lang, resultJson), E_PRINT_NONE);
        Json::Value root;
        EXPECT_TRUE(PrintJsonUtil::Parse(resultJson, root));
        return root;
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

    std::string CreatePpdWithCustomPageSize()
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
            "*HWMargins: \"11.905511811024 11.905511811024 11.905511811024 11.905511811024\"\n"
            "*ParamCustomPageSize Width: 1 points 216 612.283464566929\n"
            "*ParamCustomPageSize Height: 2 points 394.015748031496 1700.787401574803\n"
            "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
            "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
            "*ParamCustomPageSize Orientation: 5 int 0 3\n"
            "*CustomPageSize True: \"pop pop pop <</PageSize[5 -2 roll]/ImagingBBox null>>setpagedevice\"\n";
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
            "*OpenUI OutputMode: PickOne\n"
            "*OrderDependency: 30 AnySetup OutputMode\n"
            "*DefaultOutputMode: Normal\n"
            "*OutputMode Draft/Draft: \"<</cupsCompression 0>>setpagedevice\"\n"
            "*OutputMode Normal/Normal: \"<</cupsCompression 1>>setpagedevice\"\n"
            "*OutputMode High/High: \"<</cupsCompression 2>>setpagedevice\"\n"
            "*CloseUI: OutputMode\n"
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
void ParsePrinterAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);
void GetAdvanceOptionsFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);
void ParseMediaTypeAttributeFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);

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

HWTEST_F(PrintCupsPpdTest, FindCustomParamLimit_PasswordType_ReturnsCorrectJson, TestSize.Level1)
{
    ppd_cparam_t cparam;
    cparam.type = PPD_CUSTOM_PASSWORD;
    cparam.minimum.custom_password = 6;
    cparam.maximum.custom_password = 12;

    Json::Value result = FindCustomParamLimit(&cparam);
    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(result["minimum"].asInt(), 6);
    EXPECT_EQ(result["maximum"].asInt(), 12);
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
        EXPECT_TRUE(ppdIsMarked(ppd, "OutputMode", "Draft"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_NORMAL);
        EXPECT_TRUE(ppdIsMarked(ppd, "OutputMode", "Normal"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_HIGH);
        EXPECT_TRUE(ppdIsMarked(ppd, "OutputMode", "High"));

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
        EXPECT_TRUE(ppdIsMarked(ppd, "OutputMode", "Draft"));
    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, "normal");
        EXPECT_TRUE(ppdIsMarked(ppd, "OutputMode", "Normal"));
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
    EXPECT_EQ(optName, "OutputMode");
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

HWTEST_F(PrintCupsPpdTest, BuildPpdOptionMap_AllOptions_PopulatesMaps, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    Json::Value optionMap;
    Json::Value textMap;
    PpdAdapter::BuildOptionMaps(ppd, optionMap, textMap);

    EXPECT_TRUE(optionMap.isMember("defaultDuplexMode"));
    EXPECT_TRUE(optionMap.isMember("defaultColorMode"));
    EXPECT_TRUE(optionMap.isMember("defaultPageSizeId"));
    EXPECT_TRUE(optionMap.isMember("defaultMediaType"));
    EXPECT_TRUE(optionMap.isMember("defaultPrintQuality"));

    EXPECT_EQ(optionMap["defaultDuplexMode"]["optionName"].asString(), "Duplex");
    EXPECT_EQ(optionMap["defaultDuplexMode"]["choices"]["one-sided"].asString(), "None");
    EXPECT_EQ(optionMap["defaultDuplexMode"]["choices"]["two-sided-long-edge"].asString(), "DuplexNoTumble");

    EXPECT_TRUE(textMap.isMember("Duplex"));
    EXPECT_TRUE(textMap["Duplex"].isMember("default"));
    EXPECT_TRUE(textMap["Duplex"].isMember("zh_CN"));

    Json::Value duplexText = textMap["Duplex"]["default"];
    EXPECT_TRUE(duplexText.isMember("0"));
    EXPECT_TRUE(duplexText.isMember("1"));
    EXPECT_TRUE(duplexText.isMember("2"));
    EXPECT_FALSE(duplexText.isMember("one-sided"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, BuildPpdOptionMap_NoDuplexOption_SkipsMissingOptions, TestSize.Level1)
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
        "*DefaultPageSize: A4\n"
        "*PageSize A4/A4: \"<</PageSize>>\"\n"
        "*CloseUI: PageSize\n";
    std::string ppdPath = CreateTempPpdFile(content);
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    Json::Value optionMap;
    Json::Value textMap;
    PpdAdapter::BuildOptionMaps(ppd, optionMap, textMap);
    EXPECT_FALSE(optionMap.isMember("defaultDuplexMode"));
    EXPECT_TRUE(optionMap.isMember("defaultPageSizeId"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, SetOptionAttributeFromPPD_PpdFieldsAtTopLevel, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    PrinterCapability printerCaps;
    GetAdvanceOptionsFromPPD(ppd, printerCaps);
    ParsePrinterAttributesFromPPD(ppd, printerCaps);

    EXPECT_TRUE(printerCaps.HasOption());

    Json::Value optionJson;
    ASSERT_TRUE(PrintJsonUtil::Parse(printerCaps.GetOption(), optionJson));

    EXPECT_TRUE(optionJson.isMember("ppdDriverType"));
    EXPECT_EQ(optionJson["ppdDriverType"].asString(), "ppd");
    EXPECT_TRUE(optionJson.isMember("ppdOptionMap"));
    EXPECT_TRUE(optionJson.isMember("ppdOptionTextMap"));

    Json::Value cupsOptions = optionJson["cupsOptions"];
    EXPECT_FALSE(cupsOptions.isMember("ppdDriverType"));
    EXPECT_FALSE(cupsOptions.isMember("ppdOptionMap"));
    EXPECT_FALSE(cupsOptions.isMember("ppdOptionTextMap"));
    EXPECT_TRUE(cupsOptions.isMember("advanceOptions"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, FillBasicOptions_PpdMode_ConvertsAllDimensions, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);

    Json::Value optionMap;
    Json::Value textMap;
    PpdAdapter::BuildOptionMaps(ppd, optionMap, textMap);

    ppdClose(ppd);
    RemoveTempFile(ppdPath);

    JobParameters jobParams;
    jobParams.duplex = "two-sided-long-edge";
    jobParams.color = "monochrome";
    jobParams.printQuality = "4";
    jobParams.ppdOptionMap = PrintJsonUtil::WriteString(optionMap);

    cups_option_t *options = nullptr;
    int num_options = 0;
    num_options = PrintCupsClient::FillBasicOptions(&jobParams, num_options, &options);

    EXPECT_GE(num_options, 2);

    const char *duplexVal = cupsGetOption("Duplex", num_options, options);
    if (duplexVal != nullptr) {
        EXPECT_STREQ(duplexVal, "DuplexNoTumble");
    }

    const char *colorVal = cupsGetOption("ColorModel", num_options, options);
    if (colorVal != nullptr) {
        EXPECT_STREQ(colorVal, "Gray");
    }

    if (options != nullptr) {
        cupsFreeOptions(num_options, options);
    }
}

HWTEST_F(PrintCupsPpdTest, FillBasicOptions_EmptyPpdOptionMap_UsesPwgFallback, TestSize.Level1)
{
    JobParameters jobParams;
    jobParams.duplex = "one-sided";
    jobParams.color = "color";
    jobParams.printQuality = "normal";
    jobParams.ppdOptionMap = "";

    cups_option_t *options = nullptr;
    int num_options = 0;
    num_options = PrintCupsClient::FillBasicOptions(&jobParams, num_options, &options);

    EXPECT_GE(num_options, 3);

    const char *sidesVal = cupsGetOption("sides", num_options, options);
    EXPECT_NE(sidesVal, nullptr);
    EXPECT_STREQ(sidesVal, "one-sided");

    if (options != nullptr) {
        cupsFreeOptions(num_options, options);
    }
}

// ===== T16: NormalizePpdLanguage tests =====
HWTEST_F(PrintCupsPpdTest, NormalizePpdLanguage_BCP47_ToUnderscore, TestSize.Level1)
{
    std::string out;
    EXPECT_TRUE(NormalizePpdLanguage("zh_CN", out));
    EXPECT_EQ(out, "zh_CN");
    EXPECT_TRUE(NormalizePpdLanguage("zh-Hans-CN", out));
    EXPECT_EQ(out, "zh_CN");
    EXPECT_TRUE(NormalizePpdLanguage("en-US", out));
    EXPECT_EQ(out, "en_US");
    EXPECT_TRUE(NormalizePpdLanguage("fr", out));
    EXPECT_EQ(out, "fr");
    EXPECT_TRUE(NormalizePpdLanguage("zh_tw", out));
    EXPECT_EQ(out, "zh_TW");
    EXPECT_TRUE(NormalizePpdLanguage("zh-TW", out));
    EXPECT_EQ(out, "zh_TW");
    EXPECT_TRUE(NormalizePpdLanguage("zh-Hant-TW", out));
    EXPECT_EQ(out, "zh_TW");
}

// ===== T16: PPD with cupsLanguages + inline zh_CN translations =====
namespace {
static const std::string K_LANG_PPD_CONTENT =
    "*PPD-Adobe: \"4.3\"\n"
    "*FileVersion: \"1.0\"\n"
    "*LanguageEncoding: ISOLatin1\n"
    "*LanguageLevel: \"2\"\n"
    "*Manufacturer: \"Test\"\n"
    "*ModelName: \"Test Printer\"\n"
    "*NickName: \"Test Printer\"\n"
    "*ColorDevice: True\n"
    "*DefaultColor: Color\n"
    "*cupsLanguages: \"en zh_CN fr de\"\n"
    "*OpenUI PageSize: PickOne\n"
    "*OrderDependency: 10 AnySetup PageSize\n"
    "*DefaultPageSize: A4\n"
    "*PageSize A4/A4: \"<</PageSize[595 842]>>setpagedevice\"\n"
    "*PageSize Letter/US Letter: \"<</PageSize[612 792]>>setpagedevice\"\n"
    "*zh_CN.PageSize A4/A4: \"A4\"\n"
    "*zh_CN.PageSize Letter/Letter: \"\u4fe1\u7eb8\"\n"
    "*CloseUI: PageSize\n"
    "*OpenUI MediaType: PickOne\n"
    "*OrderDependency: 50 AnySetup MediaType\n"
    "*DefaultMediaType: Plain\n"
    "*MediaType Plain/Plain Paper: \"<<MediaType(Plain)>>setpagedevice\"\n"
    "*MediaType Photo/Photo Paper: \"<<MediaType(Photo)>>setpagedevice\"\n"
    "*zh_CN.MediaType Plain/\u666e\u901a\u7eb8: \"<<MediaType(Plain)>>setpagedevice\"\n"
    "*de.MediaType Plain/Ordinary Paper: \"<<MediaType(Plain)>>setpagedevice\"\n"
    "*CloseUI: MediaType\n"
    "*OpenUI ColorModel: PickOne\n"
    "*OrderDependency: 20 AnySetup ColorModel\n"
    "*DefaultColorModel: RGB\n"
    "*ColorModel RGB/Color: \"<<cupsColorModel 1>>setpagedevice\"\n"
    "*zh_CN.ColorModel RGB/\u5f69\u8272: \"<<cupsColorModel 1>>setpagedevice\"\n"
    "*zh_CN.Translation ColorModel/CNOptionText: \"\"\n"
    "*CloseUI: ColorModel\n"
    "*OpenUI Finishing: PickOne\n"
    "*OrderDependency: 30 AnySetup Finishing\n"
    "*DefaultFinishing: None\n"
    "*Finishing None/Off: \"\"\n"
    "*Finishing TwoSidedLongEdge/Two-Sided, Long-Edge: \"\"\n"
    "*zh_CN.Finishing None/关闭: \"\"\n"
    "*zh_CN.Translation Finishing/完成方式: \"\"\n"
    "*CloseUI: Finishing\n"
    "*OpenUI TestSheets: PickMany\n"
    "*DefaultTestSheets: None\n"
    "*TestSheets None/None: \"\"\n"
    "*CloseUI: TestSheets\n"
    "*OpenUI StockType: PickOne\n"
    "*DefaultStockType: Plain\n"
    "*StockType Plain/Plain: \"\"\n"
    "*StockType Custom/Custom: \"\"\n"
    "*CloseUI: StockType\n"
    "*CustomStockType True:\n"
    "*ParamCustomStockType Remark/Remark: \"1 string 1 40\"\n"
    "*OpenUI Collate: PickMany\n"
    "*OrderDependency: 30 AnySetup Collate\n"
    "*Collate True/Collated: \"<<Collated True>>setpagedevice\"\n"
    "*zh_CN.Collate True/\u6253\u7d22: \"<<Collated True>>setpagedevice\"\n"
    "*CloseUI: Collate\n";

std::string CreatePpdWithLanguages()
{
    std::string content = K_LANG_PPD_CONTENT;
    std::string tempPath = "/data/local/tmp/test_lang_" + std::to_string(getpid()) + ".ppd";
    std::ofstream file(tempPath);
    file << content;
    file.close();
    return tempPath;
}

void RemoveLangPpd(const std::string &path) { unlink(path.c_str()); }

}

// ===== T16: GetLocalizedStringsFromPpd tests =====
// Pre-populated channel snapshot of advanceOptions, same preambles as production
static Json::Value SnapshotAdvanceOptions(const std::string &ppdPath)
{
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    EXPECT_NE(ppd, nullptr);
    Json::Value adv;
    if (ppd == nullptr) {
        return adv;
    }
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    PrinterCapability printerCaps;
    GetAdvanceOptionsFromPPD(ppd, printerCaps);
    // attr 组经 SetPrinterAttrNameAndValue 仅并入 GetOption 组装，须走一次
    // ParsePrinterAttributesFromPPD（其内部 SetOption）方能从 GetOption 读回
    ParsePrinterAttributesFromPPD(ppd, printerCaps);
    ppdClose(ppd);
    Json::Value optionJson;
    EXPECT_TRUE(PrintJsonUtil::Parse(printerCaps.GetOption(), optionJson));
    const Json::Value &raw = optionJson["cupsOptions"]["advanceOptions"];
    if (raw.isString()) {
        EXPECT_TRUE(PrintJsonUtil::Parse(raw.asString(), adv));
    } else {
        adv = raw;
    }
    return adv;
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_ZhQueryContract, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    Json::Value root = QueryOk(ppdPath, "zh_CN");
    // 内容集镜像预入：非 base 仅剩 Finishing/StockType，PickMany 缺席
    ASSERT_EQ(root["advanceOptions"].size(), 2u);
    const Json::Value &fin = root["advanceOptions"][0];
    EXPECT_EQ(fin["keyword"].asString(), "Finishing");
    EXPECT_TRUE(fin.isMember("uiType"));
    EXPECT_EQ(fin["choice"]["zh_CN"]["None"].asString(), "关闭");
    EXPECT_EQ(fin["choice"]["zh_CN"].size(), fin["choice"]["default"].size());
    EXPECT_EQ(fin["optionText"]["zh_CN"].asString(), "完成方式");
    EXPECT_EQ(root["advanceOptions"][1]["keyword"].asString(), "StockType");
    EXPECT_EQ(PrintJsonUtil::WriteString(root).find("TestSheets"), std::string::npos);
    // media 两 map 语言层恒写（D1）
    for (const char *mapName : {"mediaSizeMap", "mediaTypeMap"}) {
        ASSERT_TRUE(root.isMember(mapName));
        for (const auto &key : root[mapName].getMemberNames()) {
            EXPECT_TRUE(root[mapName][key].isMember("default"));
            EXPECT_TRUE(root[mapName][key].isMember("zh_CN"));
        }
    }
    // textMap（PC 形态）：zh_CN 与 default 等长，且含真实译文
    const Json::Value &entry = root["ppdOptionTextMap"]["MediaType"];
    EXPECT_EQ(entry["zh_CN"].size(), entry["default"].size());
    // 检索非 ASCII 用 WriteStringUTF8（emitUTF8=true，与生产响应输出通道同款原文编码）；
    // WriteString 默认把非 ASCII 转义为 \uXXXX，子串检索必失败
    EXPECT_NE(PrintJsonUtil::WriteStringUTF8(entry["zh_CN"]).find("普通纸"), std::string::npos);
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_ZhEqualsCapabilitySnapshot, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    Json::Value capAdv = SnapshotAdvanceOptions(ppdPath);
    Json::Value root = QueryOk(ppdPath, "zh_CN");
    // 语言无关不变式：条目集与 default 层两通道严格相等。zh 层**值**依赖进程
    // locale（快照走 DEFAULT 本地化视图、查询走 ALL），环境不可比——只断言
    // **形状**（恒写、与 default 等长）；zh 层的值一致性由 ZhQueryContract 覆盖。
    ASSERT_EQ(capAdv.size(), root["advanceOptions"].size());
    for (Json::ArrayIndex i = 0; i < capAdv.size(); i++) {
        const Json::Value &c = capAdv[i];
        const Json::Value &q = root["advanceOptions"][i];
        EXPECT_EQ(c["keyword"], q["keyword"]);
        EXPECT_EQ(c["uiType"], q["uiType"]);
        EXPECT_EQ(c["choice"]["default"], q["choice"]["default"]);
        EXPECT_EQ(c["optionText"]["default"], q["optionText"]["default"]);
        EXPECT_EQ(c["choice"]["zh_CN"].size(), c["choice"]["default"].size());
        EXPECT_EQ(q["choice"]["zh_CN"].size(), q["choice"]["default"].size());
    }
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_AdvanceOptionMaxLenMatchesCapability, TestSize.Level1)
{
    if (setlocale(LC_ALL, "zh_CN.UTF-8") == nullptr) {
        GTEST_SKIP() << "zh_CN.UTF-8 locale unavailable";
    }
    std::string content = "*PPD-Adobe: \"4.3\"\n*cupsLanguages: \"en zh_CN\"\n";
    for (int i = 0; i < 105; i++) {
        const std::string name = "Opt" + std::to_string(i);
        content += "*OpenUI " + name + ": PickOne\n*Default" + name + ": A\n*" +
            name + " A/Alpha: \"\"\n*CloseUI: " + name + "\n";
    }
    content += "*zh_CN.Opt0 A/\u7532: \"\"\n";
    std::string ppdPath = CreateTempPpdFile(content);
    const unsigned int expected = static_cast<unsigned int>(ADVANCE_OPTION_MAXLENGTH) + 1u;
    EXPECT_EQ(SnapshotAdvanceOptions(ppdPath).size(), expected);
    Json::Value root = QueryOk(ppdPath, "zh_CN");
    EXPECT_EQ(root["advanceOptions"].size(), expected);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_Fr_NoTranslation, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    std::string resultJson;
    int32_t ret = GetLocalizedStringsFromPpd(ppdPath, "fr", resultJson);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_TRUE(resultJson.empty());
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_NotInList_InvalidParam, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    std::string resultJson;
    int32_t ret = GetLocalizedStringsFromPpd(ppdPath, "ja", resultJson);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    EXPECT_TRUE(resultJson.empty());
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_InvalidPath_FileIO, TestSize.Level1)
{
    std::string resultJson;
    int32_t ret = GetLocalizedStringsFromPpd("/nonexistent/path/test.ppd", "en", resultJson);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
    EXPECT_TRUE(resultJson.empty());
}

// 入口契约：库层先内部归一（zh-Hans-CN→zh_CN）再做 cupsLanguages 白名单比对，
// 任何调用方（SA 或库层直调）输入容忍度一致；归一纯函数行为另由 NormalizePpdLanguage 用例覆盖
HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_LanguageNormalizedInternally, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    std::string resultJson;
    ASSERT_EQ(GetLocalizedStringsFromPpd(ppdPath, "zh-Hans-CN", resultJson), E_PRINT_NONE);
    Json::Value root;
    ASSERT_TRUE(PrintJsonUtil::Parse(resultJson, root));
    EXPECT_EQ(root["language"].asString(), "zh_CN");
    EXPECT_TRUE(root.isMember("advanceOptions"));
    EXPECT_EQ(GetLocalizedStringsFromPpd(ppdPath, "1x", resultJson), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(GetLocalizedStringsFromPpd(ppdPath, "ja", resultJson), E_PRINT_INVALID_PARAMETER);
    RemoveLangPpd(ppdPath);
}

// ===== T16: BuildPpdAvailableLanguages tests =====

// ===== C: language-list edge cases =====
HWTEST_F(PrintCupsPpdTest, PpdAvailableLanguages_AtOptionLevel, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);
    PrinterCapability printerCaps;
    SetOptionAttributeFromPPD(ppd, printerCaps);
    ppdClose(ppd);
    Json::Value optionJson;
    ASSERT_TRUE(PrintJsonUtil::Parse(printerCaps.GetOption(), optionJson));
    EXPECT_TRUE(optionJson.isMember("ppdAvailableLanguages"));
    EXPECT_TRUE(optionJson["ppdAvailableLanguages"].isArray());
    EXPECT_EQ(optionJson["ppdAvailableLanguages"].size(), 4u);
    // 旧位置不再承载该键（cupsOptions 属性组）
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, BuildPpdAvailableLanguages_TruncatedAtCountCap, TestSize.Level1)
{
    std::string tokens;  // 66 个双字母 ll，值总长 197 < cups 属性值上限(~255)
    for (int i = 0; i < 66; i++) {
        char ll0 = static_cast<char>('a' + i / 26);
        char ll1 = static_cast<char>('a' + i % 26);
        tokens += std::string(1, ll0) + std::string(1, ll1) + " ";
    }
    std::string content = std::string("*PPD-Adobe: \"4.3\"\n*FileVersion: \"1.0\"\n"
        "*LanguageEncoding: ISOLatin1\n*LanguageLevel: \"2\"\n*Manufacturer: \"T\"\n"
        "*ModelName: \"T\"\n*NickName: \"T\"\n") + "*cupsLanguages: \"" + tokens + "\"\n";
    std::string ppdPath = CreateTempPpdFile(content);
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    std::string val = PrintJsonUtil::WriteString(BuildPpdAvailableLanguages(ppd));
    EXPECT_NE(val.find("\"bb\""), std::string::npos);   // token 28 kept
    EXPECT_EQ(val.find("\"cm\""), std::string::npos);   // token 65 dropped (cap 64)
    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_OversizeLanguagesValue_FileIO, TestSize.Level1)
{
    std::string tokens;
    for (int i = 0; i < 1400; i++) {
        tokens += "ab ";
    }
    std::string content = std::string("*PPD-Adobe: \"4.3\"\n*FileVersion: \"1.0\"\n"
        "*LanguageEncoding: ISOLatin1\n*LanguageLevel: \"2\"\n*Manufacturer: \"T\"\n"
        "*ModelName: \"T\"\n*NickName: \"T\"\n") + "*cupsLanguages: \"" + tokens + "\"\n";
    std::string ppdPath = CreateTempPpdFile(content);
    // cups 解析器对属性值长度上限（~255B）先于框架 4096 防线拒绝整份 PPD：
    // 真实文件通道下超长值不可达框架防线，查询按文件 I/O 错误返回
    std::string resultJson;
    EXPECT_EQ(GetLocalizedStringsFromPpd(ppdPath, "zh_CN", resultJson), E_PRINT_FILE_IO);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, BuildPpdAvailableLanguages_InvalidSkippedDeduped, TestSize.Level1)
{
    std::string content = std::string("*PPD-Adobe: \"4.3\"\n*FileVersion: \"1.0\"\n"
        "*LanguageEncoding: ISOLatin1\n*LanguageLevel: \"2\"\n*Manufacturer: \"T\"\n"
        "*ModelName: \"T\"\n*NickName: \"T\"\n") +
        "*cupsLanguages: \"en en FR 3x zh-Hant-TW\"\n";
    std::string ppdPath = CreateTempPpdFile(content);
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    std::string val = PrintJsonUtil::WriteString(BuildPpdAvailableLanguages(ppd));
    EXPECT_NE(val.find("\"en\""), std::string::npos);
    EXPECT_EQ(val.find("\"en\""), val.rfind("\"en\""));   // deduped
    EXPECT_NE(val.find("\"fr\""), std::string::npos);     // FR normalized
    EXPECT_NE(val.find("\"zh_TW\""), std::string::npos);  // BCP-47 normalized
    EXPECT_EQ(val.find("3x"), std::string::npos);           // invalid skipped
    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_PartialTranslationFallback, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithLanguages();
    Json::Value root = QueryOk(ppdPath, "de");
    const Json::Value &entry = root["ppdOptionTextMap"]["MediaType"];
    const Json::Value &def = entry["default"];
    const Json::Value &de = entry["de"];
    ASSERT_EQ(de.size(), def.size());
    bool hasRealTranslation = false;
    for (const auto &token : def.getMemberNames()) {
        if (de[token] != def[token]) {
            hasRealTranslation = true;
        }
    }
    EXPECT_TRUE(hasRealTranslation);   // 命中 token 为真译文，其余回填 default
    EXPECT_EQ(root["advanceOptions"][0]["choice"]["de"].size(),
        root["advanceOptions"][0]["choice"]["default"].size());
    RemoveLangPpd(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, QueryPpdAvailableLanguagesFromFile_EmptyAndOpenFail, TestSize.Level1)
{
    Json::Value langs;
    EXPECT_FALSE(QueryPpdAvailableLanguagesFromFile("", langs));
    EXPECT_FALSE(QueryPpdAvailableLanguagesFromFile("/nonexistent/path/no_such.ppd", langs));
}

HWTEST_F(PrintCupsPpdTest, GetLocalizedStringsFromPpd_OversizeResult_ReturnedInFull, TestSize.Level1)
{
    // cups 对超限字段直接判整份 PPD 不可解析（PPD_MAX_NAME=41 / PPD_MAX_TEXT=81，
    // 超限即 _ppdOpenFile 返回 NULL），故大结果只能靠条数堆叠，字段取上限内最长
    const std::string name(PPD_MAX_NAME - 1, 'a');   // 40 chars
    const std::string text(PPD_MAX_TEXT - 1, 'b');   // 80 chars
    std::string content = std::string("*PPD-Adobe: \"4.3\"\n*FileVersion: \"1.0\"\n"
        "*LanguageEncoding: ISOLatin1\n*LanguageLevel: \"2\"\n*Manufacturer: \"T\"\n"
        "*ModelName: \"T\"\n*NickName: \"T\"\n*cupsLanguages: \"en zh_CN\"\n"
        "*OpenUI MediaType: PickOne\n*OrderDependency: 50 AnySetup MediaType\n"
        "*DefaultMediaType: Plain\n"
        "*MediaType Plain/Plain Paper: \"x\"\n"
        "*zh_CN.MediaType Plain/CNHit: \"x\"\n*CloseUI: MediaType\n");
    for (int o = 0; o < 100; o++) {
        char buf[8];
        snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%02d", o);
        std::string kw = std::string("Opt") + buf;
        content += "*OpenUI " + kw + ": PickOne\n*OrderDependency: 10 AnySetup " + kw +
            "\n*Default" + kw + ": c0\n";
        for (int c = 0; c < 5; c++) {
            char cb[8];
            snprintf_s(cb, sizeof(cb), sizeof(cb) - 1, "c%d", c);
            content += "*" + kw + " " + cb + "/" + name + ": \"" + text + "\"\n";
        }
        content += "*CloseUI: " + kw + "\n";
    }
    std::string ppdPath = CreateTempPpdFile(content);
    std::string resultJson;
    int32_t ret = GetLocalizedStringsFromPpd(ppdPath, "zh_CN", resultJson);
    EXPECT_EQ(ret, E_PRINT_NONE);   // no 100KB business cap: full result returned
    EXPECT_GT(resultJson.size(), 60u * 1024u);  // ~100 options x 5 choices x dual layers ~= 90KB
    RemoveTempFile(ppdPath);
}

// ===== ParseCustomPageSizeFromPpd Tests =====

HWTEST_F(PrintCupsPpdTest, ParseCustomPageSizeFromPpd_NullPpd_OptionsUnchanged, TestSize.Level1)
{
    Json::Value options;
    options["existing"] = "value";
    ParseCustomPageSizeFromPpd(nullptr, options);
    // null ppd → early return, options unchanged
    EXPECT_FALSE(options.isMember("customPageSizeRange"));
    EXPECT_EQ(options["existing"].asString(), "value");
}

HWTEST_F(PrintCupsPpdTest, ParseCustomPageSizeFromPpd_NullCache_OptionsUnchanged, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    // deliberately do NOT create cache → ppd->cache is null
    ASSERT_EQ(ppd->cache, nullptr);

    Json::Value options;
    ParseCustomPageSizeFromPpd(ppd, options);
    EXPECT_FALSE(options.isMember("customPageSizeRange"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseCustomPageSizeFromPpd_WithCache_RangeSetOrNull, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    Json::Value options;
    ParseCustomPageSizeFromPpd(ppd, options);
    if (options["customPageSizeRange"].isObject()) {
        const Json::Value &range = options["customPageSizeRange"];
        EXPECT_TRUE(range.isMember("minWidth"));
        EXPECT_TRUE(range.isMember("maxWidth"));
        EXPECT_TRUE(range.isMember("minHeight"));
        EXPECT_TRUE(range.isMember("maxHeight"));
        EXPECT_GE(range["minWidth"].asUInt(), 0u);
        EXPECT_GE(range["maxWidth"].asUInt(), range["minWidth"].asUInt());
    } else {
        // probed but not supported → null
        EXPECT_TRUE(options["customPageSizeRange"].isNull());
    }

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseCustomPageSizeFromPpd_SimplePpd_RangeNullOrObject, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithVendorAbility("", "");
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    Json::Value options;
    ParseCustomPageSizeFromPpd(ppd, options);
    // simple PPD without custom page size support → key present, value null
    ASSERT_TRUE(options.isMember("customPageSizeRange"));
    EXPECT_TRUE(options["customPageSizeRange"].isNull() || options["customPageSizeRange"].isObject());

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

HWTEST_F(PrintCupsPpdTest, ParseCustomPageSizeFromPpd_WithCustomPageSize_RangeObject, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithCustomPageSize();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    Json::Value options;
    ParseCustomPageSizeFromPpd(ppd, options);
    // PPD with ParamCustomPageSize → ppdPageSizeLimits should succeed → range is an object
    ASSERT_TRUE(options.isMember("customPageSizeRange"));
    const Json::Value &range = options["customPageSizeRange"];
    ASSERT_TRUE(range.isObject());
    EXPECT_TRUE(range.isMember("minWidth"));
    EXPECT_TRUE(range.isMember("maxWidth"));
    EXPECT_TRUE(range.isMember("minHeight"));
    EXPECT_TRUE(range.isMember("maxHeight"));
    // ParamCustomPageSize Width:  216..612.283 points → mils = points * 1000 / 72
    //   minWidth = round(216 * 1000 / 72)       = 3000
    //   maxWidth = round(612.283 * 1000 / 72)   = 8504
    // ParamCustomPageSize Height: 394.016..1700.787 points
    //   minHeight = round(394.016 * 1000 / 72)  = 5472
    //   maxHeight = round(1700.787 * 1000 / 72) = 23622
    EXPECT_EQ(range["minWidth"].asUInt(), 3000u);
    EXPECT_EQ(range["maxWidth"].asUInt(), 8504u);
    EXPECT_EQ(range["minHeight"].asUInt(), 5472u);
    EXPECT_EQ(range["maxHeight"].asUInt(), 23622u);

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

}  // namespace Print
}  // namespace OHOS
