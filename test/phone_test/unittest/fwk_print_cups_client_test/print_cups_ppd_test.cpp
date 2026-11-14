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
#include "print_json_util.h"
#include "print_cups_ppd.h"
#include "printer_capability.h"

using namespace testing;
using namespace testing::ext;

// externs for library-internal composition helpers used by guards
void ParsePrinterAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);

namespace OHOS {
namespace Print {

// Forward declaration: ConvertOptionAndChoiceNameToPpd is defined in print_cups_ppd.cpp
// but not declared in the header. Declared here for direct unit testing.
bool ConvertOptionAndChoiceNameToPpd(ppd_file_t *ppd, const std::string &type, const std::string &val,
    std::string &optName, std::string &choiceName);

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


    // PPD with all standard print options for testing option marking and lookup
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

void ParseMediaTypeAttributeFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);
void GetAdvanceOptionsFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps);

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_001
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with invalid file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_001, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string invalidPath = "/invalid/path/to/nonexistent.ppd";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, invalidPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_002
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with empty file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_002, TestSize.Level1)
{
    PrinterCapability printerCaps;
    std::string emptyPath = "";
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, emptyPath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_003
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with valid PPD file returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_003, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, ppdPath);
    EXPECT_EQ(ret, E_PRINT_NONE);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_001
 * @tc.desc: MarkPpdOption with null ppd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_001, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: MarkPpdOption_002
 * @tc.desc: MarkPpdOption marks cupsPrintQuality Draft via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_002, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_DRAFT);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Draft"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_003
 * @tc.desc: MarkPpdOption marks cupsPrintQuality Normal via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_003, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_NORMAL);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "Normal"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_004
 * @tc.desc: MarkPpdOption marks cupsPrintQuality High via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_004, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_HIGH);
    EXPECT_TRUE(ppdIsMarked(ppd, "cupsPrintQuality", "High"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_005
 * @tc.desc: MarkPpdOption marks ColorModel Gray for monochrome via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_005, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, CUPS_PRINT_COLOR_MODE_MONOCHROME);
    EXPECT_TRUE(ppdIsMarked(ppd, "ColorModel", "Gray"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_006
 * @tc.desc: MarkPpdOption marks ColorModel RGB for color via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_006, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, CUPS_PRINT_COLOR_MODE_COLOR);
    EXPECT_TRUE(ppdIsMarked(ppd, "ColorModel", "RGB"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_007
 * @tc.desc: MarkPpdOption marks Duplex None for one-sided via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_007, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_ONE_SIDED);
    EXPECT_TRUE(ppdIsMarked(ppd, "Duplex", "None"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_008
 * @tc.desc: MarkPpdOption marks Duplex DuplexNoTumble for two-sided-long-edge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_008, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_PORTRAIT);
    EXPECT_TRUE(ppdIsMarked(ppd, "Duplex", "DuplexNoTumble"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_009
 * @tc.desc: MarkPpdOption marks Duplex DuplexTumble for two-sided-short-edge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_009, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_LANDSCAPE);
    EXPECT_TRUE(ppdIsMarked(ppd, "Duplex", "DuplexTumble"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_010
 * @tc.desc: MarkPpdOption marks PageSize A4 via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_010, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
    EXPECT_TRUE(ppdIsMarked(ppd, "PageSize", "A4"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_011
 * @tc.desc: MarkPpdOption marks PageSize Letter via human-readable text matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_011, TestSize.Level1)
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

/**
 * @tc.name: MarkPpdOption_012
 * @tc.desc: MarkPpdOption marks MediaType Plain via map lookup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_012, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    MarkPpdOption(ppd, PRINT_PARAM_TYPE_MEDIA_TYPE, CUPS_MEDIA_TYPE_PLAIN);
    EXPECT_TRUE(ppdIsMarked(ppd, "MediaType", "Plain"));

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: MarkPpdOption_013
 * @tc.desc: MarkPpdOption with unknown type does not crash and produces no conflicts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_013, TestSize.Level1)
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

/**
 * @tc.name: CheckPpdConflicts_001
 * @tc.desc: CheckPpdConflicts with null ppd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_001, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    std::vector<std::string> conflictTypes;
    int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4, conflictTypes);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(conflictTypes.empty());
}

/**
 * @tc.name: CheckPpdConflicts_002
 * @tc.desc: CheckPpdConflicts with valid PPD and non-conflicting option returns zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_002, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::vector<std::string> conflictTypes;
    int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4, conflictTypes);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(conflictTypes.empty());

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ParseMediaTypeAttributeFromPPD_NullTypes_NoCrash
 * @tc.desc: ParseMediaTypeAttributeFromPPD returns without crash when ppdCache->types is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ParseMediaTypeAttributeFromPPD_NullTypes_NoCrash, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);
    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    ASSERT_NE(ppd->cache, nullptr);

    auto *origTypes = ppd->cache->types;
    int origNumTypes = ppd->cache->num_types;
    ppd->cache->types = nullptr;
    ppd->cache->num_types = origNumTypes > 0 ? origNumTypes : 1;

    PrinterCapability printerCaps;
    ParseMediaTypeAttributeFromPPD(ppd, printerCaps);
    std::vector<std::string> mediaTypes;
    printerCaps.GetSupportedMediaType(mediaTypes);
    EXPECT_TRUE(mediaTypes.empty());

    ppd->cache->types = origTypes;
    ppd->cache->num_types = origNumTypes;
    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_001
 * @tc.desc: ConvertOptionAndChoiceNameToPpd with unknown type returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_001, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, "unknownType", "someValue", optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, "unknownType");
    EXPECT_EQ(choiceName, "someValue");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_002
 * @tc.desc: ConvertOptionAndChoiceNameToPpd finds match via map lookup returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_002, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_QUALITY,
        CUPS_PRINT_QUALITY_DRAFT, optName, choiceName);
    EXPECT_TRUE(ret);
    EXPECT_EQ(optName, "cupsPrintQuality");
    EXPECT_EQ(choiceName, "Draft");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_003
 * @tc.desc: ConvertOptionAndChoiceNameToPpd finds PageSize match via text lookup returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_003, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_PAGE_SIZE,
        "US Letter", optName, choiceName);
    EXPECT_TRUE(ret);
    EXPECT_EQ(optName, "PageSize");
    EXPECT_EQ(choiceName, "Letter");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_004
 * @tc.desc: ConvertOptionAndChoiceNameToPpd with no map match and non-PageSize returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_004, TestSize.Level1)
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

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_005
 * @tc.desc: ConvertOptionAndChoiceNameToPpd when type is in map but PPD option missing returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_005, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    // PRINT_PARAM_TYPE_DELIVERY_ORDER maps to "Collate" which is not in this PPD
    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_DELIVERY_ORDER,
        PRINT_PARAM_VAL_TRUE, optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, PRINT_PARAM_TYPE_DELIVERY_ORDER);
    EXPECT_EQ(choiceName, PRINT_PARAM_VAL_TRUE);

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_006
 * @tc.desc: ConvertOptionAndChoiceNameToPpd with PageSize text that does not match returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_006, TestSize.Level1)
{
    std::string ppdPath = CreatePpdWithAllOptions();
    ppd_file_t *ppd = ppdOpenFile(ppdPath.c_str());
    ASSERT_NE(ppd, nullptr);
    ppdMarkDefaults(ppd);

    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_PAGE_SIZE,
        "NonExistentSize", optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, "PageSize");
    EXPECT_EQ(choiceName, "NonExistentSize");

    ppdClose(ppd);
    RemoveTempFile(ppdPath);
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_007
 * @tc.desc: ConvertOptionAndChoiceNameToPpd with null ppd returns false safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_007, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, "unknownType", "someValue", optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, "unknownType");
    EXPECT_EQ(choiceName, "someValue");
}

/**
 * @tc.name: ConvertOptionAndChoiceNameToPpd_008
 * @tc.desc: ConvertOptionAndChoiceNameToPpd with null ppd and valid type returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, ConvertOptionAndChoiceNameToPpd_008, TestSize.Level1)
{
    ppd_file_t *ppd = nullptr;
    std::string optName, choiceName;
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_DRAFT,
        optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, PRINT_PARAM_TYPE_QUALITY);
    EXPECT_EQ(choiceName, CUPS_PRINT_QUALITY_DRAFT);
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
    "*cupsLanguages: \"en zh_CN fr\"\n"
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
    "*CloseUI: MediaType\n"
    "*OpenUI ColorModel: PickOne\n"
    "*OrderDependency: 20 AnySetup ColorModel\n"
    "*DefaultColorModel: RGB\n"
    "*ColorModel RGB/Color: \"<<cupsColorModel 1>>setpagedevice\"\n"
    "*zh_CN.ColorModel RGB/\u5f69\u8272: \"<<cupsColorModel 1>>setpagedevice\"\n"
    "*zh_CN.Translation ColorModel/CNOptionText: \"\"\n"
    "*CloseUI: ColorModel\n"
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
    EXPECT_EQ(optionJson["ppdAvailableLanguages"].size(), 3u);
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



HWTEST_F(PrintCupsPpdTest, QueryPpdAvailableLanguagesFromFile_EmptyAndOpenFail, TestSize.Level1)
{
    Json::Value langs;
    EXPECT_FALSE(QueryPpdAvailableLanguagesFromFile("", langs));
    EXPECT_FALSE(QueryPpdAvailableLanguagesFromFile("/nonexistent/path/no_such.ppd", langs));
}

}  // namespace Print
}  // namespace OHOS
