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

// Forward declaration: ConvertOptionAndChoiceNameToPpd is defined in print_cups_ppd.cpp
// but not declared in the header. Declared here for direct unit testing.
bool ConvertOptionAndChoiceNameToPpd(ppd_file_t *ppd, const std::string &type, const std::string &val,
    std::string &optName, std::string &choiceName);

class PrintCupsPpdTest : public testing::Test {
protected:
    std::string CreateTempPpdFile(const std::string &content)
    {
        std::string tempPath = "/data/local/tmp/test_ppd_" + std::to_string(getpid()) + ".ppd";
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
    bool ret = ConvertOptionAndChoiceNameToPpd(ppd, PRINT_PARAM_TYPE_QUALITY,
        CUPS_PRINT_QUALITY_DRAFT, optName, choiceName);
    EXPECT_FALSE(ret);
    EXPECT_EQ(optName, PRINT_PARAM_TYPE_QUALITY);
    EXPECT_EQ(choiceName, CUPS_PRINT_QUALITY_DRAFT);
}

}  // namespace Print
}  // namespace OHOS
