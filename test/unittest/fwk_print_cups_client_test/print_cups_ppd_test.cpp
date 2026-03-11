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
#include "print_cups_ppd.h"
#include "printer_capability.h"
#include "print_log.h"
#include "print_json_util.h"
#include <fstream>
#include <sys/stat.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

static const std::string TEST_PPD_DIR = "/data/service/el1/public/print_service/test_ppd";

class PrintCupsPpdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string CreateTestPpdFile(const std::string &content);
    void RemoveTestPpdFile(const std::string &filePath);
};

void PrintCupsPpdTest::SetUpTestCase(void)
{
    system(("mkdir -p " + TEST_PPD_DIR).c_str());
}

void PrintCupsPpdTest::TearDownTestCase(void)
{
    system(("rm -rf " + TEST_PPD_DIR).c_str());
}

void PrintCupsPpdTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCupsPpdTest_%{public}d", ++testNo);
}

void PrintCupsPpdTest::TearDown(void)
{}

std::string PrintCupsPpdTest::CreateTestPpdFile(const std::string &content)
{
    std::string filePath = TEST_PPD_DIR + "/test_" + std::to_string(std::rand()) + ".ppd";
    std::ofstream file(filePath);
    if (file.is_open()) {
        file << content;
        file.close();
        return filePath;
    }
    return "";
}

void PrintCupsPpdTest::RemoveTestPpdFile(const std::string &filePath)
{
    if (!filePath.empty()) {
        remove(filePath.c_str());
    }
}

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
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with valid minimal PPD file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_003, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*DefaultDuplex: None
*Duplex None: "<</Duplex false>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_004
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with monochrome printer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_004, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Mono Printer"
*NickName: "Test Mono Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: False
*DefaultColorModel: Gray
*DefaultPageSize: Letter
*PageSize Letter/Letter: "<</PageSize[612 792]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_005
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with various page sizes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_005, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test MultiSize Printer"
*NickName: "Test MultiSize Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*PageSize Letter/Letter: "<</PageSize[612 792]/ImagingBBox null>>setpagedevice"
*PageSize Legal/Legal: "<</PageSize[612 1008]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_006
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with duplex support
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_006, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Duplex Printer"
*NickName: "Test Duplex Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*DefaultDuplex: DuplexNoTumble
*Duplex None: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*Duplex DuplexTumble: "<</Duplex true/Tumble true>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_007
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with print quality options
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_007, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Quality Printer"
*NickName: "Test Quality Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *cupsPrintQuality: PickOne
*DefaultcupsPrintQuality: Normal
*cupsPrintQuality Draft/Draft: "<</cupsPrintQuality 3>>setpagedevice"
*cupsPrintQuality Normal/Normal: "<</cupsPrintQuality 4>>setpagedevice"
*cupsPrintQuality High/High: "<</cupsPrintQuality 5>>setpagedevice"
*CloseUI: *cupsPrintQuality
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_008
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with media type options
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_008, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test MediaType Printer"
*NickName: "Test MediaType Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *MediaType: PickOne
*DefaultMediaType: Plain
*MediaType Plain/Plain Paper: "<</MediaType(Plain)>>setpagedevice"
*MediaType Glossy/Glossy Paper: "<</MediaType(Glossy)>>setpagedevice"
*MediaType Transparency/Transparency: "<</MediaType(Transparency)>>setpagedevice"
*CloseUI: *MediaType
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_009
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with OutputMode quality option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_009, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test OutputMode Printer"
*NickName: "Test OutputMode Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *OutputMode: PickOne
*DefaultOutputMode: Normal
*OutputMode draft/Draft: "<</OutputMode(draft)>>setpagedevice"
*OutputMode fast/Fast: "<</OutputMode(fast)>>setpagedevice"
*OutputMode normal/Normal: "<</OutputMode(normal)>>setpagedevice"
*OutputMode high/High: "<</OutputMode(high)>>setpagedevice"
*OutputMode best/Best: "<</OutputMode(best)>>setpagedevice"
*CloseUI: *OutputMode
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_010
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with manufacturer info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_010, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer With Manufacturer"
*NickName: "Test Printer With Manufacturer"
*Manufacturer: "Test Manufacturer Inc"
*ShortNickName: "TestPrinter"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
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
 * @tc.desc: MarkPpdOption with valid ppd and page size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_002, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*PageSize Letter/Letter: "<</PageSize[612 792]/ImagingBBox null>>setpagedevice"
*OpenUI *Duplex: PickOne
*DefaultDuplex: None
*Duplex None: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *Duplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_003
 * @tc.desc: MarkPpdOption with duplex mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_003, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *Duplex: PickOne
*DefaultDuplex: None
*Duplex None: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*Duplex DuplexTumble: "<</Duplex true/Tumble true>>setpagedevice"
*CloseUI: *Duplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_PORTRAIT);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_004
 * @tc.desc: MarkPpdOption with color mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_004, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *ColorModel: PickOne
*DefaultColorModel: RGB
*ColorModel Gray/Grayscale: "<</cupsColorModel 0>>setpagedevice"
*ColorModel RGB/Color: "<</cupsColorModel 1>>setpagedevice"
*CloseUI: *ColorModel
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_COLOR_MODE, CUPS_PRINT_COLOR_MODE_MONOCHROME);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_005
 * @tc.desc: MarkPpdOption with print quality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_005, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *cupsPrintQuality: PickOne
*DefaultcupsPrintQuality: Normal
*cupsPrintQuality Draft/Draft: "<</cupsPrintQuality 3>>setpagedevice"
*cupsPrintQuality Normal/Normal: "<</cupsPrintQuality 4>>setpagedevice"
*cupsPrintQuality High/High: "<</cupsPrintQuality 5>>setpagedevice"
*CloseUI: *cupsPrintQuality
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_HIGH);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
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
 * @tc.desc: CheckPpdConflicts with valid ppd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_002, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*PageSize Letter/Letter: "<</PageSize[612 792]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        std::vector<std::string> conflictTypes;
        int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_PAGE_SIZE, PAGE_SIZE_ID_ISO_A4, conflictTypes);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: CheckPpdConflicts_003
 * @tc.desc: CheckPpdConflicts with duplex option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_003, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *Duplex: PickOne
*DefaultDuplex: None
*Duplex None: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *Duplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        std::vector<std::string> conflictTypes;
        int32_t ret = CheckPpdConflicts(ppd, PRINT_PARAM_TYPE_DUPLEX_MODE, CUPS_SIDES_TWO_SIDED_PORTRAIT, conflictTypes);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_011
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with JCLDuplex option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_011, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test JCLDuplex Printer"
*NickName: "Test JCLDuplex Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *JCLDuplex: PickOne
*DefaultJCLDuplex: None
*JCLDuplex None: "<</Duplex false>>setpagedevice"
*JCLDuplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *JCLDuplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_012
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with EFDuplex option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_012, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test EFDuplex Printer"
*NickName: "Test EFDuplex Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *EFDuplex: PickOne
*DefaultEFDuplex: None
*EFDuplex None: "<</Duplex false>>setpagedevice"
*EFDuplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *EFDuplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_013
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with KD03Duplex option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_013, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test KD03Duplex Printer"
*NickName: "Test KD03Duplex Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *KD03Duplex: PickOne
*DefaultKD03Duplex: None
*KD03Duplex None: "<</Duplex false>>setpagedevice"
*KD03Duplex DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *KD03Duplex
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_014
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with Collate option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_014, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Collate Printer"
*NickName: "Test Collate Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *Collate: PickOne
*DefaultCollate: True
*Collate True: "<</Collate true>>setpagedevice"
*Collate False: "<</Collate false>>setpagedevice"
*CloseUI: *Collate
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_015
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with EFDuplexing option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_015, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test EFDuplexing Printer"
*NickName: "Test EFDuplexing Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *EFDuplexing: PickOne
*DefaultEFDuplexing: None
*EFDuplexing None: "<</Duplex false>>setpagedevice"
*EFDuplexing DuplexNoTumble: "<</Duplex true/Tumble false>>setpagedevice"
*CloseUI: *EFDuplexing
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_016
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with invalid PPD content
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_016, TestSize.Level1)
{
    std::string ppdContent = "Invalid PPD Content";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_006
 * @tc.desc: MarkPpdOption with unknown option type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_006, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, "UnknownOptionType", "SomeValue");
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: CheckPpdConflicts_004
 * @tc.desc: CheckPpdConflicts with unknown option type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, CheckPpdConflicts_004, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        std::vector<std::string> conflictTypes;
        int32_t ret = CheckPpdConflicts(ppd, "UnknownOptionType", "SomeValue", conflictTypes);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_007
 * @tc.desc: MarkPpdOption with media type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_007, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *MediaType: PickOne
*DefaultMediaType: Plain
*MediaType Plain/Plain Paper: "<</MediaType(Plain)>>setpagedevice"
*MediaType Glossy/Glossy Paper: "<</MediaType(Glossy)>>setpagedevice"
*CloseUI: *MediaType
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_MEDIA_TYPE, CUPS_MEDIA_TYPE_PLAIN);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_008
 * @tc.desc: MarkPpdOption with delivery order (Collate)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_008, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *Collate: PickOne
*DefaultCollate: True
*Collate True: "<</Collate true>>setpagedevice"
*Collate False: "<</Collate false>>setpagedevice"
*CloseUI: *Collate
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_DELIVERY_ORDER, PRINT_PARAM_VAL_TRUE);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_017
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with all common page sizes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_017, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test AllSizes Printer"
*NickName: "Test AllSizes Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*PageSize A3/A3: "<</PageSize[842 1191]/ImagingBBox null>>setpagedevice"
*PageSize Letter/Letter: "<</PageSize[612 792]/ImagingBBox null>>setpagedevice"
*PageSize Legal/Legal: "<</PageSize[612 1008]/ImagingBBox null>>setpagedevice"
*PageSize B4/B4: "<</PageSize[709 1001]/ImagingBBox null>>setpagedevice"
*PageSize B5/B5: "<</PageSize[499 709]/ImagingBBox null>>setpagedevice"
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: QueryPrinterCapabilityFromPPDFile_018
 * @tc.desc: QueryPrinterCapabilityFromPPDFile with PPD_UI_PICKMANY option (should be skipped)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, QueryPrinterCapabilityFromPPDFile_018, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test PickMany Printer"
*NickName: "Test PickMany Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *TestPickMany: PickMany
*DefaultTestPickMany: Option1
*TestPickMany Option1: "<</TestPickMany(Option1)>>setpagedevice"
*TestPickMany Option2: "<</TestPickMany(Option2)>>setpagedevice"
*CloseUI: *TestPickMany
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    PrinterCapability printerCaps;
    int32_t ret = QueryPrinterCapabilityFromPPDFile(printerCaps, filePath);
    EXPECT_EQ(ret, E_PRINT_NONE);

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_009
 * @tc.desc: MarkPpdOption with draft quality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_009, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *cupsPrintQuality: PickOne
*DefaultcupsPrintQuality: Normal
*cupsPrintQuality Draft/Draft: "<</cupsPrintQuality 3>>setpagedevice"
*cupsPrintQuality Normal/Normal: "<</cupsPrintQuality 4>>setpagedevice"
*cupsPrintQuality High/High: "<</cupsPrintQuality 5>>setpagedevice"
*CloseUI: *cupsPrintQuality
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_DRAFT);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

/**
 * @tc.name: MarkPpdOption_010
 * @tc.desc: MarkPpdOption with normal quality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsPpdTest, MarkPpdOption_010, TestSize.Level1)
{
    std::string ppdContent = R"ppd(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageEncoding: ISOLatin1
*LanguageVersion: English
*ModelName: "Test Printer"
*NickName: "Test Printer Model"
*Manufacturer: "Test Manufacturer"
*ColorDevice: True
*DefaultColorModel: RGB
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]/ImagingBBox null>>setpagedevice"
*OpenUI *cupsPrintQuality: PickOne
*DefaultcupsPrintQuality: Normal
*cupsPrintQuality Draft/Draft: "<</cupsPrintQuality 3>>setpagedevice"
*cupsPrintQuality Normal/Normal: "<</cupsPrintQuality 4>>setpagedevice"
*cupsPrintQuality High/High: "<</cupsPrintQuality 5>>setpagedevice"
*CloseUI: *cupsPrintQuality
)ppd";
    std::string filePath = CreateTestPpdFile(ppdContent);
    ASSERT_FALSE(filePath.empty());

    ppd_file_t *ppd = ppdOpenFile(filePath.c_str());
    if (ppd != nullptr) {
        int32_t ret = MarkPpdOption(ppd, PRINT_PARAM_TYPE_QUALITY, CUPS_PRINT_QUALITY_NORMAL);
        EXPECT_GE(ret, 0);
        ppdClose(ppd);
    }

    RemoveTestPpdFile(filePath);
}

}  // namespace Print
}  // namespace OHOS
