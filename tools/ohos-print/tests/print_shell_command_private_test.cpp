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
#include <vector>
#include </.h>
#include <memory>

// Must be defined before including the header under test
#define private public
#define protected public
#include "print_shell_command.h"
#undef protected
#undef private

#include "printer_info.h"
#include "print_job.h"
#include "print_page_size.h"
#include "print_range.h"
#include "print_constant.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Print;

class PrintShellCommandPrivateTest : public ::testing::Test {
protected:
    static std::vector<const char*> BuildArgv(const std::vector<std::string>& args,
        std::vector<std::string>& holder)
    {
        holder = args;
        std::vector<const char*> argv;
        for (auto& s : holder) {
            argv.push_back(s.data());
        }
        return argv;
    }

    void SetUp() override
    {
        auto argv = BuildArgv({"ohos-print", "start-print-job"}, argvHolder_);
        cmd_ = new PrintShellCommand(argv.size(), argv.data());
    }

    void TearDown() override
    {
        delete cmd_;
        cmd_ = nullptr;
    }

    PrintShellCommand* cmd_ = nullptr;
    std::vector<std::string> argvHolder_;

    static void ParseJsonResponse(const std::string& result, Json::Value& out)
    {
        ASSERT_FALSE(result.empty()) << "resultReceiver_ is empty";
        ::CharReaderBuilder rBuilder;
        std::unique_ptr<::CharReader> reader(rBuilder.newCharReader());
        JSONCPP_STRING err;
        ASSERT_TRUE(reader->parse(result.c_str(), result.c_str()  result.length(), &out, &err))
            << "resultReceiver_ is not valid : " << result;
    }
};

// ========== A. ValidateRequiredParams ==========

/**
 * @tc.number: ValidateRequiredParams_BothPresent_0100
 * @tc.name: ValidateRequiredParams with both required params present
 * @tc.desc: When filePath and documentFormat are both non-empty, ValidateRequiredParams returns ERR_OK.
 */
HWTEST_F(PrintShellCommandPrivateTest, ValidateRequiredParams_BothPresent_0100, Function | MediumTest | Level1)
{
    // Given: params with both required fields present
    PrintJobParams params;
    params.filePath = "/data/test.pdf";
    params.documentFormat = "application/pdf";

    // When: calling ValidateRequiredParams
    int32_t ret = cmd_->ValidateRequiredParams(params);

    // Then: should return ERR_OK
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ValidateRequiredParams_MissingFilePath_0100
 * @tc.name: ValidateRequiredParams with missing file-path
 * @tc.desc: When filePath is empty, ValidateRequiredParams returns ERR_INVALID_VALUE.
 */
HWTEST_F(PrintShellCommandPrivateTest, ValidateRequiredParams_MissingFilePath_0100, Function | MediumTest | Level1)
{
    // Given: params with missing filePath
    PrintJobParams params;
    params.filePath = "";
    params.documentFormat = "application/pdf";

    // When: calling ValidateRequiredParams
    int32_t ret = cmd_->ValidateRequiredParams(params);

    // Then: should return ERR_INVALID_VALUE and set resultReceiver_ with ERR_ARG_MISSING
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_ARG_MISSING");
    EXPECT_NE(response["errMsg"].asString().find("file-path"), std::string::npos);
}

/**
 * @tc.number: ValidateRequiredParams_MissingDocFormat_0100
 * @tc.name: ValidateRequiredParams with missing document-format
 * @tc.desc: When documentFormat is empty, ValidateRequiredParams returns ERR_INVALID_VALUE.
 */
HWTEST_F(PrintShellCommandPrivateTest, ValidateRequiredParams_MissingDocFormat_0100, Function | MediumTest | Level1)
{
    // Given: params with missing documentFormat
    PrintJobParams params;
    params.filePath = "/data/test.pdf";
    params.documentFormat = "";

    // When: calling ValidateRequiredParams
    int32_t ret = cmd_->ValidateRequiredParams(params);

    // Then: should return ERR_INVALID_VALUE and set resultReceiver_ with ERR_ARG_MISSING
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_ARG_MISSING");
    EXPECT_NE(response["errMsg"].asString().find("document-format"), std::string::npos);
}

// ========== B. ApplyStartPrintJobOption ==========

/**
 * @tc.number: ApplyOption_CollateTrue_0100
 * @tc.name: ApplyStartPrintJobOption with collate=true
 * @tc.desc: When opt is START_OPTION_COLLATE and optarg is "true", params.collate should be true.
 */
HWTEST_F(PrintShellCommandPrivateTest, ApplyOption_CollateTrue_0100, Function | MediumTest | Level1)
{
    // Given: START_OPTION_COLLATE with "true"
    PrintJobParams params;
    optind = 0;
    // Simulate optarg for collate
    static std::string collateValue = "true";
    optarg = const_cast<char*>(collateValue.c_str());

    // When: calling ApplyStartPrintJobOption
    cmd_->ApplyStartPrintJobOption(START_OPTION_COLLATE, params);

    // Then: collateInput should be "true" and collate should be true
    EXPECT_EQ(params.collateInput, "true");
    EXPECT_TRUE(params.collate);
}

/**
 * @tc.number: ApplyOption_CollateFalse_0100
 * @tc.name: ApplyStartPrintJobOption with collate=false
 * @tc.desc: When opt is START_OPTION_COLLATE and optarg is "false", params.collate should be false.
 */
HWTEST_F(PrintShellCommandPrivateTest, ApplyOption_CollateFalse_0100, Function | MediumTest | Level1)
{
    // Given: START_OPTION_COLLATE with "false"
    PrintJobParams params;
    static std::string collateValue = "false";
    optarg = const_cast<char*>(collateValue.c_str());

    // When: calling ApplyStartPrintJobOption
    cmd_->ApplyStartPrintJobOption(START_OPTION_COLLATE, params);

    // Then: collateInput should be "false" and collate should be false
    EXPECT_EQ(params.collateInput, "false");
    EXPECT_FALSE(params.collate);
}

/**
 * @tc.number: ApplyOption_FilePath_0100
 * @tc.name: ApplyStartPrintJobOption with file-path
 * @tc.desc: When opt is START_OPTION_FILE_PATH, params.filePath should be set.
 */
HWTEST_F(PrintShellCommandPrivateTest, ApplyOption_FilePath_0100, Function | MediumTest | Level1)
{
    // Given: START_OPTION_FILE_PATH
    PrintJobParams params;
    static std::string filePath = "/data/test.pdf";
    optarg = const_cast<char*>(filePath.c_str());

    // When: calling ApplyStartPrintJobOption
    cmd_->ApplyStartPrintJobOption(START_OPTION_FILE_PATH, params);

    // Then: filePath should be set
    EXPECT_EQ(params.filePath, "/data/test.pdf");
}

/**
 * @tc.number: ApplyOption_DocumentFormat_0100
 * @tc.name: ApplyStartPrintJobOption with document-format
 * @tc.desc: When opt is START_OPTION_DOCUMENT_FORMAT, params.documentFormat should be set.
 */
HWTEST_F(PrintShellCommandPrivateTest, ApplyOption_DocumentFormat_0100, Function | MediumTest | Level1)
{
    // Given: START_OPTION_DOCUMENT_FORMAT
    PrintJobParams params;
    static std::string docFormat = "application/pdf";
    optarg = const_cast<char*>(docFormat.c_str());

    // When: calling ApplyStartPrintJobOption
    cmd_->ApplyStartPrintJobOption(START_OPTION_DOCUMENT_FORMAT, params);

    // Then: documentFormat should be set
    EXPECT_EQ(params.documentFormat, "application/pdf");
}

/**
 * @tc.number: ApplyOption_PrinterId_0100
 * @tc.name: ApplyStartPrintJobOption with printer-id
 * @tc.desc: When opt is START_OPTION_PRINTER_ID, params.printerId should be set.
 */
HWTEST_F(PrintShellCommandPrivateTest, ApplyOption_PrinterId_0100, Function | MediumTest | Level1)
{
    // Given: START_OPTION_PRINTER_ID
    PrintJobParams params;
    static std::string printerId = "printer001";
    optarg = const_cast<char*>(printerId.c_str());

    // When: calling ApplyStartPrintJobOption
    cmd_->ApplyStartPrintJobOption(START_OPTION_PRINTER_ID, params);

    // Then: printerId should be set
    EXPECT_EQ(params.printerId, "printer001");
}

// ========== C. MapInputParams ==========

/**
 * @tc.number: MapInputParams_AllDefaults_0100
 * @tc.name: MapInputParams with all empty inputs
 * @tc.desc: When all input fields are empty, defaults should be applied.
 */
HWTEST_F(PrintShellCommandPrivateTest, MapInputParams_AllDefaults_0100, Function | MediumTest | Level1)
{
    // Given: params with all input fields empty
    PrintJobParams params;

    // When: calling MapInputParams
    MappedParams mapped;
    int32_t ret = cmd_->MapInputParams(params, mapped);

    // Then: default values should be applied
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mapped.copyNumber, DEFAULT_COPIES);
    EXPECT_EQ(mapped.pageSizeId, DEFAULT_PAGE_SIZE_ID);
    EXPECT_EQ(mapped.direction, DIRECTION_MODE_PORTRAIT);
    EXPECT_EQ(mapped.colorMode, 0u);
    EXPECT_EQ(mapped.duplexMode, 0u);
}

/**
 * @tc.number: MapInputParams_AllProvided_0100
 * @tc.name: MapInputParams with all inputs provided
 * @tc.desc: When all input fields are provided, mapped values should reflect the inputs.
 */
HWTEST_F(PrintShellCommandPrivateTest, MapInputParams_AllProvided_0100, Function | MediumTest | Level1)
{
    // Given: params with all inputs set
    PrintJobParams params;
    params.copiesInput = "3";
    params.pageSizeInput = "A3";
    params.directionInput = "landscape";
    params.colorModeInput = "color";
    params.duplexInput = "long";

    // When: calling MapInputParams
    MappedParams mapped;
    int32_t ret = cmd_->MapInputParams(params, mapped);

    // Then: mapped values should reflect the provided inputs
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mapped.copyNumber, 3u);
    EXPECT_EQ(mapped.pageSizeId, "ISO_A3");
    EXPECT_EQ(mapped.direction, DIRECTION_MODE_LANDSCAPE);
    EXPECT_EQ(mapped.colorMode, 1u);
    EXPECT_EQ(mapped.duplexMode, 1u);
}

// ========== D. BuildOptionsJson ==========

/**
 * @tc.number: BuildOptionsJson_Minimal_0100
 * @tc.name: BuildOptionsJson with only required params
 * @tc.desc: When only required params are set, no copies/pageSize/direction/colorMode/duplex/pageRange/collate fields.
 */
HWTEST_F(PrintShellCommandPrivateTest, BuildOptionsJson_Minimal_0100, Function | MediumTest | Level1)
{
    // Given: minimal params with only required fields and printerUri
    PrintJobParams params;
    params.filePath = "/data/test.pdf";
    params.documentFormat = "application/pdf";
    params.printerUri = "lpd://192.168.1.1:515/auto";

    // When: calling BuildOptionsJson
    Json::Value optionsJson;
    cmd_->BuildOptionsJson(params, "test.pdf", 1, optionsJson);

    // Then: required fields should exist, optional fields should not
    EXPECT_EQ(optionsJson["jobName"].asString(), "test.pdf");
    EXPECT_EQ(optionsJson["printerUri"].asString(), "lpd://192.168.1.1:515/auto");
    EXPECT_EQ(optionsJson["documentFormat"].asString(), "application/pdf");
    EXPECT_FALSE(optionsJson.isMember("copies"));
    EXPECT_FALSE(optionsJson.isMember("pageSize"));
    EXPECT_FALSE(optionsJson.isMember("direction"));
    EXPECT_FALSE(optionsJson.isMember("colorMode"));
    EXPECT_FALSE(optionsJson.isMember("duplex"));
    EXPECT_FALSE(optionsJson.isMember("pageRange"));
    EXPECT_FALSE(optionsJson.isMember("collate"));
}

/**
 * @tc.number: BuildOptionsJson_AllOptions_0100
 * @tc.name: BuildOptionsJson with all optional params
 * @tc.desc: When all optional params are provided, all fields should exist in output .
 */
HWTEST_F(PrintShellCommandPrivateTest, BuildOptionsJson_AllOptions_0100, Function | MediumTest | Level1)
{
    // Given: params with all optional fields set
    PrintJobParams params;
    params.filePath = "/data/test.pdf";
    params.documentFormat = "application/pdf";
    params.printerUri = "lpd://192.168.1.1:515/auto";
    params.copiesInput = "3";
    params.pageSizeInput = "A4";
    params.directionInput = "landscape";
    params.colorModeInput = "color";
    params.duplexInput = "long";
    params.pageRangeInput = "1-5";
    params.collateInput = "true";
    params.collate = true;

    // When: calling BuildOptionsJson
    Json::Value optionsJson;
    cmd_->BuildOptionsJson(params, "test.pdf", 3, optionsJson);

    // Then: all optional fields should exist
    EXPECT_TRUE(optionsJson.isMember("copies"));
    EXPECT_TRUE(optionsJson.isMember("pageSize"));
    EXPECT_TRUE(optionsJson.isMember("direction"));
    EXPECT_TRUE(optionsJson.isMember("colorMode"));
    EXPECT_TRUE(optionsJson.isMember("duplex"));
    EXPECT_TRUE(optionsJson.isMember("pageRange"));
    EXPECT_TRUE(optionsJson.isMember("collate"));
    EXPECT_EQ(optionsJson["copies"].asString(), "3");
    EXPECT_EQ(optionsJson["direction"].asString(), "landscape");
    EXPECT_EQ(optionsJson["colorMode"].asString(), "color");
    EXPECT_EQ(optionsJson["duplex"].asString(), "long");
    EXPECT_EQ(optionsJson["pageRange"].asString(), "1-5");
    EXPECT_EQ(optionsJson["collate"].asString(), "collate");
}

/**
 * @tc.number: BuildOptionsJson_ImageFormat_0100
 * @tc.name: BuildOptionsJson with image format
 * @tc.desc: When documentFormat is "image/png", isImageFormat should be true and jobDesArr should reflect that.
 */
HWTEST_F(PrintShellCommandPrivateTest, BuildOptionsJson_ImageFormat_0100, Function | MediumTest | Level1)
{
    // Given: image format document
    PrintJobParams params;
    params.filePath = "/data/test.png";
    params.documentFormat = "image/png";
    params.printerUri = "lpd://192.168.1.1:515/auto";

    // When: calling BuildOptionsJson
    Json::Value optionsJson;
    cmd_->BuildOptionsJson(params, "test.png", 1, optionsJson);

    // Then: jobDesArr should indicate image format [jobName, "1", "0"]
    EXPECT_TRUE(optionsJson.isMember("jobDesArr"));
    EXPECT_EQ(optionsJson["jobDesArr"][1].asString(), "1");
    EXPECT_EQ(optionsJson["jobDesArr"][2].asString(), "0");
}

/**
 * @tc.number: BuildOptionsJson_PdfFormat_0100
 * @tc.name: BuildOptionsJson with PDF format
 * @tc.desc: When documentFormat is "application/pdf", isImageFormat should be false and jobDesArr should reflect that.
 */
HWTEST_F(PrintShellCommandPrivateTest, BuildOptionsJson_PdfFormat_0100, Function | MediumTest | Level1)
{
    // Given: PDF format document
    PrintJobParams params;
    params.filePath = "/data/test.pdf";
    params.documentFormat = "application/pdf";
    params.printerUri = "lpd://192.168.1.1:515/auto";

    // When: calling BuildOptionsJson
    Json::Value optionsJson;
    cmd_->BuildOptionsJson(params, "test.pdf", 1, optionsJson);

    // Then: jobDesArr should indicate PDF format [jobName, "0", "1"]
    EXPECT_TRUE(optionsJson.isMember("jobDesArr"));
    EXPECT_EQ(optionsJson["jobDesArr"][1].asString(), "0");
    EXPECT_EQ(optionsJson["jobDesArr"][2].asString(), "1");
}

// ========== E. SetPageRangeOnJob ==========

/**
 * @tc.number: SetPageRange_RangeFormat_0100
 * @tc.name: SetPageRangeOnJob with range format "1-5"
 * @tc.desc: Page range "1-5" should set startPage=1 and endPage=5.
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageRange_RangeFormat_0100, Function | MediumTest | Level1)
{
    // Given: page range input "1-5"
    PrintJob printJob;

    // When: calling SetPageRangeOnJob
    int32_t ret = cmd_->SetPageRangeOnJob("1-5", printJob);

    // Then: should return ERR_OK and set startPage and endPage
    EXPECT_EQ(ret, ERR_OK);
    PrintRange range;
    printJob.GetPageRange(range);
    EXPECT_EQ(range.GetStartPage(), 1u);
    EXPECT_EQ(range.GetEndPage(), 5u);
}

/**
 * @tc.number: SetPageRange_PagesFormat_0100
 * @tc.name: SetPageRangeOnJob with pages format "1,3,5"
 * @tc.desc: Page range "1,3,5" should set pages=[1,3,5].
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageRange_PagesFormat_0100, Function | MediumTest | Level1)
{
    // Given: page range input "1,3,5"
    PrintJob printJob;

    // When: calling SetPageRangeOnJob
    int32_t ret = cmd_->SetPageRangeOnJob("1,3,5", printJob);

    // Then: should return ERR_OK and set pages
    EXPECT_EQ(ret, ERR_OK);
    PrintRange range;
    printJob.GetPageRange(range);
    std::vector<uint32_t> pages;
    range.GetPages(pages);
    EXPECT_EQ(pages.size(), 3u);
    EXPECT_EQ(pages[0], 1u);
    EXPECT_EQ(pages[1], 3u);
    EXPECT_EQ(pages[2], 5u);
}

/**
 * @tc.number: SetPageRange_InvalidRange_0100
 * @tc.name: SetPageRangeOnJob with invalid range "abc-def"
 * @tc.desc: Invalid page range "abc-def" should return ERR_INVALID_VALUE.
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageRange_InvalidRange_0100, Function | MediumTest | Level1)
{
    // Given: invalid page range input "abc-def"
    PrintJob printJob;

    // When: calling SetPageRangeOnJob
    int32_t ret = cmd_->SetPageRangeOnJob("abc-def", printJob);

    // Then: should return ERR_INVALID_VALUE and set resultReceiver_ with ERR_INVALID_INPUT
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_INVALID_INPUT");
}

/**
 * @tc.number: SetPageRange_InvalidPage_0100
 * @tc.name: SetPageRangeOnJob with invalid page "1,abc,3"
 * @tc.desc: Invalid page number in range should return ERR_INVALID_VALUE.
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageRange_InvalidPage_0100, Function | MediumTest | Level1)
{
    // Given: invalid page number in range "1,abc,3"
    PrintJob printJob;

    // When: calling SetPageRangeOnJob
    int32_t ret = cmd_->SetPageRangeOnJob("1,abc,3", printJob);

    // Then: should return ERR_INVALID_VALUE and set resultReceiver_ with ERR_INVALID_INPUT
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_INVALID_INPUT");
}

// ========== F. SetPageSizeOnJob ==========

/**
 * @tc.number: SetPageSize_KnownId_0100
 * @tc.name: SetPageSizeOnJob with known page size ID
 * @tc.desc: Known page size ID "ISO_A4" should be found via FindPageSizeById and set on the print job.
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageSize_KnownId_0100, Function | MediumTest | Level1)
{
    // Given: known page size ID
    PrintJob printJob;
    PrintPageSize::BuildPageSizeMap();

    // When: calling SetPageSizeOnJob with "ISO_A4"
    cmd_->SetPageSizeOnJob("ISO_A4", printJob);

    // Then: page size should be set on the print job
    PrintPageSize pageSize;
    printJob.GetPageSize(pageSize);
    EXPECT_EQ(pageSize.GetId(), "ISO_A4");
}

/**
 * @tc.number: SetPageSize_UnknownId_0100
 * @tc.name: SetPageSizeOnJob with unknown page size ID
 * @tc.desc: Unknown page size ID should fall back to default values.
 */
HWTEST_F(PrintShellCommandPrivateTest, SetPageSize_UnknownId_0100, Function | MediumTest | Level1)
{
    // Given: unknown page size ID
    PrintJob printJob;

    // When: calling SetPageSizeOnJob with "custom_id"
    cmd_->SetPageSizeOnJob("custom_id", printJob);

    // Then: fallback page size should be set
    PrintPageSize pageSize;
    printJob.GetPageSize(pageSize);
    EXPECT_EQ(pageSize.GetName(), FALLBACK_PAGE_SIZE_NAME);
    EXPECT_EQ(pageSize.GetWidth(), static_cast<uint32_t>(FALLBACK_PAGE_SIZE_WIDTH));
    EXPECT_EQ(pageSize.GetHeight(), static_cast<uint32_t>(FALLBACK_PAGE_SIZE_HEIGHT));
}

// ========== G. HandleQueryAddedPrinterError ==========

/**
 * @tc.number: HandleQueryError_NoPermission_0100
 * @tc.name: HandleQueryAddedPrinterError with E_PRINT_NO_PERMISSION
 * @tc.desc: E_PRINT_NO_PERMISSION should result in ERR_PERMISSION_DENIED in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleQueryError_NoPermission_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_NO_PERMISSION
    cmd_->resultReceiver_.clear();

    // When: calling HandleQueryAddedPrinterError
    int32_t ret = cmd_->HandleQueryAddedPrinterError(E_PRINT_NO_PERMISSION);

    // Then: should return ERR_INVALID_VALUE and output ERR_PERMISSION_DENIED
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PERMISSION_DENIED");
}

/**
 * @tc.number: HandleQueryError_RpcFailure_0100
 * @tc.name: HandleQueryAddedPrinterError with E_PRINT_RPC_FAILURE
 * @tc.desc: E_PRINT_RPC_FAILURE should result in ERR_PRINT_RPC_FAILURE in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleQueryError_RpcFailure_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_RPC_FAILURE
    cmd_->resultReceiver_.clear();

    // When: calling HandleQueryAddedPrinterError
    int32_t ret = cmd_->HandleQueryAddedPrinterError(E_PRINT_RPC_FAILURE);

    // Then: should return ERR_INVALID_VALUE and output ERR_PRINT_RPC_FAILURE
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PRINT_RPC_FAILURE");
}

/**
 * @tc.number: HandleQueryError_Other_0100
 * @tc.name: HandleQueryAddedPrinterError with other error code
 * @tc.desc: Other error codes should result in ERR_PRINT_QUERY_FAILED in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleQueryError_Other_0100, Function | MediumTest | Level1)
{
    // Given: ret = some other error code
    cmd_->resultReceiver_.clear();

    // When: calling HandleQueryAddedPrinterError
    int32_t ret = cmd_->HandleQueryAddedPrinterError(E_PRINT_GENERIC_FAILURE);

    // Then: should return ERR_INVALID_VALUE and output ERR_PRINT_QUERY_FAILED
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PRINT_QUERY_FAILED");
}

// ========== H. HandleStartPrintJobResult ==========

/**
 * @tc.number: HandleJobResult_Success_0100
 * @tc.name: HandleStartPrintJobResult with E_PRINT_NONE
 * @tc.desc: E_PRINT_NONE should return ERR_OK.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleJobResult_Success_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_NONE
    cmd_->resultReceiver_.clear();

    // When: calling HandleStartPrintJobResult
    int32_t ret = cmd_->HandleStartPrintJobResult(E_PRINT_NONE);

    // Then: should return ERR_OK
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HandleJobResult_NoPermission_0100
 * @tc.name: HandleStartPrintJobResult with E_PRINT_NO_PERMISSION
 * @tc.desc: E_PRINT_NO_PERMISSION should result in ERR_PERMISSION_DENIED in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleJobResult_NoPermission_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_NO_PERMISSION
    cmd_->resultReceiver_.clear();

    // When: calling HandleStartPrintJobResult
    int32_t ret = cmd_->HandleStartPrintJobResult(E_PRINT_NO_PERMISSION);

    // Then: should return ERR_INVALID_VALUE and output ERR_PERMISSION_DENIED
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PERMISSION_DENIED");
}

/**
 * @tc.number: HandleJobResult_RpcFailure_0100
 * @tc.name: HandleStartPrintJobResult with E_PRINT_RPC_FAILURE
 * @tc.desc: E_PRINT_RPC_FAILURE should result in ERR_PRINT_RPC_FAILURE in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleJobResult_RpcFailure_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_RPC_FAILURE
    cmd_->resultReceiver_.clear();

    // When: calling HandleStartPrintJobResult
    int32_t ret = cmd_->HandleStartPrintJobResult(E_PRINT_RPC_FAILURE);

    // Then: should return ERR_INVALID_VALUE and output ERR_PRINT_RPC_FAILURE
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PRINT_RPC_FAILURE");
}

/**
 * @tc.number: HandleJobResult_InvalidPrinter_0100
 * @tc.name: HandleStartPrintJobResult with E_PRINT_INVALID_PRINTER
 * @tc.desc: E_PRINT_INVALID_PRINTER should result in ERR_INVALID_PRINTER in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleJobResult_InvalidPrinter_0100, Function | MediumTest | Level1)
{
    // Given: ret = E_PRINT_INVALID_PRINTER
    cmd_->resultReceiver_.clear();

    // When: calling HandleStartPrintJobResult
    int32_t ret = cmd_->HandleStartPrintJobResult(E_PRINT_INVALID_PRINTER);

    // Then: should return ERR_INVALID_VALUE and output ERR_INVALID_PRINTER
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_INVALID_PRINTER");
}

/**
 * @tc.number: HandleJobResult_Other_0100
 * @tc.name: HandleStartPrintJobResult with other error code
 * @tc.desc: Other error codes should result in ERR_PRINT_JOB_FAILED in output.
 */
HWTEST_F(PrintShellCommandPrivateTest, HandleJobResult_Other_0100, Function | MediumTest | Level1)
{
    // Given: ret = some other error code
    cmd_->resultReceiver_.clear();

    // When: calling HandleStartPrintJobResult
    int32_t ret = cmd_->HandleStartPrintJobResult(E_PRINT_GENERIC_FAILURE);

    // Then: should return ERR_INVALID_VALUE and output ERR_PRINT_JOB_FAILED
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PRINT_JOB_FAILED");
}

// ========== I. CheckPrinterStatus ==========

/**
 * @tc.number: CheckStatus_InvalidInput_0100
 * @tc.name: CheckPrinterStatus with non-numeric status input
 * @tc.desc: Non-numeric printerStatusInput should result in ERR_INVALID_INPUT.
 */
HWTEST_F(PrintShellCommandPrivateTest, CheckStatus_InvalidInput_0100, Function | MediumTest | Level1)
{
    // Given: non-numeric status input (does not depend on PrintManagerClient since input is provided)
    cmd_->resultReceiver_.clear();

    // When: calling CheckPrinterStatus with non-numeric status
    int32_t ret = cmd_->CheckPrinterStatus("printer001", "abc");

    // Then: should return ERR_INVALID_VALUE and output ERR_INVALID_INPUT
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_INVALID_INPUT");
}

/**
 * @tc.number: CheckStatus_ExplicitUnavailable_0100
 * @tc.name: CheckPrinterStatus with explicit UNAVAILABLE status
 * @tc.desc: Explicit status=2 (UNAVAILABLE) should result in ERR_PRINTER_UNAVAILABLE.
 */
HWTEST_F(PrintShellCommandPrivateTest, CheckStatus_ExplicitUnavailable_0100, Function | MediumTest | Level1)
{
    // Given: status input "2" (PRINTER_STATUS_UNAVAILABLE)
    cmd_->resultReceiver_.clear();

    // When: calling CheckPrinterStatus with "2"
    int32_t ret = cmd_->CheckPrinterStatus("printer001", "2");

    // Then: should return ERR_INVALID_VALUE and output ERR_PRINTER_UNAVAILABLE
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Json::Value response; ParseJsonResponse(cmd_->resultReceiver_, response);
    EXPECT_EQ(response["errCode"].asString(), "ERR_PRINTER_UNAVAILABLE");
}

/**
 * @tc.number: CheckStatus_Available_0100
 * @tc.name: CheckPrinterStatus with available status
 * @tc.desc: Explicit status=0 (IDLE) should return ERR_OK.
 */
HWTEST_F(PrintShellCommandPrivateTest, CheckStatus_Available_0100, Function | MediumTest | Level1)
{
    // Given: status input "0" (IDLE)
    cmd_->resultReceiver_.clear();

    // When: calling CheckPrinterStatus with "0"
    int32_t ret = cmd_->CheckPrinterStatus("printer001", "0");

    // Then: should return ERR_OK
    EXPECT_EQ(ret, ERR_OK);
}

// ========== J. MarshalPrinterInfo ==========

/**
 * @tc.number: MarshalPrinter_AllFields_0100
 * @tc.name: MarshalPrinterInfo with all optional fields set
 * @tc.desc: PrinterInfo with all optional fields should produce  containing all those fields.
 */
HWTEST_F(PrintShellCommandPrivateTest, MarshalPrinter_AllFields_0100, Function | MediumTest | Level1)
{
    // Given: PrinterInfo with all optional fields set
    PrinterInfo info;
    info.SetPrinterId("printer001");
    info.SetPrinterName("TestPrinter");
    info.SetUri("lpd://192.168.1.1:515/auto");
    info.SetIsDefaultPrinter(true);
    info.SetPrinterStatus(0);
    info.SetPrinterMake("HP");
    info.SetAlias("MyPrinter");

    // When: calling MarshalPrinterInfo
    Json::Value data;
    cmd_->MarshalPrinterInfo(info, data);

    // Then: all fields should appear in 
    EXPECT_EQ(data["printerId"].asString(), "printer001");
    EXPECT_EQ(data["printerName"].asString(), "TestPrinter");
    EXPECT_EQ(data["uri"].asString(), "lpd://192.168.1.1:515/auto");
    EXPECT_TRUE(data.isMember("isDefaultPrinter"));
    EXPECT_TRUE(data["isDefaultPrinter"].isBool());
    EXPECT_TRUE(data.isMember("printerStatus"));
    EXPECT_TRUE(data.isMember("printerMake"));
    EXPECT_EQ(data["printerMake"].asString(), "HP");
    EXPECT_TRUE(data.isMember("alias"));
    EXPECT_EQ(data["alias"].asString(), "MyPrinter");
}

/**
 * @tc.number: MarshalPrinter_MinimalFields_0100
 * @tc.name: MarshalPrinterInfo with only required fields
 * @tc.desc: PrinterInfo with only required fields should produce  without optional fields.
 */
HWTEST_F(PrintShellCommandPrivateTest, MarshalPrinter_MinimalFields_0100, Function | MediumTest | Level1)
{
    // Given: PrinterInfo with only required fields (id, name, uri)
    PrinterInfo info;
    info.SetPrinterId("printer002");
    info.SetPrinterName("MinimalPrinter");
    info.SetUri("ipp://10.0.0.1/ipp/print");

    // When: calling MarshalPrinterInfo
    Json::Value data;
    cmd_->MarshalPrinterInfo(info, data);

    // Then: required fields should exist, optional fields should not
    EXPECT_EQ(data["printerId"].asString(), "printer002");
    EXPECT_EQ(data["printerName"].asString(), "MinimalPrinter");
    EXPECT_EQ(data["uri"].asString(), "ipp://10.0.0.1/ipp/print");
    EXPECT_FALSE(data.isMember("isDefaultPrinter"));
    EXPECT_FALSE(data.isMember("printerStatus"));
    EXPECT_FALSE(data.isMember("printerMake"));
    EXPECT_FALSE(data.isMember("alias"));
}

// ========== K. CloseFdList ==========

/**
 * @tc.number: CloseFdList_NonEmpty_0100
 * @tc.name: CloseFdList with non-empty list
 * @tc.desc: After calling CloseFdList, the fd list should be empty.
 */
HWTEST_F(PrintShellCommandPrivateTest, CloseFdList_NonEmpty_0100, Function | MediumTest | Level1)
{
    // Given: a non-empty fdList (use stdin fd=0 which is always valid and close is safe)
    std::vector<uint32_t> fdList;
    // We do not actually open files; use dup to create valid fds that can be closed safely
    int fd = dup(STDIN_FILENO);
    ASSERT_GE(fd, 0);
    fdList.push_back(static_cast<uint32_t>(fd));

    // When: calling CloseFdList
    cmd_->CloseFdList(fdList);

    // Then: fdList should be empty
    EXPECT_TRUE(fdList.empty());
}

/**
 * @tc.number: CloseFdList_Empty_0100
 * @tc.name: CloseFdList with empty list
 * @tc.desc: Calling CloseFdList on an empty list should not crash.
 */
HWTEST_F(PrintShellCommandPrivateTest, CloseFdList_Empty_0100, Function | MediumTest | Level1)
{
    // Given: an empty fdList
    std::vector<uint32_t> fdList;

    // When: calling CloseFdList
    cmd_->CloseFdList(fdList);

    // Then: no crash, fdList remains empty
    EXPECT_TRUE(fdList.empty());
}
