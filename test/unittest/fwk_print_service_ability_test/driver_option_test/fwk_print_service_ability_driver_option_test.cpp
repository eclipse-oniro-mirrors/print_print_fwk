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

HWTEST_F(PrintServiceAbilityTest, UpdatePageSizeNameWithPrinterInfo_StandardPageSize_NameUnchanged, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo printerInfo;
    PrintPageSize pageSize;
    pageSize.SetId("ISO_A4");
    pageSize.SetName("iso_a4_210x297mm");
    service->UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
    EXPECT_EQ(pageSize.GetName(), "iso_a4_210x297mm");
}

HWTEST_F(
    PrintServiceAbilityTest, UpdatePageSizeNameWithPrinterInfo_FindNonStandardPageSize_NameChanged, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintPageSize pageSize;
    pageSize.SetId("A4.borderless");
    pageSize.SetName("iso_a4_210x297mm");

    PrinterInfo printerInfo;
    PrinterCapability printerCapability;
    std::vector<PrintPageSize> supportedPageSizeList;
    PrintPageSize custompPageSize;
    custompPageSize.SetId("A4.borderless");
    custompPageSize.SetName("A4.borderless");
    supportedPageSizeList.emplace_back(custompPageSize);
    printerCapability.SetSupportedPageSize(supportedPageSizeList);
    printerInfo.SetCapability(printerCapability);
    service->UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
    EXPECT_EQ(pageSize.GetName(), "A4.borderless");
}

HWTEST_F(PrintServiceAbilityTest, UpdatePageSizeNameWithPrinterInfo_CannotFindNonStandardPageSize_NameUnchanged,
    TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrintPageSize pageSize;
    pageSize.SetId("A4.borderless");
    pageSize.SetName("iso_a4_210x297mm");

    PrinterInfo printerInfo;
    PrinterCapability printerCapability;
    std::vector<PrintPageSize> supportedPageSizeList;
    PrintPageSize custompPageSize;
    custompPageSize.SetId("A5.borderless");
    custompPageSize.SetName("A5.borderless");
    supportedPageSizeList.emplace_back(custompPageSize);
    printerInfo.SetCapability(printerCapability);
    printerCapability.SetSupportedPageSize(supportedPageSizeList);
    service->UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
    EXPECT_EQ(pageSize.GetName(), "iso_a4_210x297mm");
}

HWTEST_F(PrintServiceAbilityTest, RefreshPrinterPageSize, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo printerInfo;
    PrinterCapability cap;
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSize.SetWidth(ISO_A4_WIDTH);
    pageSize.SetHeight(ISO_A4_HEIGHT);
    pageSizeList.push_back(pageSize);
    cap.SetSupportedPageSize(pageSizeList);
    printerInfo.SetCapability(cap);
    service->RefreshPrinterPageSize(printerInfo);
    printerInfo.GetCapability(cap);
    cap.GetSupportedPageSize(pageSizeList);
    EXPECT_EQ(pageSizeList.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, UpdateBsuniPrinterAdvanceOptions_OptionFormatError_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    printerCaps.SetOption("test");
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdateBsuniPrinterAdvanceOptions_NoSupportOption_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    Json::Value cupsOptionsJson;
    cupsOptionsJson["key"] = "value";
    optionJson["cupsOptions"] = cupsOptionsJson;
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest,
    UpdateBsuniPrinterAdvanceOptions_SupportOptionFormatError_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    Json::Value cupsOptionsJson;
    cupsOptionsJson["media-source-supported"] = 1;
    optionJson["cupsOptions"] = cupsOptionsJson;
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdateBsuniPrinterAdvanceOptions_NoDefaultOption_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    Json::Value cupsOptionsJson;
    Json::Value supportedArrayJson;
    supportedArrayJson.append("auto");
    cupsOptionsJson["media-source-supported"] = PrintJsonUtil::WriteStringUTF8(supportedArrayJson);
    optionJson["cupsOptions"] = cupsOptionsJson;
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest,
    UpdateBsuniPrinterAdvanceOptions_DefaultOptionFormatError_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    Json::Value cupsOptionsJson;
    Json::Value supportedArrayJson;
    supportedArrayJson.append("auto");
    cupsOptionsJson["media-source-supported"] = PrintJsonUtil::WriteStringUTF8(supportedArrayJson);
    cupsOptionsJson["media-source-default"] = 1;
    optionJson["cupsOptions"] = cupsOptionsJson;
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest,
    UpdateBsuniPrinterAdvanceOptions_CorrectAdvanceOption_ReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    Json::Value cupsOptionsJson;
    Json::Value supportedArrayJson;
    supportedArrayJson.append("auto");
    cupsOptionsJson["media-source-supported"] = PrintJsonUtil::WriteStringUTF8(supportedArrayJson);
    cupsOptionsJson["media-source-default"] = "auto";
    optionJson["cupsOptions"] = cupsOptionsJson;
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), true);
}

/**
* @tc.name: RefreshThirdDriverPrinter_CustomDriverPrinter_SetIdle
* @tc.desc: Custom driver printers are set to PRINTER_STATUS_IDLE during refresh
* @tc.type: FUNC
* @tc.require: Printer with prefix "fwk.driver.printer.driver" should have status updated
*/
HWTEST_F(PrintServiceAbilityTest, RefreshThirdDriverPrinter_CustomDriverPrinter_SetIdle, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "fwk.driver.printer.driver.com.example:TestPrinter";
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("TestPrinter");
    service->printSystemData_.InsertAddedPrinter(printerId, printerInfo);
    service->RefreshThirdDriverPrinter();
}

/**
* @tc.name: RefreshThirdDriverPrinter_RegularPrinter_NoChange
* @tc.desc: Regular (non-custom-driver) printers are not affected by RefreshThirdDriverPrinter
* @tc.type: FUNC
* @tc.require: Printers without custom driver prefix should be skipped
*/
HWTEST_F(PrintServiceAbilityTest, RefreshThirdDriverPrinter_RegularPrinter_NoChange, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string regularId = "com.huawei.hmos.spooler:SomePrinter";
    PrinterInfo regularInfo;
    regularInfo.SetPrinterId(regularId);
    regularInfo.SetPrinterName("SomePrinter");
    service->printSystemData_.InsertAddedPrinter(regularId, regularInfo);
    service->RefreshThirdDriverPrinter();
}

/**
* @tc.name: AddPrinterByPrinterDriver_NameTooLong_InvalidParameter
* @tc.desc: Printer name exceeding MAX_DRIVER_PRINTER_NAME_LENGTH returns E_PRINT_INVALID_PARAMETER
* @tc.type: FUNC
* @tc.require: Input validation: name length must not exceed MAX_DRIVER_PRINTER_NAME_LENGTH
*/
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_NameTooLong_InvalidParameter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string longName(MAX_DRIVER_PRINTER_NAME_LENGTH + 1, 'A');
    int32_t ret = service->AddPrinterByPrinterDriver(
        longName, "ipp://192.168.1.1:631/ipp/print", "", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_InvalidNameChar_InvalidParameter
 * @tc.desc: Printer name with invalid characters returns E_PRINT_INVALID_PARAMETER
 * @tc.type: FUNC
 * @tc.require: Input validation: name must not contain /, \\, ?, etc.
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_InvalidNameChar_InvalidParameter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    int32_t ret = service->AddPrinterByPrinterDriver(
        "test/printer", "ipp://192.168.1.1:631/ipp/print", "", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_UriTooLong_InvalidParameter
 * @tc.desc: URI exceeding HTTP_MAX_URI returns E_PRINT_INVALID_PARAMETER
 * @tc.type: FUNC
 * @tc.require: Input validation: uri length must not exceed HTTP_MAX_URI
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_UriTooLong_InvalidParameter, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string longUri(1025, 'a');
    int32_t ret = service->AddPrinterByPrinterDriver(
        "TestPrinter", longUri, "", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, GetPpdInfoFromPpdName_BsuniPpd_Test, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);
    
    std::string ppdName = BSUNI_PPD_NAME;
    PpdInfo ppdInfo = service->GetPpdInfoFromPpdName(ppdName);
    
    EXPECT_EQ(ppdInfo.GetPpdName(), BSUNI_PPD_NAME);
    EXPECT_EQ(ppdInfo.GetManufacturer(), "Generic");
    EXPECT_EQ(ppdInfo.GetNickName(), "System Default Driver");
}

HWTEST_F(PrintServiceAbilityTest, FillCustomOptionsToJson_OptNotSet_SkipsOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterUserPreferences userPrefs;
    userPrefs.SetCustomOption("UnsetCustomPin", "");
    SecureBlob value;
    std::string valueStr = "test";
    value.SetData(reinterpret_cast<const uint8_t*>(valueStr.c_str()), valueStr.size());
    userPrefs.SetCustomOption("SetCustomPin", CUSTOM_OPTION_CHOICE, value);
    Json::Value opsJson;
    opsJson["existingKey"] = "existingValue";

    service->FillCustomOptionsToJson(userPrefs, opsJson);
    EXPECT_TRUE(opsJson.isMember("existingKey"));
    EXPECT_FALSE(opsJson.isMember("UnsetCustomPin"));
    EXPECT_TRUE(opsJson.isMember("SetCustomPin"));
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrinterOption_PrinterNotFound_NoOp, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();

    service->printSystemData_.UpdatePrinterOption("non_existent_printer_id", "some_option");

    EXPECT_EQ(service->printSystemData_.addedPrinterMap_.Find("non_existent_printer_id"), nullptr);
}

HWTEST_F(PrintServiceAbilityTest, DecryptAndFillCustomOptionsToJson_NullHksAdapter_SkipsAll, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->hksAdapter_ = nullptr;
    PrinterUserPreferences userPrefs;
    SecureBlob value;
    std::string valueStr = "dGVzdA==";
    value.SetData(reinterpret_cast<const uint8_t*>(valueStr.c_str()), valueStr.size());
    userPrefs.SetCustomOption("CustomPin", CUSTOM_OPTION_CHOICE, value);
    Json::Value opsJson;
    opsJson["existingKey"] = "existingValue";

    service->DecryptAndFillCustomOptionsToJson(userPrefs, opsJson);
    EXPECT_TRUE(opsJson.isMember("existingKey"));
    EXPECT_TRUE(opsJson.isMember("CustomPin"));
    EXPECT_EQ(opsJson["CustomPin"]["choice"].asString(), CUSTOM_OPTION_CHOICE);
    EXPECT_EQ(opsJson["CustomPin"]["value"].asString(), "");
}

HWTEST_F(PrintServiceAbilityTest, DecryptAndFillCustomOptionsToJson_Base64DecodeFail_SkipsOption, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockAdapter = std::make_shared<MockHksAdapter>();
    EXPECT_CALL(*mockAdapter, EVP_DecodeBlockWrapper(_, _, _)).WillOnce(Return(-1));
    service->hksAdapter_ = mockAdapter;
    PrinterUserPreferences userPrefs;
    SecureBlob value;
    std::string valueStr = "invalidBase64!!!";
    value.SetData(reinterpret_cast<const uint8_t*>(valueStr.c_str()), valueStr.size());
    userPrefs.SetCustomOption("CustomPin", CUSTOM_OPTION_CHOICE, value);
    Json::Value opsJson;

    service->DecryptAndFillCustomOptionsToJson(userPrefs, opsJson);
    EXPECT_TRUE(opsJson.isMember("CustomPin"));
    EXPECT_EQ(opsJson["CustomPin"]["choice"].asString(), CUSTOM_OPTION_CHOICE);
    EXPECT_EQ(opsJson["CustomPin"]["value"].asString(), "");
}

HWTEST_F(PrintServiceAbilityTest, DecryptAndFillCustomOptionsToJson_DecryptSuccess_WritesPlaintext, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->currentUserId_ = 100;
    auto mockAdapter = std::make_shared<MockHksAdapter>();
    EXPECT_CALL(*mockAdapter, EVP_DecodeBlockWrapper(_, _, _)).WillOnce(Return(4));
    EXPECT_CALL(*mockAdapter, Base64Decode(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*mockAdapter, HksKeyExist(_, _)).WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter, HksDecrypt(_, _, _, _)).WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter, HksFreeParamSet(_)).WillRepeatedly(Return());
    service->hksAdapter_ = mockAdapter;
    PrinterUserPreferences userPrefs;
    SecureBlob value;
    std::string valueStr = "dGVzdA==";
    value.SetData(reinterpret_cast<const uint8_t*>(valueStr.c_str()), valueStr.size());
    userPrefs.SetCustomOption("CustomPin", CUSTOM_OPTION_CHOICE, value);
    Json::Value opsJson;

    service->DecryptAndFillCustomOptionsToJson(userPrefs, opsJson);
    EXPECT_TRUE(opsJson.isMember("CustomPin"));
}

}  // namespace Print
}  // namespace OHOS
