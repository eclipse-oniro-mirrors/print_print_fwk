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
#include "iprint_service.h"
#include "print_data_repository.h"
#include "print_json_util.h"
#include <filesystem>

namespace OHOS {
namespace Print {

static std::string GetTestPpdDir()
{
    return "/data/service/el1/public/print_service/cups/datadir/model";
}

static void CreateTestPpdFile(const std::string &fileName, const std::string &content)
{
    std::string dir = GetTestPpdDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    std::string filePath = dir + "/" + fileName;
    std::ofstream ofs(filePath);
    ofs << content;
    ofs.close();
    PrintServiceAbilityTest::RegisterTempFileForCleanup(filePath);
}

static void RemoveTestPpdFile(const std::string &fileName)
{
    std::string filePath = GetTestPpdDir() + "/" + fileName;
    std::error_code ec;
    std::filesystem::remove(filePath, ec);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0035_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerUri = "testPrinterUri";
    std::string printerName = "testPrinterName";
    std::string printerMake = "testPrinterMake";
    EXPECT_EQ(service->AddPrinterToCups(printerUri, printerName, printerMake), E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0109_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string printerName = "pixlab_0759";
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NONE);
    std::string printerId = "1234";
    std::string jobId = "job1234";
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName(printerName);
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId, printerInfo);
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NONE);
    service->printerJobMap_[printerId].clear();
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_AddRawPrinter_ServerFailure, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;

    PrinterInfo info;
    info.SetPrinterId("test_printer_id");
    info.SetUri("test_printer_uri");
    info.SetPrinterName("test_printer_name");
    int32_t ret = service->AddRawPrinter(info);
    EXPECT_EQ(ret, E_PRINT_SERVER_FAILURE);
}

HWTEST_F(PrintServiceAbilityTest, RefreshPrinterInfoByPpd_InsertAddedPrinter_CapabilityUnchanged, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId1 = "printerId1";
    std::string printerId2 = "printerId2";
    PrinterInfo info;
    info.SetPrinterId(printerId2);
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId2, info);
    service->RefreshPrinterInfoByPpd();
    EXPECT_EQ(info.HasCapability(), false);
}

HWTEST_F(PrintServiceAbilityTest, QueryAllPpdsTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::vector<PpdInfo> ppds;
    EXPECT_EQ(service->QueryAllPrinterPpds(ppds), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, CheckPreferencesConflicts_InvalidPpdName, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    std::string printerId = GetDefaultPrinterId();
    PrinterPreferences printerPreference;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(_, _))
        .WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(*service, QueryPPDInformation(_, _))
        .WillOnce(Return(false))
        .WillOnce([](const std::string &makeModel, std::string &ppdName) {
            ppdName = "TestNone.ppd";
            return true;
        });

    int32_t ret = service->CheckPreferencesConflicts(
        printerId, PRINT_PARAM_TYPE_PAGE_SIZE, printerPreference, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    ret = service->CheckPreferencesConflicts(
        printerId, PRINT_PARAM_TYPE_PAGE_SIZE, printerPreference, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_FILE_IO);
#endif
}

HWTEST_F(PrintServiceAbilityTest, CheckPrintJobConflicts_NoPermission, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    PrintJob testPrinterJob;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    testPrinterJob.SetPrinterId(GetInvalidPrinterId());
    int32_t ret = service->CheckPrintJobConflicts(
        PRINT_PARAM_TYPE_PAGE_SIZE, testPrinterJob, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
#endif
}

HWTEST_F(PrintServiceAbilityTest, CheckPrintJobConflicts_InvalidPrinterId, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    PrintJob testPrinterJob;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);

    testPrinterJob.SetPrinterId(GetInvalidPrinterId());
    int32_t ret = service->CheckPrintJobConflicts(
        PRINT_PARAM_TYPE_PAGE_SIZE, testPrinterJob, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_TRUE(conflictingOptions.empty());
#endif
}

HWTEST_F(PrintServiceAbilityTest, CheckPrintJobConflicts_InvalidPpdName, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    PrintJob testPrinterJob;
    std::vector<std::string> conflictingOptions;
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);

    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(_, _))
        .WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_CALL(*service, QueryPPDInformation(_, _))
        .WillOnce(Return(false))
        .WillOnce([](const std::string &makeModel, std::string &ppdName) {
            ppdName = "TestNone.ppd";
            return true;
        });

    int32_t ret = service->CheckPrintJobConflicts(
        PRINT_PARAM_TYPE_PAGE_SIZE, testPrinterJob, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
    ret = service->CheckPrintJobConflicts(
        PRINT_PARAM_TYPE_PAGE_SIZE, testPrinterJob, conflictingOptions);
    EXPECT_NE(ret, E_PRINT_NONE);
#endif
}

HWTEST_F(PrintServiceAbilityTest, UpdateBsuniPrinterAdvanceOptions_NoCupsOptions_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    optionJson["key"] = "value";
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest, UpdateBsuniPrinterAdvanceOptions_CupsOptionsFormatError_ReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterCapability printerCaps;
    Json::Value optionJson;
    optionJson["cupsOptions"] = "value";
    printerCaps.SetOption(PrintJsonUtil::WriteStringUTF8(optionJson));
    printerInfo->SetCapability(printerCaps);
    EXPECT_EQ(service->UpdateBsuniPrinterAdvanceOptions(printerInfo), false);
}

HWTEST_F(PrintServiceAbilityTest, StopCupsd_EnterprisedEnable_EnterpriseSpace, TestSize.Level1)
{
#ifdef ENTERPRISE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, IS_ENTERPRISE_ENABLE);
    service->isEnterprise_ = true;
    service->OnStart();
    service->StopCupsService();

    const int bufferSize = 96;
    char value[bufferSize] = {0};
    GetParameter(CUPSD_ENTERPRISE_CONTROL_PARAM.c_str(), "", value, bufferSize - 1);
    EXPECT_STREQ(value, "false");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
#endif  // ENTERPRISE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, StopCupsd_EnterprisedEnable_PersonalSpace, TestSize.Level1)
{
#ifdef ENTERPRISE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, IS_ENTERPRISE_ENABLE);
    service->isEnterprise_ = false;
    service->OnStart();
    service->StopCupsService();

    const int bufferSize = 96;
    char value[bufferSize] = {0};
    GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize - 1);
    EXPECT_STREQ(value, "false");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
#endif  // ENTERPRISE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, StopCupsd_EnterprisedDisable, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->OnStart();
    service->StopCupsService();

    const int bufferSize = 96;
    char value[bufferSize] = {0};
    GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize - 1);
    EXPECT_STREQ(value, "false");
}

HWTEST_F(PrintServiceAbilityTest, UpdatePpdForPreinstalledDriverPrinter_ShouldProcessEach, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId1 = "test_printer_id_1";
    auto printerInfo1 = std::make_shared<PrinterInfo>();
    printerInfo1->SetPrinterId(printerId1);
    printerInfo1->SetPrinterName("Printer1");
    printerInfo1->SetPrinterMake("");
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId1, printerInfo1);
    std::string printerId2 = "test_printer_id_2";
    auto printerInfo2 = std::make_shared<PrinterInfo>();
    printerInfo2->SetPrinterId(printerId2);
    printerInfo2->SetPrinterName(CUSTOM_PRINTER_NAME);
    printerInfo2->SetPrinterMake("Make2");
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId2, printerInfo2);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(Return(true));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = PrintDataRepository::GetInstance().QueryAddedPrinterIdList();
    EXPECT_EQ(printerIdList.size(), 2);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePpdForPreinstalledDriverPrinter_QueryPpdFailed_ShouldContinue, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer_id_1";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName(CUSTOM_PRINTER_NAME);
    printerInfo->SetPrinterMake("Make1");
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(Return(false));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = PrintDataRepository::GetInstance().QueryAddedPrinterIdList();
    EXPECT_EQ(printerIdList.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePpdForPreinstalledDriverPrinter_HashCodeSame_ShouldContinue, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer_id_1";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName(CUSTOM_PRINTER_NAME);
    printerInfo->SetPrinterMake("Make1");
    printerInfo->SetPpdHashCode("");
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(DoAll(SetArgReferee<1>("ppd1"), Return(true)));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = PrintDataRepository::GetInstance().QueryAddedPrinterIdList();
    EXPECT_EQ(printerIdList.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, UpdatePpdForPreinstalledDriverPrinter_HashCode_Notequal, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer_id_1";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName(CUSTOM_PRINTER_NAME);
    printerInfo->SetPrinterMake("Make1");
    printerInfo->SetPpdHashCode("notEqualHash");
    PrintDataRepository::GetInstance().InsertAddedPrinter(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(DoAll(SetArgReferee<1>("ppd1"), Return(true)));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = PrintDataRepository::GetInstance().QueryAddedPrinterIdList();
    EXPECT_EQ(printerIdList.size(), 1);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToCupsWithPpd_PrinterInfoNull_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    std::string printerId = "printer_001";
    std::string ppdName = "test_ppd";
    std::string ppdData = "test_ppd_data";
    bool result = service->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToCupsWithPpd_DoAddPrinterToCupsFail_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalVendorName = "vendor_001";
    std::string printerId = "printer_001";
    std::string globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    std::string ppdName = "test_ppd";
    std::string ppdData = "test_ppd_data";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName("test_printer");
    // No URI set: DoAddPrinterToCups fails at HasUri() check
    printerInfo->SetPrinterMake("HP");
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
printerInfo->SetPrinterId(globalPrinterId);
    PrintDataRepository::GetInstance().AddIpPrinterToList(printerInfo);
    bool result = service->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, AddIpPrinterToCupsWithPpd_WhenValidPrinterInfo_ShouldReturnTrue, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string globalVendorName = "vendor_001";
    std::string printerId = "printer_001";
    std::string globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    std::string ppdName = "test_ppd";
    std::string ppdData = "test_ppd_data";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName("test_printer");
    printerInfo->SetUri("ipp://192.168.1.1:631/printers/printer1");
    printerInfo->SetPrinterMake("HP");
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
    PrinterCapability capability;
    printerInfo->SetCapability(capability);
printerInfo->SetPrinterId(globalPrinterId);
    PrintDataRepository::GetInstance().AddIpPrinterToList(printerInfo);
    EXPECT_CALL(*service, DoAddPrinterToCupsEnable(_, _, _, _, _)).WillOnce(Return(true));
    bool result = service->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
    EXPECT_EQ(result, true);
}

/**
* @tc.desc: Test UpdateSinglePrinterInfo when printer has make and PPD query succeeds
* @tc.type: FUNC
* @tc.require: Printer capability should be updated from PPD
*/
HWTEST_F(PrintServiceAbilityTest, UpdateSinglePrinterInfo_HasPrinterMake_PpdQuerySuccess, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    
    EXPECT_CALL(*service, QueryPPDInformation(_, _))
        .WillOnce([](const std::string &makeModel, std::string &ppdName) {
            ppdName = "Test.ppd";
            return true;
        });
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterName("TestPrinter");
    info->SetPrinterId(GetDefaultPrinterId());
    info->SetPrinterMake("TestMake");
    PrinterCapability caps;
    Json::Value opsJson;
    opsJson["key"] = "value";
    caps.SetOption(PrintJsonUtil::WriteString(opsJson));
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSizeList.push_back(pageSize);
    caps.SetSupportedPageSize(pageSizeList);
    info->SetCapability(caps);
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);
    bool result = service->UpdateSinglePrinterInfo(*info, DEFAULT_EXTENSION_ID);
    EXPECT_TRUE(result);
}

/**
* @tc.name: UpdateSinglePrinterInfo_HasPrinterMake_PpdReturnEmpty
* @tc.desc: Test UpdateSinglePrinterInfo when printer has make and PPD is empty
* @tc.type: FUNC
* @tc.require: Printer capability should be updated from PPD
*/
HWTEST_F(PrintServiceAbilityTest, UpdateSinglePrinterInfo_HasPrinterMake_PpdReturnEmpty, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    
    EXPECT_CALL(*service, QueryPPDInformation(_, _))
        .WillOnce([](const std::string &makeModel, std::string &ppdName) {
            return true;
        });
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterName("TestPrinter");
    info->SetPrinterId(GetDefaultPrinterId());
    info->SetPrinterMake("TestMake");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);
    bool result = service->UpdateSinglePrinterInfo(*info, DEFAULT_EXTENSION_ID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_EmptyPpdName_Success
 * @tc.desc: Empty ppdName triggers default capability setup path
 * @tc.type: FUNC
 * @tc.require: Empty ppdName handling with capability initialization
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_EmptyPpdName_Success, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, DoAddPrinterToCupsEnable(_, _, _, _, _)).WillOnce(Return(true));
    EXPECT_CALL(*service, QueryPrinterCapabilityFromPPD(_, _, _)).WillOnce(Return(E_PRINT_NONE));
    int32_t ret = service->AddPrinterByPrinterDriver(
        "TestPrinter", "ipp://192.168.1.1:631/ipp/print", "", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_DefaultPpdName_Success
 * @tc.desc: ppdName equals DEFAULT_PPD_NAME triggers default capability setup
 * @tc.type: FUNC
 * @tc.require: DEFAULT_PPD_NAME handling with capability initialization
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_DefaultPpdName_Success, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, DoAddPrinterToCupsEnable(_, _, _, _, _)).WillOnce(Return(true));
    EXPECT_CALL(*service, QueryPrinterCapabilityFromPPD(_, _, _)).WillOnce(Return(E_PRINT_NONE));
    int32_t ret = service->AddPrinterByPrinterDriver(
        "TestPrinter", "ipp://192.168.1.1:631/ipp/print", DEFAULT_PPD_NAME, "", "com.example");
    EXPECT_EQ(ret, E_PRINT_NONE);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_InvalidPpdName_InvalidParameter
 * @tc.desc: Invalid ppdName (IsPpdNameValid returns false) returns E_PRINT_INVALID_PARAMETER
 * @tc.type: FUNC
 * @tc.require: PPD name validation before adding printer
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_InvalidPpdName_InvalidParameter, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, IsPpdNameValid(_)).WillOnce(Return(false));
    int32_t ret = service->AddPrinterByPrinterDriver(
        "TestPrinter", "ipp://192.168.1.1:631/ipp/print", "invalid.ppd", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

/**
 * @tc.name: AddPrinterByPrinterDriver_CupsFailed_GenericFailure
 * @tc.desc: DoAddPrinterToCupsEnable returns false returns E_PRINT_GENERIC_FAILURE
 * @tc.type: FUNC
 * @tc.require: CUPS add printer failure handling
 */
HWTEST_F(PrintServiceAbilityTest, AddPrinterByPrinterDriver_CupsFailed_GenericFailure, TestSize.Level1)
{
    auto service = sptr<MockPrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    EXPECT_CALL(*service, IsPpdNameValid(_)).WillOnce(Return(true));
    EXPECT_CALL(*service, DoAddPrinterToCupsEnable(_, _, _, _, _)).WillOnce(Return(false));
    int32_t ret = service->AddPrinterByPrinterDriver(
        "TestPrinter", "ipp://192.168.1.1:631/ipp/print", "valid.ppd", "", "com.example");
    EXPECT_EQ(ret, E_PRINT_GENERIC_FAILURE);
}


// ===== SA layer: GetPpdFilePathByPrinterId / GetPrinterLocalizedStrings branches =====
namespace {
const std::string UT_PPD_MINIMAL =
    "*PPD-Adobe: \"4.3\"\n*FileVersion: \"1.0\"\n*LanguageEncoding: ISOLatin1\n"
    "*LanguageLevel: \"2\"\n*Manufacturer: \"T\"\n*ModelName: \"T\"\n*NickName: \"T\"\n"
    "*cupsLanguages: \"en zh_CN\"\n";
const std::string UT_PPD_WITH_ZH = UT_PPD_MINIMAL +
    "*OpenUI MediaType: PickOne\n*OrderDependency: 50 AnySetup MediaType\n"
    "*DefaultMediaType: Plain\n*MediaType Plain/Plain Paper: \"<<MediaType(Plain)>>setpagedevice\"\n"
    "*zh_CN.MediaType Plain/\u666e\u901a\u7eb8: \"<<MediaType(Plain)>>setpagedevice\"\n*CloseUI: MediaType\n";

PrinterInfo MakeUtPrinter(const std::string &id, const std::string &name, const std::string &ppdName)
{
    PrinterInfo info;
    info.SetPrinterId(id);
    info.SetPrinterName(name);
    info.SetUri("ipp://127.0.0.1/printers/" + name);
    PpdInfo drv;
    drv.SetPpdName(ppdName);
    info.SetSelectedDriver(drv);
    PrinterCapability caps;
    caps.SetOption("{\"make\":\"T\"}");
    info.SetCapability(caps);
    return info;
}
} // namespace

HWTEST_F(PrintServiceAbilityTest, GetPpdFilePathByPrinterId_UnknownId_ReturnsInvalidPrinter, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    std::string resolvedPath;
    EXPECT_EQ(PrintServiceAbility::GetInstance()->GetPpdFilePathByPrinterId("", resolvedPath),
        E_PRINT_INVALID_PRINTER);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPpdFilePathByPrinterId_ManualDriverHit_ReturnsNone, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    const std::string ppdName = "ut_manual_" + std::to_string(getpid()) + ".ppd";
    CreateTestPpdFile(ppdName, UT_PPD_MINIMAL);
    const std::string id = "ut_hit_" + std::to_string(getpid());
    PrintDataRepository::GetInstance().InsertAddedPrinter(id, MakeUtPrinter(id, "Ut Hit", ppdName));
    std::string resolvedPath;
    EXPECT_EQ(PrintServiceAbility::GetInstance()->GetPpdFilePathByPrinterId(id, resolvedPath), E_PRINT_NONE);
    EXPECT_NE(resolvedPath.find(ppdName), std::string::npos);
    PrintDataRepository::GetInstance().DeleteAddedPrinter(id, "Ut Hit");
    RemoveTestPpdFile(ppdName);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPpdFilePathByPrinterId_TraversalNameAndQueueMiss_ReturnsInvalid, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    const std::string id = "ut_trav_" + std::to_string(getpid());
    PrintDataRepository::GetInstance().InsertAddedPrinter(id, MakeUtPrinter(id, "Ut Trav", "../evil.ppd"));
    std::string resolvedPath;
    EXPECT_EQ(PrintServiceAbility::GetInstance()->GetPpdFilePathByPrinterId(id, resolvedPath),
        E_PRINT_INVALID_PRINTER);
    PrintDataRepository::GetInstance().DeleteAddedPrinter(id, "Ut Trav");
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPpdFilePathByPrinterId_AutoDriverQueueHit_ReturnsNone, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    const std::string id = "ut_auto_" + std::to_string(getpid());
    const std::string pname = "Ut Auto " + std::to_string(getpid());
    PrintDataRepository::GetInstance().InsertAddedPrinter(id, MakeUtPrinter(id, pname, PPD_NAME_AUTO));
    std::string queueDir = DelayedSingleton<PrintCupsClient>::GetInstance()->GetCurCupsRootDir() + "/ppd";
    std::string queuePath = queueDir + "/" + PrintUtil::StandardizePrinterName(pname) + ".ppd";
    std::error_code ec;
    std::filesystem::create_directories(queueDir, ec);
    { std::ofstream ofs(queuePath); ofs << UT_PPD_MINIMAL; }
    std::string resolvedPath;
    EXPECT_EQ(PrintServiceAbility::GetInstance()->GetPpdFilePathByPrinterId(id, resolvedPath), E_PRINT_NONE);
    unlink(queuePath.c_str());
    PrintDataRepository::GetInstance().DeleteAddedPrinter(id, pname);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterLocalizedStrings_PermissionDenied_ReturnsNoPermission, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(false));
    service->SetHelper(mockHelper);
    std::string resultJson = "keep";
    int32_t ret = static_cast<IPrintService &>(*service)
        .GetPrinterLocalizedStrings("any", "zh_CN", resultJson);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
    EXPECT_EQ(resultJson, "keep");   // output untouched on failure
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterLocalizedStrings_InvalidLanguageFormat_Err401, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    std::string resultJson;
    int32_t ret = static_cast<IPrintService &>(*service)
        .GetPrinterLocalizedStrings("any", "1x", resultJson);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterLocalizedStrings_Bcp47Hit_Translation, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    // BCP47 full form is normalized to zh_CN at both SA and library entries (idempotent)
    const std::string ppdName = "ut_loc_" + std::to_string(getpid()) + ".ppd";
    CreateTestPpdFile(ppdName, UT_PPD_WITH_ZH);
    const std::string id = "ut_loc_" + std::to_string(getpid());
    PrintDataRepository::GetInstance().InsertAddedPrinter(id, MakeUtPrinter(id, "Ut Loc", ppdName));
    // SA 入口 ManualStart 可能触发 OnStart 从 spool 重载并清洗内存表：先落盘再调用
    PrintDataRepository::GetInstance().SavePrinterFile(id);
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    std::string resultJson;
    int32_t ret = static_cast<IPrintService &>(*service)
        .GetPrinterLocalizedStrings(id, "zh-Hans-CN", resultJson);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_NE(resultJson.find("\u666e\u901a\u7eb8"), std::string::npos);   // 普通纸 (UTF8 raw output)
    PrintDataRepository::GetInstance().DeleteAddedPrinter(id, "Ut Loc");
    RemoveTestPpdFile(ppdName);
#endif
}

HWTEST_F(PrintServiceAbilityTest, GetPrinterLocalizedStrings_NoTranslation_ResolvesEmpty, TestSize.Level1)
{
#ifdef CUPS_ENABLE
    const std::string ppdName = "ut_notrans_" + std::to_string(getpid()) + ".ppd";
    const std::string minimal =
        "*PPD-Adobe: \"4.3\"\n*cupsLanguages: \"en zh_CN\"\n*ModelName: \"T\"\n*NickName: \"T\"\n";
    CreateTestPpdFile(ppdName, minimal);
    const std::string id = "ut_notrans_" + std::to_string(getpid());
    PrintDataRepository::GetInstance().InsertAddedPrinter(id, MakeUtPrinter(id, "Ut NoTrans", ppdName));
    PrintDataRepository::GetInstance().SavePrinterFile(id);
    auto service = sptr<PrintServiceAbility>::MakeSptr(PRINT_SERVICE_ID, true);
    ASSERT_NE(service, nullptr);
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    std::string resultJson = "keep";
    int32_t ret = static_cast<IPrintService &>(*service)
        .GetPrinterLocalizedStrings(id, "zh_CN", resultJson);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_TRUE(resultJson.empty());   // 无任何译文：命中但 resolve 空串
    PrintDataRepository::GetInstance().DeleteAddedPrinter(id, "Ut NoTrans");
    RemoveTestPpdFile(ppdName);
#endif
}
}  // namespace Print
}  // namespace OHOS
