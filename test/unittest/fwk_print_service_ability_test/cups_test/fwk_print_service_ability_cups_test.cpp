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

static std::string CreateIppRawDataDirForAbilityTest()
{
    std::string dirPath = PRINTER_SERVICE_IPP_RAW_DATA_PATH;
    std::filesystem::path dir(dirPath);
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || ec) {
        std::filesystem::create_directories(dir, ec);
    }
    return dirPath;
}

static void CleanupIppRawDataDirForAbilityTest()
{
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(PRINTER_SERVICE_IPP_RAW_DATA_PATH, ec)) {
        if (entry.is_regular_file()) {
            std::filesystem::remove(entry.path(), ec);
        }
    }
}

static void CreateFileInIppDirForAbilityTest(const std::string &fileName)
{
    std::string filePath = PRINTER_SERVICE_IPP_RAW_DATA_PATH + "/" + fileName;
    std::ofstream ofs(filePath);
    ofs << "test_data";
    ofs.close();
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
    std::string printerName = "pixlab_0759";
    EXPECT_EQ(service->DeletePrinterFromCups(printerName), E_PRINT_NONE);
    std::string printerId = "1234";
    std::string jobId = "job1234";
    service->printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName(printerName);
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
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
    service->printSystemData_.addedPrinterMap_.Insert(printerId1, nullptr);
    service->printSystemData_.addedPrinterMap_.Insert(printerId2, info);
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
    // CUPS conflict check error is now swallowed to prioritize basic parameter modification
    EXPECT_EQ(ret, E_PRINT_NONE);
#endif
}

/**
 * @tc.name: CheckPreferencesConflicts_CupsCheckError
 * @tc.desc: GetPpdNameByPrinterId succeeds but CUPS conflict check returns error, expect E_PRINT_NONE
 * @tc.type: FUNC
 * @tc.require: Conflict check errors should be swallowed to ensure basic parameter modification works
 */
HWTEST_F(PrintServiceAbilityTest, CheckPreferencesConflicts_CupsCheckError, TestSize.Level1)
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
        .WillRepeatedly([](const std::string &makeModel, std::string &ppdName) {
            ppdName = "NonExistent.ppd";
            return true;
        });

    // GetPpdNameByPrinterId succeeds, but CUPS CheckPreferencesConflicts fails with non-existent PPD.
    // New behavior: error is swallowed, returns E_PRINT_NONE to ensure basic parameter modification.
    int32_t ret = service->CheckPreferencesConflicts(
        printerId, PRINT_PARAM_TYPE_PAGE_SIZE, printerPreference, conflictingOptions);
    EXPECT_EQ(ret, E_PRINT_NONE);
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
    service->printSystemData_.GetAddedPrinterMap().Insert(printerId1, printerInfo1);
    std::string printerId2 = "test_printer_id_2";
    auto printerInfo2 = std::make_shared<PrinterInfo>();
    printerInfo2->SetPrinterId(printerId2);
    printerInfo2->SetPrinterName(CUSTOM_PRINTER_NAME);
    printerInfo2->SetPrinterMake("Make2");
    service->printSystemData_.GetAddedPrinterMap().Insert(printerId2, printerInfo2);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(Return(true));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = service->printSystemData_.QueryAddedPrinterIdList();
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
    service->printSystemData_.GetAddedPrinterMap().Insert(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(Return(false));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = service->printSystemData_.QueryAddedPrinterIdList();
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
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(DoAll(SetArgReferee<1>("ppd1"), Return(true)));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = service->printSystemData_.QueryAddedPrinterIdList();
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
    service->printSystemData_.addedPrinterMap_.Insert(printerId, printerInfo);
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).WillOnce(DoAll(SetArgReferee<1>("ppd1"), Return(true)));
    service->UpdatePpdForPreinstalledDriverPrinter();
    std::vector<std::string> printerIdList = service->printSystemData_.QueryAddedPrinterIdList();
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
    printerInfo->SetPrinterMake("HP");
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
    service->printSystemData_.connectingIpPrinterInfoList_[globalPrinterId] = printerInfo;
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
    service->printSystemData_.connectingIpPrinterInfoList_[globalPrinterId] = printerInfo;
    EXPECT_CALL(*service, DoAddPrinterToCupsEnable(_, _, _, _, _)).WillOnce(Return(true));
    bool result = service->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdName, ppdData);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, IsPrinterPpdUpdateRequired_WhenPrinterNotFound_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string standardPrinterName = "test_printer";
    std::string ppdHashCode = "hash_123456";
    bool result = service->IsPrinterPpdUpdateRequired(standardPrinterName, ppdHashCode);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, IsPrinterPpdUpdateRequired_WhenHashCodeSame_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "printer_001";
    std::string printerName = "test_printer";
    std::string standardPrinterName = PrintUtil::StandardizePrinterName(printerName);
    std::string ppdHashCode = "hash_123456";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName(printerName);
    printerInfo->SetPpdHashCode(ppdHashCode);
    service->printSystemData_.GetAddedPrinterMap().Insert(printerId, printerInfo);
    bool result = service->IsPrinterPpdUpdateRequired(standardPrinterName, ppdHashCode);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, IsPrinterPpdUpdateRequired_WhenHashCodeDifferent_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string printerId = "printer_001";
    std::string printerName = "test_printer";
    std::string standardPrinterName = PrintUtil::StandardizePrinterName(printerName);
    std::string oldPpdHashCode = "hash_123456";
    std::string newPpdHashCode = "hash_789012";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(printerId);
    printerInfo->SetPrinterName(printerName);
    printerInfo->SetPpdHashCode(oldPpdHashCode);
    service->printSystemData_.GetAddedPrinterMap().Insert(printerId, printerInfo);
    bool result = service->IsPrinterPpdUpdateRequired(standardPrinterName, newPpdHashCode);
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
    service->printSystemData_.AddPrinterToDiscovery(info);
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
    service->printSystemData_.AddPrinterToDiscovery(info);
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

HWTEST_F(PrintServiceAbilityTest, GetPpdInfoFromPpdName_DefaultPpd_Test, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);
    
    std::string ppdName = DEFAULT_PPD_NAME;
    PpdInfo ppdInfo = service->GetPpdInfoFromPpdName(ppdName);
    
    EXPECT_EQ(ppdInfo.GetPpdName(), DEFAULT_PPD_NAME);
    EXPECT_EQ(ppdInfo.GetManufacturer(), "Generic");
    EXPECT_EQ(ppdInfo.GetNickName(), "IPP Everywhere");
}

HWTEST_F(PrintServiceAbilityTest, GetPpdInfoFromPpdName_UnknownPpd_Test, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    ASSERT_NE(service, nullptr);
    
    std::string ppdName = "unknown.ppd";
    PpdInfo ppdInfo = service->GetPpdInfoFromPpdName(ppdName);
    
    EXPECT_EQ(ppdInfo.GetPpdName(), "unknown.ppd");
    EXPECT_EQ(ppdInfo.GetManufacturer(), "auto");
    EXPECT_EQ(ppdInfo.GetNickName(), "auto");
}

HWTEST_F(PrintServiceAbilityTest, UpdatePrinterInDiscovery_IppOverUsbPrinter_UsesDefaultPpdName, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    info.SetPrinterId("com.huawei.hmos.spooler:IPP-testPrinter");
    info.SetPrinterName("IPPOverUsbPrinter");
    info.SetPrinterMake("Custom Printer Model");
    info.SetUri("usb://serial=12345");
    EXPECT_EQ(service->UpdatePrinterInDiscovery(info), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, CheckAndUpdateIppRawData_HasIppRawDataFileTrue_ShouldUpdateTimestamp, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string originId = "fwk.driver:testPrinter";
    std::string vendorPrinterId = VendorManager::ExtractPrinterId(originId);
    CreateIppRawDataDirForAbilityTest();
    CreateFileInIppDirForAbilityTest(vendorPrinterId + "_1234567890");
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetOriginId(originId);
    EXPECT_TRUE(service->printSystemData_.HasIppRawDataFile(vendorPrinterId));
    service->CheckAndUpdateIppRawData(printerInfo);
    CleanupIppRawDataDirForAbilityTest();
}

HWTEST_F(PrintServiceAbilityTest,
    CheckAndUpdateIppRawData_HasIppRawDataFileFalse_ShouldQueryIppRawData, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    CleanupIppRawDataDirForAbilityTest();
    std::string originId = "fwk.driver:testPrinter";
    std::string vendorPrinterId = VendorManager::ExtractPrinterId(originId);
    EXPECT_FALSE(service->printSystemData_.HasIppRawDataFile(vendorPrinterId));
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetOriginId(originId);
    service->CheckAndUpdateIppRawData(printerInfo);
}

HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_ManualDriverSelection, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterMake("HP");

    PpdInfo ppdInfo;
    ppdInfo.SetPpdName("manual_ppd_name");
    printerInfo.SetSelectedDriver(ppdInfo);

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerInfo), Return(E_PRINT_NONE)));
    EXPECT_CALL(*service, IsPpdNameValid("manual_ppd_name")).WillOnce(Return(true));
    EXPECT_CALL(*service, QueryPPDInformation(_, _)).Times(0);

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(ppdName, "manual_ppd_name");
}

/**
 * @tc.name: GetPpdNameByPrinterId_ManualDriverInvalidPpdName
 * @tc.desc: Non-empty, non-"auto" ppdName that fails IsPpdNameValid falls through to auto selection
 * @tc.type: FUNC
 * @tc.require: Invalid manual PPD name should fall back to auto driver selection
 */
HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_ManualDriverInvalidPpdName, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterMake("HP");

    PpdInfo ppdInfo;
    ppdInfo.SetPpdName("stale_ppd_name");
    printerInfo.SetSelectedDriver(ppdInfo);

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerInfo), Return(E_PRINT_NONE)));
    EXPECT_CALL(*service, IsPpdNameValid("stale_ppd_name")).WillOnce(Return(false));
    EXPECT_CALL(*service, QueryPPDInformation("HP", _))
        .WillOnce(DoAll(SetArgReferee<1>("auto_ppd"), Return(true)));

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(ppdName, "auto_ppd");
}

HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_AutoDriverSelection, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterMake("HP");

    PpdInfo ppdInfo;
    ppdInfo.SetPpdName("auto");
    printerInfo.SetSelectedDriver(ppdInfo);

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerInfo), Return(E_PRINT_NONE)));

    EXPECT_CALL(*service, QueryPPDInformation("HP", _))
        .WillOnce(DoAll(SetArgReferee<1>("auto_ppd"), Return(true)));

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(ppdName, "auto_ppd");
}

HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_EmptyPpdName, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterMake("Canon");

    PpdInfo ppdInfo;
    ppdInfo.SetPpdName("");
    printerInfo.SetSelectedDriver(ppdInfo);

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerInfo), Return(E_PRINT_NONE)));

    EXPECT_CALL(*service, QueryPPDInformation("Canon", _))
        .WillOnce(DoAll(SetArgReferee<1>("canon_ppd"), Return(true)));

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_NONE);
    EXPECT_EQ(ppdName, "canon_ppd");
}

HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_QueryPPDInformationFailed, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterMake("Epson");

    PpdInfo ppdInfo;
    ppdInfo.SetPpdName("auto");
    printerInfo.SetSelectedDriver(ppdInfo);

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(DoAll(SetArgReferee<1>(printerInfo), Return(E_PRINT_NONE)));

    EXPECT_CALL(*service, QueryPPDInformation("Epson", _))
        .WillOnce(Return(false));

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
}

HWTEST_F(PrintServiceAbilityTest, GetPpdNameByPrinterId_QueryPrinterInfoFailed, TestSize.Level1)
{
    auto service = std::make_shared<MockPrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string printerId = "test_printer";
    std::string ppdName;

    EXPECT_CALL(*service, QueryPrinterInfoByPrinterId(printerId, _))
        .WillOnce(Return(E_PRINT_INVALID_PRINTER));

    EXPECT_CALL(*service, QueryPPDInformation(_, _)).Times(0);

    int32_t ret = service->GetPpdNameByPrinterId(printerId, ppdName);
    EXPECT_EQ(ret, E_PRINT_INVALID_PRINTER);
}

}  // namespace Print
}  // namespace OHOS
