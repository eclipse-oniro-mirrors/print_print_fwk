/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define private public
#include "print_cups_client.h"
#undef private
#include "print_constant.h"
#include "print_log.h"
#include "mock/mock_print_cups_wrapper.h"

using namespace testing;
using namespace testing::ext;
using json = nlohmann::json;

namespace OHOS {
namespace Print {
static const std::string PRINTER_STATE_NONE = "none";
static const std::string PRINTER_STATE_MEDIA_EMPTY = "media-empty";
static const std::string PRINTER_STATE_MEDIA_JAM = "media-jam";
static const std::string PRINTER_STATE_PAUSED = "paused";
static const std::string PRINTER_STATE_TONER_LOW = "toner-low";
static const std::string PRINTER_STATE_TONER_EMPTY = "toner-empty";
static const std::string PRINTER_STATE_DOOR_EMPTY = "door-open";
static const std::string PRINTER_STATE_MEDIA_NEEDED = "media-needed";
static const std::string PRINTER_STATE_MARKER_LOW = "marker-supply-low";
static const std::string PRINTER_STATE_MARKER_EMPTY = "marker-supply-empty";
static const std::string PRINTER_STATE_INK_EMPTY = "marker-ink-almost-empty";
static const std::string PRINTER_STATE_COVER_OPEN = "cover-open";
static const std::string PRINTER_STATE_OFFLINE = "offline";

using MockTestFunc = std::function<void(PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock)>;

class PrintCupsWrapperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void DoMockTest(MockTestFunc func);
};

void PrintCupsWrapperTest::SetUpTestCase(void)
{}

void PrintCupsWrapperTest::TearDownTestCase(void)
{}

void PrintCupsWrapperTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintCupsWrapperTest_%{public}d", ++testNo);
}

void PrintCupsWrapperTest::TearDown(void)
{}

void PrintCupsWrapperTest::DoMockTest(MockTestFunc func)
{
    if (func == nullptr) {
        PRINT_HILOGE("test func is null");
        return;
    }
    PrintCupsClient printCupsClient;
    if (printCupsClient.printAbility != nullptr) {
        delete printCupsClient.printAbility;
        printCupsClient.printAbility = nullptr;
    }
    auto mock = new (std::nothrow) MockPrintCupsWrapper();
    if (mock == nullptr) {
        PRINT_HILOGE("mock is null");
        return;
    }
    printCupsClient.printAbility = mock;
    func(printCupsClient, *mock);
}

/**
 * @tc.name: PrintCupsWrapperTest_0001
 * @tc.desc: QueryPrinterAttrList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0001, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    if (printCupsClient.printAbility != nullptr) {
        delete printCupsClient.printAbility;
        printCupsClient.printAbility = nullptr;
    }
    std::string printerName = "testPrinterName";
    std::string printUri;
    std::string printerId;
    std::vector<std::string> keyList;
    std::vector<std::string> valueList;
    EXPECT_EQ(printCupsClient.QueryPrinterAttrList(printerName, keyList, valueList), E_PRINT_SERVER_FAILURE);
    printCupsClient.QueryPPDInformation(printerId.c_str(), valueList);
    EXPECT_EQ(printCupsClient.DeleteCupsPrinter(printerName.c_str()), E_PRINT_SERVER_FAILURE);
    PrinterCapability printerCap;
    EXPECT_EQ(printCupsClient.QueryPrinterCapabilityByUri(printUri, printerId, printerCap), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(printCupsClient.SetDefaultPrinter(printerName.c_str()), E_PRINT_SERVER_FAILURE);
    printCupsClient.QueryJobState(nullptr, nullptr, nullptr);
}

/**
 * @tc.name: PrintCupsWrapperTest_0002
 * @tc.desc: QueryPrinterAttrList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0002, TestSize.Level1)
{
    MockTestFunc testFunc = [this](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(nullptr));
        std::string printerName = "testPrinterName";
        std::vector<std::string> keyList = {"key1", "key2"};
        std::vector<std::string> valueList;
        EXPECT_EQ(printCupsClient.QueryPrinterAttrList(printerName, keyList, valueList), E_PRINT_SERVER_FAILURE);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0003
 * @tc.desc: QueryPrinterAttrList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0003, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string printerName = "testPrinterName";
        std::vector<std::string> keyList = {"key1", "key2"};
        std::vector<std::string> valueList;
        EXPECT_EQ(printCupsClient.QueryPrinterAttrList(printerName, keyList, valueList), E_PRINT_NONE);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0010
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0010, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    if (printCupsClient.printAbility != nullptr) {
        delete printCupsClient.printAbility;
        printCupsClient.printAbility = nullptr;
    }
    std::string printerId = "testPrinterId";
    PrinterInfo info;
    EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: PrintCupsWrapperTest_0011
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0011, TestSize.Level1)
{
    MockTestFunc testFunc = [this](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(nullptr));
        std::string printerId = "testPrinterId";
        PrinterInfo info;
        EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_SERVER_FAILURE);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0012
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0012, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string printerId = "testPrinterId";
        PrinterInfo info;
        EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_NONE);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0013
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0013, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string printerId = "testPrinterId";
        PrinterInfo info;
        std::string option = "test option";
        info.SetOption(option);
        EXPECT_EQ(printCupsClient.QueryPrinterInfoByPrinterId(printerId, info), E_PRINT_INVALID_PARAMETER);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0014
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0014, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string printerId = "testPrinterId";
        PrinterInfo info;
        nlohmann::json option;
        option["printerName"] = "name";
        option["printerUri"] = "uri";
        info.SetOption(option.dump());
        printCupsClient.QueryPrinterInfoByPrinterId(printerId, info);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0015
 * @tc.desc: QueryPrinterInfoByPrinterId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0015, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).Times(1).WillOnce(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string printerId = "testPrinterId";
        PrinterInfo info;
        nlohmann::json option;
        option["printerName"] = "name";
        info.SetOption(option.dump());
        printCupsClient.QueryPrinterInfoByPrinterId(printerId, info);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0020
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0020, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    if (printCupsClient.printAbility != nullptr) {
        delete printCupsClient.printAbility;
        printCupsClient.printAbility = nullptr;
    }
    JobParameters jobParams;
    EXPECT_EQ(printCupsClient.CheckPrinterMakeModel(&jobParams), false);
    printCupsClient.DumpJobParameters(nullptr);
}

/**
 * @tc.name: PrintCupsWrapperTest_0021
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0021, TestSize.Level1)
{
    MockTestFunc testFunc = [this](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).WillRepeatedly(Return(nullptr));
        JobParameters jobParams;
        EXPECT_EQ(printCupsClient.CheckPrinterMakeModel(&jobParams), false);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0022
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0022, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).WillRepeatedly(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        JobParameters jobParams;
        EXPECT_EQ(printCupsClient.CheckPrinterMakeModel(&jobParams), false);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0030
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0030, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    if (printCupsClient.printAbility != nullptr) {
        delete printCupsClient.printAbility;
        printCupsClient.printAbility = nullptr;
    }
    std::string name = "testName";
    std::string uri = "testUri";
    std::string ppd = "testPpd";
    EXPECT_EQ(printCupsClient.IsPrinterExist(name.c_str(), uri.c_str(), ppd.c_str()), false);
}

/**
 * @tc.name: PrintCupsWrapperTest_0031
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0031, TestSize.Level1)
{
    MockTestFunc testFunc = [this](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).WillRepeatedly(Return(nullptr));
        std::string name = "testName";
        std::string uri = "testUri";
        std::string ppd = "testPpd";
        EXPECT_EQ(printCupsClient.IsPrinterExist(name.c_str(), uri.c_str(), ppd.c_str()), false);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0032
 * @tc.desc: CheckPrinterMakeModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0032, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    MockTestFunc testFunc = [this, &cupsDests](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).WillRepeatedly(Return(&cupsDests));
        EXPECT_CALL(mock, FreeDests(_, _)).WillRepeatedly(Return());
        std::string name = "testName";
        std::string uri = "testUri";
        std::string ppd = "testPpd";
        EXPECT_EQ(printCupsClient.IsPrinterExist(name.c_str(), uri.c_str(), ppd.c_str()), false);
    };
    DoMockTest(testFunc);
}

/**
 * @tc.name: PrintCupsWrapperTest_0080
 * @tc.desc: QueryPPDInformation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0080, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.InitCupsResources();
    EXPECT_EQ(ret, E_PRINT_NONE);
    std::vector<std::string> ppds;
    printCupsClient.QueryPPDInformation(nullptr, ppds);
    printCupsClient.ParsePPDInfo(nullptr, nullptr, nullptr, ppds);
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsWrapperTest_0081
 * @tc.desc: QueryPPDInformation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0081, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.InitCupsResources();
    EXPECT_EQ(ret, E_PRINT_NONE);
    std::string makeModel = "testmodel";
    std::vector<std::string> ppds;
    printCupsClient.QueryPPDInformation(makeModel.c_str(), ppds);
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsWrapperTest_0082
 * @tc.desc: ParsePPDInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0082, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    std::vector<std::string> ppds;
    ipp_t* response = ippNew();
    EXPECT_NE(response, nullptr);
    ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-location", nullptr, "en_us");
    ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_TEXT, "ppd-make-and-model", nullptr, "testmodel");
    ippAddString(response, IPP_TAG_PRINTER, IPP_TAG_NAME, "ppd-name", nullptr, "testppd");
    printCupsClient.ParsePPDInfo(response, nullptr, nullptr, ppds);
    printCupsClient.ParsePPDInfo(response, "testmodel", nullptr, ppds);
    printCupsClient.ParsePPDInfo(response, "testmodel", "testppd", ppds);
    ippDelete(response);
}

/**
 * @tc.name: PrintCupsWrapperTest_0083
 * @tc.desc: AddPrinterToCups
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0083, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    int32_t ret = printCupsClient.InitCupsResources();
    EXPECT_EQ(ret, E_PRINT_NONE);
    std::string uri = "testuri";
    std::string name = "testname";
    std::string makeModel = "testmodel";
    printCupsClient.AddPrinterToCups(uri, name, makeModel);
    printCupsClient.DeletePrinterFromCups(uri, name, makeModel);
    printCupsClient.DeleteCupsPrinter(name.c_str());
    printCupsClient.StopCupsdService();
}

/**
 * @tc.name: PrintCupsWrapperTest_0084
 * @tc.desc: GetBlockedSubstate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0084, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    JobStatus jobStatus = {0};
    constexpr size_t len = sizeof(jobStatus.printer_state_reasons);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_MEDIA_EMPTY.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_MEDIA_JAM.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_TONER_EMPTY.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_TONER_LOW.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_MARKER_EMPTY.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_INK_EMPTY.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_MARKER_LOW.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_DOOR_EMPTY.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
    strcpy_s(jobStatus.printer_state_reasons, len, PRINTER_STATE_COVER_OPEN.c_str());
    printCupsClient.GetBlockedSubstate(&jobStatus);
}

/**
 * @tc.name: PrintCupsWrapperTest_0085
 * @tc.desc: GetIpAddress
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0085, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    unsigned int num = 0x12345678;
    std::string ip = printCupsClient.GetIpAddress(num);
    EXPECT_STREQ(ip.c_str(), "18.52.86.120");
}

/**
 * @tc.name: PrintCupsWrapperTest_0086
 * @tc.desc: UpdateBorderlessJobParameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0086, TestSize.Level1)
{
    OHOS::Print::PrintCupsClient printCupsClient;
    nlohmann::json optionJson;
    JobParameters *jobParams = nullptr;
    printCupsClient.UpdateBorderlessJobParameter(optionJson, jobParams);
    jobParams = new JobParameters();
    printCupsClient.UpdateBorderlessJobParameter(optionJson, jobParams);
    optionJson["borderless"] = "false";
    printCupsClient.UpdateBorderlessJobParameter(optionJson, jobParams);
    optionJson["borderless"] = "true";
    printCupsClient.UpdateBorderlessJobParameter(optionJson, jobParams);
    optionJson["documentCategory"] = 1;
    printCupsClient.UpdateBorderlessJobParameter(optionJson, jobParams);
    delete jobParams;
}

/**
 * @tc.name: PrintCupsWrapperTest_0087
 * @tc.desc: GetNextJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0087, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    EXPECT_EQ(printCupsClient.GetNextJob(), nullptr);
    JobParameters *jobParams1 = new JobParameters();
    JobParameters *jobParams2 = new JobParameters();
    printCupsClient.jobQueue_.push_back(jobParams1);
    printCupsClient.jobQueue_.push_back(jobParams2);
    EXPECT_EQ(printCupsClient.GetNextJob(), jobParams1);
    EXPECT_EQ(printCupsClient.GetNextJob(), nullptr);
    delete jobParams1;
    delete jobParams2;
}

/**
 * @tc.name: PrintCupsWrapperTest_0088
 * @tc.desc: CopyDirectory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0088, TestSize.Level1)
{
    PrintCupsClient printCupsClient;
    std::string srcDir = "/system/bin/cups/";
    std::string dstDir1 = "/data/local/tmp/cups_cp";
    std::string dstDir2 = "/data/local/tmp/cups_sm";
    printCupsClient.CopyDirectory(nullptr, dstDir1.c_str());
    printCupsClient.SymlinkDirectory(nullptr, dstDir2.c_str());
    printCupsClient.CopyDirectory(srcDir.c_str(), dstDir1.c_str());
    printCupsClient.SymlinkDirectory(srcDir.c_str(), dstDir2.c_str());
    mode_t permissions = S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH;
    printCupsClient.ChangeFilterPermission(dstDir1, permissions);
}

/**
 * @tc.name: PrintCupsWrapperTest_0089
 * @tc.desc: QueryPrinterCapabilityFromPpd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCupsWrapperTest, PrintCupsWrapperTest_0089, TestSize.Level1)
{
    cups_dest_t cupsDests = {0};
    cups_dinfo_t cupsDinfo = {0};
    MockTestFunc testFunc =
        [this, &cupsDests, &cupsDinfo](PrintCupsClient &printCupsClient, MockPrintCupsWrapper &mock) {
        EXPECT_CALL(mock, GetNamedDest(_, _, _)).WillRepeatedly(Return(&cupsDests));
        EXPECT_CALL(mock, CopyDestInfo(_, _)).WillRepeatedly(Return(&cupsDinfo));
        std::string printerName = "testName";
        PrinterCapability printerCaps;
        EXPECT_EQ(printCupsClient.QueryPrinterCapabilityFromPPD(printerName, printerCaps), E_PRINT_SERVER_FAILURE);
    };
    DoMockTest(testFunc);
}
}  // namespace Print
}  // namespace OHOS