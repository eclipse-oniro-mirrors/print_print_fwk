/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "print_service_ability.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceAbilityTest::SetUpTestCase(void) {}

void PrintServiceAbilityTest::TearDownTestCase(void) {}

void PrintServiceAbilityTest::SetUp(void) {}

void PrintServiceAbilityTest::TearDown(void) {}

/**
* @tc.name: PrintServiceAbilityTest_0001
* @tc.desc: StartPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    printServiceAbility.~PrintServiceAbility();
}

/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: StartPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002, TestSize.Level1)
{
    auto printServiceAbility = OHOS::Print::PrintServiceAbility::GetInstance();
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    int32_t result = printServiceAbility->StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0003
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;
    std::string taskId = "taskId_1";
    int32_t result = printServiceAbility.StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0004
* @tc.desc: StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    int32_t result = printServiceAbility.StopPrint(taskId);
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0005
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "1";
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfo.SetPrinterId("1");
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.AddPrinters(printerInfos);
    printServiceAbility.ConnectPrinter(printerId);
    int32_t result = printServiceAbility.DisconnectPrinter(printerId);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0006
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "2";
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfo.SetPrinterId("1");
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.AddPrinters(printerInfos);
    printServiceAbility.ConnectPrinter(printerId);
    int32_t result = printServiceAbility.DisconnectPrinter(printerId);
    EXPECT_EQ(E_PRINT_INVALID_PRINTER, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0007
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "1";
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfo.SetPrinterId("1");
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.AddPrinters(printerInfos);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    printServiceAbility.ConnectPrinter(printerId);
    int32_t result = printServiceAbility.DisconnectPrinter(printerId);
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0008
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> extensionList = {"50", "51", "52"};
    std::vector<PrintExtensionInfo> extensionInfoList;
    PrintExtensionInfo infoFirst, infoSecond, infoThird;
    infoFirst.SetExtensionId("50");
    infoSecond.SetExtensionId("51");
    infoThird.SetExtensionId("52");
    extensionInfoList.emplace_back(infoFirst);
    extensionInfoList.emplace_back(infoSecond);
    extensionInfoList.emplace_back(infoThird);
    printServiceAbility.QueryAllExtension(extensionInfoList);
    printServiceAbility.StartDiscoverPrinter(extensionList);
    int32_t result = printServiceAbility.StopDiscoverPrinter();
    EXPECT_EQ(E_PRINT_NONE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0009
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> extensionList = {"50", "51", "52"};
    std::vector<PrintExtensionInfo> extensionInfoList;
    PrintExtensionInfo infoFirst;
    infoFirst.SetExtensionId("49");
    extensionInfoList.emplace_back(infoFirst);
    printServiceAbility.QueryAllExtension(extensionInfoList);
    int32_t result = printServiceAbility.StartDiscoverPrinter(extensionList);
    EXPECT_EQ(E_PRINT_INVALID_EXTENSION, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0010
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> extensionList;
    std::vector<PrintExtensionInfo> extensionInfoList;
    PrintExtensionInfo infoFirst;
    infoFirst.SetExtensionId("49");
    extensionInfoList.emplace_back(infoFirst);
    printServiceAbility.QueryAllExtension(extensionInfoList);
    int32_t result = printServiceAbility.StartDiscoverPrinter(extensionList);
    EXPECT_EQ(E_PRINT_INVALID_EXTENSION, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0011
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<PrintExtensionInfo> extensionList;
    int32_t result = printServiceAbility.QueryAllExtension(extensionList);
    EXPECT_EQ(E_PRINT_SERVER_FAILURE, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0012
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    int32_t ret = printServiceAbility.StartPrintJob(jobinfo);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0013
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    int32_t ret = printServiceAbility.StartPrintJob(jobinfo);
    EXPECT_EQ(E_PRINT_INVALID_PRINTJOB, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0014
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    int32_t ret = printServiceAbility.StartPrintJob(jobinfo);
    ret = printServiceAbility.CancelPrintJob(jobId);
    EXPECT_EQ(E_PRINT_GENERIC_FAILURE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0015
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    int32_t ret = printServiceAbility.CancelPrintJob(jobId);
    EXPECT_EQ(E_PRINT_INVALID_PRINTJOB, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0016
* @tc.desc: AddPrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0016, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    std::vector<std::string> printerIds = {"1", "2"};
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    int32_t ret = printServiceAbility.AddPrinters(printerInfos);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0017
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    PrintJob jobinfo;
    std::vector<std::string> printerIds = {"1", "2"};
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.AddPrinters(printerInfos);
    int32_t ret = printServiceAbility.RemovePrinters(printerIds);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0018
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0018, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::vector<std::string> printerIds = {"1", "2"};
    int32_t ret = printServiceAbility.RemovePrinters(printerIds);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0019
* @tc.desc: UpdatePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0019, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "1";
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    int32_t ret = printServiceAbility.UpdatePrinters(printerInfos);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0020
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0020, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "1";
    uint32_t state = 0;
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfo.SetPrinterId("1");
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.AddPrinters(printerInfos);
    printServiceAbility.UpdatePrinters(printerInfos);
    int32_t ret = printServiceAbility.UpdatePrinterState(printerId, state);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0021
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0021, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string printerId = "1";
    uint32_t state = 0;
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfo.SetPrinterId("1");
    printerInfos.emplace_back(printerInfo);
    printServiceAbility.UpdatePrinters(printerInfos);
    int32_t ret = printServiceAbility.UpdatePrinterState(printerId, state);
    EXPECT_EQ(E_PRINT_INVALID_PRINTER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0022
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 5;
    uint32_t subState = 0;
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0023
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 3;
    uint32_t subState = 0;
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0024
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 3;
    uint32_t subState = 100;
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0025
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 4;
    uint32_t subState = 4;
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_INVALID_PARAMETER, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0026
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 3;
    uint32_t subState = 4;
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    printServiceAbility.StartPrintJob(jobinfo);
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0027
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0027, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 4;
    uint32_t subState = 4;
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    printServiceAbility.StartPrintJob(jobinfo);
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_NONE, ret);
}

/**
* @tc.name: PrintServiceAbilityTest_0028
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 4;
    uint32_t subState = 4;
    PrintJob jobinfo;
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::string taskId = "taskId_1";
    printServiceAbility.StartPrint(fileList, fdList, taskId);
    std::string extensionCID = "1";
    const sptr<IPrintExtensionCallback> listener;
    printServiceAbility.RegisterExtCallback(extensionCID, listener);
    printServiceAbility.StartPrintJob(jobinfo);
    int32_t ret = printServiceAbility.UpdatePrintJobState(jobId, state, subState);
    EXPECT_EQ(E_PRINT_NONE, ret);
}







/**
* @tc.name: PrintServiceAbilityTest_0011
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0023, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string jobId = "1";
//     std::string extInfo = "1";
//     uint32_t state = 0;
//     uint32_t subState = 0;
//     printServiceAbility.UpdatePrintJobState(jobId, state, subState);
//     int32_t ret = printServiceAbility.UpdateExtensionInfo(extInfo);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0012
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string printerId = "1";
//     std::string previewResult = "1";
//     PrintJob jobInfo;
//     int32_t ret = printServiceAbility.RequestPreview(jobInfo, previewResult);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0013
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string printerId = "1";
//     int32_t ret = printServiceAbility.QueryPrinterCapability(printerId);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0014
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string taskId = "1";
//     std::string type = "1";
//     sptr<IPrintCallback> listener;
//     printServiceAbility.On(taskId, type, listener);
//     int32_t ret = printServiceAbility.Off(taskId, type);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0015
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0027, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string extensionCID = "1";
//     std::string extensionId = "1";
//     const sptr<IPrintExtensionCallback> listener;
//     printServiceAbility.RegisterExtCallback(extensionCID, listener);
//     int32_t ret = printServiceAbility.UnregisterAllExtCallback(extensionId);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0016
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string extensionId = "1";
//     int32_t ret = printServiceAbility.LoadExtSuccess(extensionId);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }

// /**
// * @tc.name: PrintServiceAbilityTest_0017
// * @tc.desc: PrintServiceAbility
// * @tc.type: FUNC
// * @tc.require:
// */
// HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0029, TestSize.Level1)
// {
//     OHOS::Print::PrintServiceAbility printServiceAbility(32, true);
//     std::string printJobId = "1";
//     PrintJob printJob;
//     std::vector<PrintJob> printJobs;
//     printJobs.emplace_back(printJob);
//     printServiceAbility.QueryAllPrintJob(printJobs);
//     int32_t ret = printServiceAbility.QueryPrintJobById(printJobId, printJob);
//     EXPECT_EQ(E_PRINT_NONE, ret);
// }
} // namespace Print
} // namespace OHOS
