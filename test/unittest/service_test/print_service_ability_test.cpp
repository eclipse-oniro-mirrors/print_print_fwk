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
#include "napi/native_api.h"
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
* @tc.desc: PrintServiceAbility
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001, TestSize.Level1)
{
    // OHOS::Print::PrintServiceAbility::PrintServiceAbility printSA;
    OHOS::Print::PrintServiceAbility printSA_init(32, true);
    printSA_init.~PrintServiceAbility();
}

/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA_init(32, true);
    std::vector<std::string> fileList = {"50", "51", "52"};
    std::vector<uint32_t> fdList = {1, 2, 3};
    std::vector<std::string> fileList_err = {};
    std::vector<uint32_t> fdList_err = {};
    std::string taskId = "taskId_1";
    printSA_init.StartPrint(fileList, fdList, taskId);
    printSA_init.StartPrint(fileList_err, fdList_err, taskId);
}

/**
* @tc.name: PrintServiceAbilityTest_0003
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::vector<std::string> extensionList = {"50", "51", "52"};
    std::string printerId = "1";
    printSA.ConnectPrinter(printerId);
    printSA.DisconnectPrinter(printerId);
    printSA.StartDiscoverPrinter(extensionList);
    printSA.StopDiscoverPrinter();
}

/**
* @tc.name: PrintServiceAbilityTest_0004
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string printerId = "1";
    printSA.QueryPrinterCapability(printerId);
}

/**
* @tc.name: PrintServiceAbilityTest_0005
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string printerId = "1";
    std::string jobId = "1";
    PrintJob jobinfo;
    printSA.StartPrintJob(jobinfo);
    printSA.CancelPrintJob(jobId);
}

/**
* @tc.name: PrintServiceAbilityTest_0006
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::vector<std::string> printerIds = {"1", "2"};
    PrinterInfo printerInfo;
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    printSA.AddPrinters(printerInfos);
    printSA.RemovePrinters(printerIds);
}

/**
* @tc.name: PrintServiceAbilityTest_0007
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string printerId = "1";
    PrinterInfo printerInfo;
    uint32_t state = 0;
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);
    printSA.UpdatePrinters(printerInfos);
    printSA.UpdatePrinterState(printerId, state);
}

/**
* @tc.name: PrintServiceAbilityTest_0008
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string printerId = "1";
    std::string previewResult = "1";
    PrintJob jobInfo;
    printSA.RequestPreview(jobInfo, previewResult);
}

/**
* @tc.name: PrintServiceAbilityTest_0009
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string taskId = "1";
    std::string type = "1";
    sptr<IPrintCallback> listener;
    printSA.On(taskId, type, listener);
    printSA.Off(taskId, type);
}

/**
* @tc.name: PrintServiceAbilityTest_0010
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string printJobId = "1";
    PrintJob printJob;
    std::vector<PrintJob> printJobs;
    printJobs.emplace_back(printJob);
    printSA.QueryAllPrintJob(printJobs);
    printSA.QueryPrintJobById(printJobId, printJob);
}

/**
* @tc.name: PrintServiceAbilityTest_0011
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string jobId = "1";
    std::string extInfo = "1";
    uint32_t state = 0;
    uint32_t subState = 0;
    printSA.UpdatePrintJobState(jobId, state, subState);
    printSA.UpdateExtensionInfo(extInfo);
}

/**
* @tc.name: PrintServiceAbilityTest_0012
* @tc.desc: StartPrint, StopPrint
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintServiceAbility printSA(32, true);
    std::string extensionCID = "1";
    std::string extensionId = "1";
    const sptr<IPrintExtensionCallback> listener;
    printSA.RegisterExtCallback(extensionCID, listener);
    printSA.UnregisterAllExtCallback(extensionId);
}
} // namespace Print
} // namespace OHOS
