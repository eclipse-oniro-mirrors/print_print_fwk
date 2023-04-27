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
#include "print_manager_client.h"

#include "iservice_registry.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintManagerClientTest::SetUpTestCase(void)
{
    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    const std::vector<uint32_t> fdList = {1, 2};

    std::string previewResult = "1";
    std::string taskId = "1";
    std::string type = "1";
    wptr<IRemoteObject> object;
    sptr<IPrintCallback> listener;

    std::string extensionId = "1";
    std::vector<std::string> extensionList = {"1"};

    const std::string printerId = "1";
    std::vector<std::string> printerIds = {"1"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    std::string jobId = "1";
    std::string printJobId = "1";
    PrintJob jobinfo;
    jobinfo.SetFdList(fdList);
    jobinfo.SetJobId(jobId);
    jobinfo.SetPrinterId(printerId);
    jobinfo.SetJobState(1);
    jobinfo.SetSubState(1);
    jobinfo.SetCopyNumber(1);
    PrintRange pageRange;
    jobinfo.SetPageRange(pageRange);
    jobinfo.SetColorMode(1);
    jobinfo.SetDuplexMode(1);
    jobinfo.SetIsLandscape(true);
    jobinfo.SetIsSequential(true);
    PrintPageSize pageSize;
    jobinfo.SetPageSize(pageSize);
    const PrintMargin margin;
    jobinfo.SetMargin(margin);
    jobinfo.SetOption(option);
    std::vector<PrintJob> printJobs;
    printJobs.emplace_back(jobinfo);
}

void PrintManagerClientTest::TearDownTestCase(void) {}

void PrintManagerClientTest::SetUp(void) {}

void PrintManagerClientTest::TearDown(void) {}

/**
 * @tc.name: PrintManagerClientTest_0001
 * @tc.desc: LoadExtSuccess_NA1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::string extensionId = "0";
    std::vector<PrintExtensionInfo> extensionListEmpty = {};
    std::vector<std::string> extensionList = {"3"};
    std::vector<std::string> printIdList;
    std::vector<PrinterInfo> printerInfos;
    std::string previewResult;
    std::string printerId = "1";
    std::string printJobId = "1";
    PrintJob jobinfo, jobNull;
    std::string type = "1";
    sptr<IPrintCallback> listener;
    std::vector<PrintJob> printJobs;

    Testclient.On(taskId, type, listener);
    Testclient.QueryAllExtension(extensionListEmpty);
    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.StopDiscoverPrinter();
    Testclient.AddPrinters(printerInfos);
    Testclient.UpdatePrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrintJobState(jobinfo.GetJobId(), 1, 1);
    Testclient.UpdateExtensionInfo(extensionId);
    Testclient.RequestPreview(jobinfo, previewResult);
    Testclient.QueryAllPrintJob(printJobs);
    Testclient.QueryPrintJobById(printJobId, jobNull);
    Testclient.CancelPrintJob(jobinfo.GetJobId());
    Testclient.UpdatePrinterState(jobinfo.GetJobId(), 1);
    Testclient.DisconnectPrinter(printerId);
    Testclient.RemovePrinters(printIdList);
    Testclient.StopPrint(taskId);
    Testclient.Off(taskId, type);
}

/**
 * @tc.name: PrintManagerClientTest_0002
 * @tc.desc: LoadServerSuccess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;
    Testclient.LoadServerSuccess();
}

/**
 * @tc.name: PrintManagerClientTest_0003
 * @tc.desc: LoadServerFail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;
    Testclient.LoadServerFail();
}
} // namespace Print
} // namespace OHOS
