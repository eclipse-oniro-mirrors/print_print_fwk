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

void PrintManagerClientTest::SetUpTestCase(void) {}

void PrintManagerClientTest::TearDownTestCase(void) {}

void PrintManagerClientTest::SetUp(void) {}

void PrintManagerClientTest::TearDown(void) {}

/**
 * @tc.name: PrintManagerClientTest_0001
 * @tc.desc: QueryAllExtension
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
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> extensionInfos;
    extensionInfos.emplace_back(printExtensionInfo);
    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.QueryAllExtension(extensionInfos);
}

/**
* @tc.name: PrintManagerClientTest_0002
* @tc.desc: QueryAllExtension_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<PrintExtensionInfo> extensionInfos;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.QueryAllExtension(extensionInfos);
}

/**
* @tc.name: PrintManagerClientTest_0003
* @tc.desc: StartDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
}

/**
* @tc.name: PrintManagerClientTest_0004
* @tc.desc: StartDiscoverPrinter_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
}

/**
* @tc.name: PrintManagerClientTest_0005
* @tc.desc: StopDiscoverPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.StopDiscoverPrinter();
}

/**
* @tc.name: PrintManagerClientTest_0006
* @tc.desc: AddPrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

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

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
}

/**
* @tc.name: PrintManagerClientTest_0007
* @tc.desc: AddPrinters_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
}

/**
* @tc.name: PrintManagerClientTest_0008
* @tc.desc: RemovePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    const std::string printerId = "1";
    std::vector<std::string> printerIds = {"1"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.RemovePrinters(printerIds);
}

/**
* @tc.name: PrintManagerClientTest_0009
* @tc.desc: RemovePrinters_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::vector<std::string> printerIds;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.RemovePrinters(printerIds);
}

/**
* @tc.name: PrintManagerClientTest_0010
* @tc.desc: RemovePrinters_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::vector<std::string> printerIds = {"1"};

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.RemovePrinters(printerIds);
}

/**
* @tc.name: PrintManagerClientTest_0011
* @tc.desc: UpdatePrinters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    const std::string printerId = "1";
    std::vector<std::string> printerIds = {"1"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.UpdatePrinters(printerInfos);
}

/**
* @tc.name: PrintManagerClientTest_0012
* @tc.desc: UpdatePrinters_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.UpdatePrinters(printerInfos);
}

/**
* @tc.name: PrintManagerClientTest_0013
* @tc.desc: ConnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    const std::string printerId = "1";
    std::vector<std::string> printerIds = {"1"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0014
* @tc.desc: ConnectPrinter_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0015
* @tc.desc: DisconnectPrinter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};

    const std::string printerId = "1";
    std::vector<std::string> printerIds = {"1"};
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.DisconnectPrinter(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0016
* @tc.desc: DisconnectPrinter_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0016, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.DisconnectPrinter(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0017
* @tc.desc: DisconnectPrinter_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.DisconnectPrinter(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0018
* @tc.desc: StartPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0018, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
}

/**
* @tc.name: PrintManagerClientTest_0019
* @tc.desc: StartPrintJob_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0019, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
}

/**
* @tc.name: PrintManagerClientTest_0020
* @tc.desc: CancelPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0020, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.CancelPrintJob(jobId);
}

/**
* @tc.name: PrintManagerClientTest_0021
* @tc.desc: CancelPrintJob_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0021, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string jobId;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.CancelPrintJob(jobId);
}

/**
* @tc.name: PrintManagerClientTest_0022
* @tc.desc: CancelPrintJob_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0022, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string jobId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.CancelPrintJob(jobId);
}

/**
* @tc.name: PrintManagerClientTest_0023
* @tc.desc: UpdatePrinterState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0023, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    uint32_t state = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrinterState(printerId, state);
}

/**
* @tc.name: PrintManagerClientTest_0024
* @tc.desc: UpdatePrinterState_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0024, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    uint32_t state = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrinterState(printerId, state);
}

/**
* @tc.name: PrintManagerClientTest_0025
* @tc.desc: UpdatePrinterState_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0025, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    uint32_t state = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrinterState(printerId, state);
}

/**
* @tc.name: PrintManagerClientTest_0026
* @tc.desc: UpdatePrintJobState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0026, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    uint32_t state = 0;
    uint32_t subState = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrintJobState(jobId, state, subState);
}

/**
* @tc.name: PrintManagerClientTest_0027
* @tc.desc: UpdatePrintJobState_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0027, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string jobId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
}

/**
* @tc.name: PrintManagerClientTest_0028
* @tc.desc: UpdatePrintJobState_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0028, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string jobId = "1";
    uint32_t state = 0;
    uint32_t subState = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrintJobState(jobId, state, subState);
}

/**
* @tc.name: PrintManagerClientTest_0029
* @tc.desc: UpdatePrintJobState_NA3
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0029, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string jobId = "1";
    uint32_t state = 0;
    uint32_t subState = 0;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdatePrintJobState(jobId, state, subState);
}

/**
* @tc.name: PrintManagerClientTest_0030
* @tc.desc: UpdateExtensionInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0030, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string extensionId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdateExtensionInfo(extensionId);
}

/**
* @tc.name: PrintManagerClientTest_0031
* @tc.desc: UpdateExtensionInfo_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0031, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string extensionId;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.UpdateExtensionInfo(extensionId);
}

/**
* @tc.name: PrintManagerClientTest_0032
* @tc.desc: RequestPreview
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0032, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    std::string previewResult = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.RequestPreview(jobinfo, previewResult);
}

/**
* @tc.name: PrintManagerClientTest_0033
* @tc.desc: RequestPreview_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0033, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string previewResult = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.RequestPreview(jobinfo, previewResult);
}

/**
* @tc.name: PrintManagerClientTest_0034
* @tc.desc: RequestPreview_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0034, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string previewResult;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.RequestPreview(jobinfo, previewResult);
}

/**
* @tc.name: PrintManagerClientTest_0035
* @tc.desc: QueryPrinterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0035, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";

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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    std::vector<PrintJob> printJobs;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryPrinterCapability(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0036
* @tc.desc: QueryPrinterCapability_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0036, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId;
    PrintJob jobinfo;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryPrinterCapability(printerId);
}

/**
* @tc.name: PrintManagerClientTest_0037
* @tc.desc: QueryAllPrintJob
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0037, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    std::vector<PrintJob> printJobs;
    printJobs.emplace_back(jobinfo);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryAllPrintJob(printJobs);
}

/**
* @tc.name: PrintManagerClientTest_0038
* @tc.desc: QueryAllPrintJob_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0038, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::vector<PrintJob> printJobs = {};

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryAllPrintJob(printJobs);
}

/**
* @tc.name: PrintManagerClientTest_0039
* @tc.desc: QueryPrintJobById
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0039, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    std::string printJobId = "1";

    PrintJob jobinfo, printjob;
    jobinfo.SetFdList(fdList);
    jobinfo.SetJobId(printJobId);
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
    const std::string option = "1";
    jobinfo.SetOption(option);
    const PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryPrintJobById(printJobId, printjob);
}

/**
* @tc.name: PrintManagerClientTest_0040
* @tc.desc: QueryPrintJobById_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0040, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    std::string printJobId = "1";
    PrintJob jobinfo;
    PrintJob printjob;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryPrintJobById(printJobId, printjob);
}

/**
* @tc.name: PrintManagerClientTest_0041
* @tc.desc: QueryPrintJobById_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0041, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    std::string printJobId = "1";
    PrintJob jobinfo;
    PrintJob printjob;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.QueryPrintJobById(printJobId, printjob);
}

/**
* @tc.name: PrintManagerClientTest_0044
* @tc.desc: On_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0044, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type;
    sptr<IPrintCallback> listener;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
}

/**
* @tc.name: PrintManagerClientTest_0045
* @tc.desc: On_NA3
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0045, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId;
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type;
    sptr<IPrintCallback> listener;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
}

/**
* @tc.name: PrintManagerClientTest_0046
* @tc.desc: Off
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0046, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type = "1";
    sptr<IPrintCallback> listener;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
    Testclient.Off(taskId, type);
}

/**
* @tc.name: PrintManagerClientTest_0047
* @tc.desc: Off_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0047, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId;
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type = "1";
    sptr<IPrintCallback> listener;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
    Testclient.Off(taskId, type);
}

/**
* @tc.name: PrintManagerClientTest_0048
* @tc.desc: Off_NA2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0048, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type;
    sptr<IPrintCallback> listener;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
    Testclient.Off(taskId, type);
}

/**
* @tc.name: PrintManagerClientTest_0049
* @tc.desc: LoadExtSuccess
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0049, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type = "1";
    sptr<IPrintCallback> listener;
    std::string extensionId = "1";

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
    Testclient.LoadExtSuccess(extensionId);
}


/**
* @tc.name: PrintManagerClientTest_0050
* @tc.desc: LoadExtSuccess_NA1
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0050, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;

    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    std::vector<std::string> extensionList = {"3"};
    std::vector<PrinterInfo> printerInfos;
    std::string printerId = "1";
    PrintJob jobinfo;
    std::string type = "1";
    sptr<IPrintCallback> listener;
    std::string extensionId;

    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.StartDiscoverPrinter(extensionList);
    Testclient.AddPrinters(printerInfos);
    Testclient.ConnectPrinter(printerId);
    Testclient.StartPrintJob(jobinfo);
    Testclient.On(taskId, type, listener);
    Testclient.LoadExtSuccess(extensionId);
}

/**
* @tc.name: PrintManagerClientTest_0051
* @tc.desc: LoadServerSuccess
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0051, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;
    Testclient.LoadServerSuccess();
}

/**
* @tc.name: PrintManagerClientTest_0052
* @tc.desc: LoadServerFail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0052, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;
    Testclient.LoadServerFail();
}
} // namespace Print
} // namespace OHOS
