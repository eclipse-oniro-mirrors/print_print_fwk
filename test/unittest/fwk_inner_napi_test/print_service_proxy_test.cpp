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

#include "print_service_proxy.h"
#include "print_manager_client.h"
#include "iremote_broker.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceProxyTest::SetUpTestCase(void) {}

void PrintServiceProxyTest::TearDownTestCase(void) {}

void PrintServiceProxyTest::SetUp(void) {}

void PrintServiceProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintServiceProxyTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0001, TestSize.Level1)
{
    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->StartPrint(fileList, fdList, taskId);
    client.printServiceProxy_->StopPrint(taskId);
}

/**
 * @tc.name: PrintServiceProxyTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0002, TestSize.Level1)
{
    const std::string printerId = "1";
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->ConnectPrinter(printerId);
    client.printServiceProxy_->DisconnectPrinter(printerId);
}

/**
 * @tc.name: PrintServiceProxyTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0003, TestSize.Level1)
{
    const std::vector<std::string> extensionList = {"3"};
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->StartDiscoverPrinter(extensionList);
    client.printServiceProxy_->StopDiscoverPrinter();
}

/**
 * @tc.name: PrintServiceProxyTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0004, TestSize.Level1)
{
    const PrintJob jobinfo;
    const std::string jobId  = "1";
    OHOS::Print::PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> extensionInfos;
    extensionInfos.emplace_back(printExtensionInfo);

    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->StartPrintJob(jobinfo);
    client.printServiceProxy_->QueryAllExtension(extensionInfos);
    client.printServiceProxy_->CancelPrintJob(jobId);
}

/**
 * @tc.name: PrintServiceProxyTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0005, TestSize.Level1)
{
    const std::vector<std::string> printerIds = {"1"};
    std::string printerId = "1";
    OHOS::Print::PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName("1");
    printerInfo.SetPrinterIcon(1);
    printerInfo.SetPrinterState(1);
    printerInfo.SetDescription("111");
    const OHOS::Print::PrinterCapability capability;
    printerInfo.SetCapability(capability);
    const std::string option = "1";
    printerInfo.SetOption(option);
    std::vector<PrinterInfo> printerInfos;
    printerInfos.emplace_back(printerInfo);

    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->AddPrinters(printerInfos);
    client.printServiceProxy_->RemovePrinters(printerIds);
    client.printServiceProxy_->UpdatePrinters(printerInfos);
}

/**
 * @tc.name: PrintServiceProxyTest_0006
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0006, TestSize.Level1)
{
    uint32_t state = 0;
    uint32_t subState = 0;
    std::string printerId = "1";
    const std::string jobId = "1";
    const std::string extensionId = "1";

    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->UpdatePrinterState(printerId, state);
    client.printServiceProxy_->UpdatePrintJobState(jobId, state, subState);
    client.printServiceProxy_->UpdateExtensionInfo(extensionId);
}

/**
 * @tc.name: PrintServiceProxyTest_0007
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0007, TestSize.Level1)
{
    std::string printerId = "1";
    std::string previewResult = "1";
    std::vector<uint32_t> fdList = {1, 2};
    std::string jobId = "1";
    OHOS::Print::PrintJob jobinfo;
    jobinfo.SetFdList(fdList);
    jobinfo.SetJobId(jobId);
    jobinfo.SetPrinterId(printerId);
    jobinfo.SetJobState(1);
    jobinfo.SetSubState(1);
    jobinfo.SetCopyNumber(1);
    OHOS::Print::PrintRange pageRange;
    jobinfo.SetPageRange(pageRange);
    jobinfo.SetColorMode(1);
    jobinfo.SetDuplexMode(1);
    jobinfo.SetIsLandscape(true);
    jobinfo.SetIsSequential(true);
    OHOS::Print::PrintPageSize pageSize;
    jobinfo.SetPageSize(pageSize);
    const OHOS::Print::PrintMargin margin;
    jobinfo.SetMargin(margin);
    const std::string option = "1";
    jobinfo.SetOption(option);
    const OHOS::Print::PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->RequestPreview(jobinfo, previewResult);
    client.printServiceProxy_->QueryPrinterCapability(printerId);
}

/**
 * @tc.name: PrintServiceProxyTest_0008
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0008, TestSize.Level1)
{
    const std::string taskId = "2";
    const std::string type = "success";
    const sptr<IPrintCallback> listener;

    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->On(taskId, type, listener);
    client.printServiceProxy_->Off(taskId, type);
}

/**
 * @tc.name: PrintServiceProxyTest_0009
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0009, TestSize.Level1)
{
    //OHOS::Print::PrintServiceProxy printServiceProxy;
    const std::string extensionCID = "1";
    const std::string extensionId = "1";
    const sptr<IPrintExtensionCallback> listener;
    
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->RegisterExtCallback(extensionCID, listener);
    client.printServiceProxy_->UnregisterAllExtCallback(extensionId);
}

/**
 * @tc.name: PrintServiceProxyTest_0010
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0010, TestSize.Level1)
{
    const std::string extensionId = "1";
    std::string printerId = "1";
    std::string printJobId = "1";
    std::vector<uint32_t> fdList = {1, 2};
    std::string jobId = "1";
    OHOS::Print::PrintJob jobinfo;
    jobinfo.SetFdList(fdList);
    jobinfo.SetJobId(jobId);
    jobinfo.SetPrinterId(printerId);
    jobinfo.SetJobState(1);
    jobinfo.SetSubState(1);
    jobinfo.SetCopyNumber(1);
    OHOS::Print::PrintRange pageRange;
    jobinfo.SetPageRange(pageRange);
    jobinfo.SetColorMode(1);
    jobinfo.SetDuplexMode(1);
    jobinfo.SetIsLandscape(true);
    jobinfo.SetIsSequential(true);
    OHOS::Print::PrintPageSize pageSize;
    jobinfo.SetPageSize(pageSize);
    const OHOS::Print::PrintMargin margin;
    jobinfo.SetMargin(margin);
    const std::string option = "1";
    jobinfo.SetOption(option);
    const OHOS::Print::PrintPreviewAttribute preview;
    jobinfo.SetPreview(preview);
    std::vector<PrintJob> printJobs;
    printJobs.emplace_back(jobinfo);
    
    OHOS::Print::PrintManagerClient client;
    client.printServiceProxy_ = client.GetPrintServiceProxy();
    client.printServiceProxy_->LoadExtSuccess(extensionId);
    client.printServiceProxy_->QueryAllPrintJob(printJobs);
    client.printServiceProxy_->QueryPrintJobById(printJobId, jobinfo);
}
} // namespace Print
} // namespace OHOS