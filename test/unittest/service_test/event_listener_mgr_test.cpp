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
#include <fstream>
#include <map>
#include <memory>
#define private public
#include "event_listener_mgr.h"
#undef private
#include "print_log.h"
#include "print_constant.h"
#include "mock_remote_object.h"
#include "mock_print_callback_proxy.h"
#include "mock_print_extension_callback_proxy.h"
#include "print_job.h"
#include "printer_info.h"
#include "print_attributes.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

const int32_t TEST_USER_ID = 100;
const int32_t TEST_USER_ID_2 = 200;
const std::string TEST_JOB_ID = "test_job_id_001";
const std::string TEST_JOB_ID_2 = "test_job_id_002";
const std::string TEST_EXTENSION_ID = "com.ohos.testext";
const std::string TEST_EXTENSION_ID_2 = "com.ohos.testext2";
const std::string TEST_PRINTER_ID = "test_printer_001";

class EventListenerMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<PrintJob> CreateTestPrintJob(const std::string &jobId);
    std::shared_ptr<PrinterInfo> CreateTestPrinterInfo();
    std::shared_ptr<PrintAttributes> CreateTestPrintAttributes();
};

void EventListenerMgrTest::SetUpTestCase(void)
{}

void EventListenerMgrTest::TearDownTestCase(void)
{}

void EventListenerMgrTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("EventListenerMgrTest_%{public}d", ++testNo);
}

void EventListenerMgrTest::TearDown(void)
{}

std::shared_ptr<PrintJob> EventListenerMgrTest::CreateTestPrintJob(const std::string &jobId)
{
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    printJob->SetPrinterId(TEST_PRINTER_ID);
    return printJob;
}

std::shared_ptr<PrinterInfo> EventListenerMgrTest::CreateTestPrinterInfo()
{
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(TEST_PRINTER_ID);
    printerInfo->SetPrinterName("Test Printer");
    printerInfo->SetPrinterState(PRINTER_STATUS_IDLE);
    return printerInfo;
}

std::shared_ptr<PrintAttributes> EventListenerMgrTest::CreateTestPrintAttributes()
{
    auto attrs = std::make_shared<PrintAttributes>();
    return attrs;
}

HWTEST_F(EventListenerMgrTest, RegisterPrinterListener_ShouldReturnTrue_WhenValidListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterPrinterListener_ShouldReturnFalse_WhenNullListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, nullptr));
}

HWTEST_F(EventListenerMgrTest, RegisterPrinterListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterExtensionListener_ShouldReturnTrue_WhenValidListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterExtensionListener_ShouldReturnFalse_WhenNullListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, nullptr));
}

HWTEST_F(EventListenerMgrTest, RegisterExtensionListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterPrintJobListener_ShouldReturnTrue_WhenValidListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINTER_JOB_STATE_CHANGE, TEST_JOB_ID, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterPrintJobListener_ShouldReturnFalse_WhenNullListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.RegisterPrintJobListener(PRINTER_JOB_STATE_CHANGE, TEST_JOB_ID, nullptr));
}

HWTEST_F(EventListenerMgrTest, RegisterPrintJobListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterPrintJobListener_ShouldSupportMultipleJobs, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID_2, listener));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrinterListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.UnRegisterPrinterListener(PRINTER_STATE_CHANGE));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrinterListener_ShouldReturnFalse_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.UnRegisterPrinterListener(PRINTER_STATE_CHANGE));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrintJobListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    EXPECT_TRUE(eventListenerMgr.UnRegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrintJobListener_ShouldReturnFalse_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.UnRegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrintJobListener_ShouldKeepOtherJobs, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID_2, listener));
    EXPECT_TRUE(eventListenerMgr.UnRegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
    EXPECT_FALSE(eventListenerMgr.IsPrintJobListenerEmpty(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID_2));
}

HWTEST_F(EventListenerMgrTest, IsPrinterListenerEmpty_ShouldReturnFalse_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
}

HWTEST_F(EventListenerMgrTest, IsPrinterListenerEmpty_ShouldReturnTrue_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
}

HWTEST_F(EventListenerMgrTest, IsExtensionListenerEmpty_ShouldReturnFalse_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));
    EXPECT_FALSE(eventListenerMgr.IsExtensionListenerEmpty(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, 0));
}

HWTEST_F(EventListenerMgrTest, IsExtensionListenerEmpty_ShouldReturnTrue_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.IsExtensionListenerEmpty(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, TEST_USER_ID));
}

HWTEST_F(EventListenerMgrTest, IsPrintJobListenerEmpty_ShouldReturnFalse_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    EXPECT_FALSE(eventListenerMgr.IsPrintJobListenerEmpty(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
}

HWTEST_F(EventListenerMgrTest, IsPrintJobListenerEmpty_ShouldReturnTrue_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.IsPrintJobListenerEmpty(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterStateChangeCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printerInfo = CreateTestPrinterInfo();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_STATE_CHANGE;
    cbInfo.printerInfo = printerInfo;

    EXPECT_CALL(*listener, OnCallback(printerInfo->GetPrinterState(), An<const PrinterInfo &>()))
        .WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterChangeCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printerInfo = CreateTestPrinterInfo();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_CHANGE, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_CHANGE;
    cbInfo.printerInfo = printerInfo;
    cbInfo.printerEvent = PRINTER_EVENT_ADDED;

    EXPECT_CALL(*listener, OnCallback(PRINTER_EVENT_ADDED, An<const PrinterInfo &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterDiscoverCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printerInfo = CreateTestPrinterInfo();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_DISCOVER, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_DISCOVER;
    cbInfo.printerInfo = printerInfo;
    cbInfo.printerEvent = PRINTER_EVENT_STATE_CHANGED;

    EXPECT_CALL(*listener, OnCallback(PRINTER_EVENT_STATE_CHANGED, An<const PrinterInfo &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterInfoQueryCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printerInfo = CreateTestPrinterInfo();
    std::vector<PpdInfo> ppdInfos;

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_INFO_QUERY, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_INFO_QUERY;
    cbInfo.printerInfo = printerInfo;
    cbInfo.ppdInfos = ppdInfos;

    EXPECT_CALL(*listener, OnCallback(An<const PrinterInfo &>(), An<const std::vector<PpdInfo> &>()))
        .WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterExtInfoChangeCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_EXT_INFO_CHANGE, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_EXT_INFO_CHANGE;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.extInfo = "test_ext_info";

    EXPECT_CALL(*listener, OnCallback(TEST_EXTENSION_ID, "test_ext_info")).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrinterJobStateChangeCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printJob = CreateTestPrintJob(TEST_JOB_ID);

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_JOB_STATE_CHANGE, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_JOB_STATE_CHANGE;
    cbInfo.printJobInfo = printJob;

    EXPECT_CALL(*listener, OnCallback(printJob->GetJobState(), An<const PrintJob &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionStartDiscoveryCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_START_DISCOVERY;
    cbInfo.extensionId = TEST_EXTENSION_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionStopDiscoveryCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_STOP_DISCOVERY, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_STOP_DISCOVERY;
    cbInfo.extensionId = TEST_EXTENSION_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionConnectPrinterCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_CONNECT_PRINTER, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_CONNECT_PRINTER;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.printerId = TEST_PRINTER_ID;

    EXPECT_CALL(*listener, OnCallback(TEST_PRINTER_ID)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionDisconnectPrinterCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_DISCONNECT_PRINTER, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_DISCONNECT_PRINTER;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.printerId = TEST_PRINTER_ID;

    EXPECT_CALL(*listener, OnCallback(TEST_PRINTER_ID)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionRequestCapCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_REQUEST_CAP, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_REQUEST_CAP;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.printerId = TEST_PRINTER_ID;

    EXPECT_CALL(*listener, OnCallback(TEST_PRINTER_ID)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionStartPrintCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    auto printJob = CreateTestPrintJob(TEST_JOB_ID);

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_PRINT, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_START_PRINT;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.printJobInfo = printJob;

    EXPECT_CALL(*listener, OnCallback(An<const PrintJob &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionCancelPrintCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    auto printJob = CreateTestPrintJob(TEST_JOB_ID);

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_CANCEL_PRINT, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_CANCEL_PRINT;
    cbInfo.extensionId = TEST_EXTENSION_ID;
    cbInfo.printJobInfo = printJob;

    EXPECT_CALL(*listener, OnCallback(An<const PrintJob &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallExtensionDestroyExtensionCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_DESTROY_EXTENSION, TEST_EXTENSION_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = EXTCB_DESTROY_EXTENSION;
    cbInfo.extensionId = TEST_EXTENSION_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobBlockCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_BLOCK, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_BLOCK;
    cbInfo.jobId = TEST_JOB_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobSuccessCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_SUCCESS, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_SUCCESS;
    cbInfo.jobId = TEST_JOB_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobFailCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_FAIL, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_FAIL;
    cbInfo.jobId = TEST_JOB_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobCancelCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_CANCEL, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_CANCEL;
    cbInfo.jobId = TEST_JOB_ID;

    EXPECT_CALL(*listener, OnCallback()).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobStateCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto printJob = CreateTestPrintJob(TEST_JOB_ID);

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_STATE_CALLBACK;
    cbInfo.jobId = TEST_JOB_ID;
    cbInfo.printJobInfo = printJob;

    EXPECT_CALL(*listener, OnCallback(printJob->GetJobState(), An<const PrintJob &>())).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobCallbackAdapterJobStateChanged, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_CALLBACK_ADAPTER, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_CALLBACK_ADAPTER;
    cbInfo.jobId = TEST_JOB_ID;
    cbInfo.jobState = PRINT_JOB_COMPLETED;
    cbInfo.adapterState = PREVIEW_ABILITY_DESTROY;
    cbInfo.fd = 0;

    EXPECT_CALL(*listener, OnCallbackAdapterJobStateChanged(_, _, _)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobCallbackAdapterLayout, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    auto oldAttrs = CreateTestPrintAttributes();
    auto newAttrs = CreateTestPrintAttributes();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_CALLBACK_ADAPTER, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_CALLBACK_ADAPTER;
    cbInfo.jobId = TEST_JOB_ID;
    cbInfo.oldAttrs = oldAttrs;
    cbInfo.newAttrs = newAttrs;
    cbInfo.fd = 100;

    EXPECT_CALL(*listener, OnCallbackAdapterLayout(TEST_JOB_ID, _, _, 100)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldCallPrintJobFileGetAdapterCallback, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_FILE_GET_ADAPTER, TEST_JOB_ID, listener));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_FILE_GET_ADAPTER;
    cbInfo.jobId = TEST_JOB_ID;
    cbInfo.fileCompletedState = 1;

    EXPECT_CALL(*listener, OnCallbackAdapterGetFile(1)).WillOnce(Return(true));

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldDoNothing_WhenListenerNull, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    ;
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    eventListenerMgr.OnRemoteListenerDied(nullptr);
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldErasePrinterListener_WhenListenerRegistered, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
}

HWTEST_F(
    EventListenerMgrTest, OnRemoteListenerDied_ShouldEraseExtensionListener_WhenListenerRegistered, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintExtensionCallbackProxy> listener = new MockPrintExtensionCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_TRUE(eventListenerMgr.RegisterExtensionListener(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, listener));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.IsExtensionListenerEmpty(EXTCB_START_DISCOVERY, TEST_EXTENSION_ID, TEST_USER_ID));
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldErasePrintJobListener_WhenListenerRegistered, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.IsPrintJobListenerEmpty(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID));
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldKeepOther_WhenListenerDied, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    sptr<MockPrintCallbackProxy> listenerOther = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> objOther = new MockRemoteObject();
    EXPECT_CALL(*listenerOther, AsObject()).WillRepeatedly(Return(objOther));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_CHANGE, listenerOther));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_CHANGE));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldReturnFalse_WhenNoListenerRegistered, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINTER_STATE_CHANGE;
    cbInfo.printerInfo = CreateTestPrinterInfo();

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, Execute_ShouldFilterByJobId, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener1 = new MockPrintCallbackProxy();
    sptr<MockPrintCallbackProxy> listener2 = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID, listener1));
    EXPECT_TRUE(eventListenerMgr.RegisterPrintJobListener(PRINT_JOB_STATE_CALLBACK, TEST_JOB_ID_2, listener2));

    CallbackInfo cbInfo;
    cbInfo.cbEventType = PRINT_JOB_STATE_CALLBACK;
    cbInfo.printJobInfo = CreateTestPrintJob(TEST_JOB_ID);
    cbInfo.jobId = TEST_JOB_ID;

    EXPECT_CALL(*listener1, OnCallback(_, An<const PrintJob &>())).WillOnce(Return(true));
    EXPECT_CALL(*listener2, OnCallback(_, An<const PrintJob &>())).Times(0);

    EXPECT_TRUE(eventListenerMgr.Execute(cbInfo));
}

HWTEST_F(EventListenerMgrTest, RegisterPrinterListener_ShouldSupportMultipleEventTypes, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_DISCOVER, listener));

    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_CHANGE));
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_DISCOVER));
}

HWTEST_F(EventListenerMgrTest, UnRegisterPrinterListener_ShouldKeepOtherEventTypes, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();

    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_STATE_CHANGE, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterPrinterListener(PRINTER_CHANGE, listener));

    EXPECT_TRUE(eventListenerMgr.UnRegisterPrinterListener(PRINTER_STATE_CHANGE));

    EXPECT_TRUE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_STATE_CHANGE));
    EXPECT_FALSE(eventListenerMgr.IsPrinterListenerEmpty(PRINTER_CHANGE));
}

}  // namespace Print
}  // namespace OHOS