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

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_PARAMETER);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_NON_EXIST), PRINT_EXTCB_START_DISCOVERY);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_UNLOAD), PRINT_EXTCB_START_DISCOVERY);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_MAX);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_NON_EXIST)), E_PRINT_INVALID_EXTENSION);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_UNLOAD)), E_PRINT_INVALID_EXTENSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string taskId = "";
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_INVALID_PARAMETER);
    taskId = "1";
    type = "printCallback_adapter";
    service->On(taskId, type, listener);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
    listener = new MockPrintCallbackProxy();
    if (listener != nullptr) {
        service->On(taskId, type, listener);
    }
    taskId = "";
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0051_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    std::string jobId = "1";
    uint32_t state = PRINTER_UNKNOWN;
    uint32_t subState = 0;
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    EXPECT_EQ(service->AdapterGetFileCallBack(jobId, state, subState), E_PRINT_NONE);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    service->AdapterGetFileCallBack(jobId, state, subState);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_FAILED;
    service->AdapterGetFileCallBack(jobId, state, subState);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0056_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterPrinterCallback(type, listener), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->UnregisterPrinterCallback(type), E_PRINT_INVALID_TOKEN);
    sptr<IPrintCallback> listener2 = new MockPrintCallbackProxy();
    service->RegisterPrinterCallback(type, listener2);
    service->UnregisterPrinterCallback(type);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0057_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    int event = 0;
    PrinterInfo info;
    EXPECT_EQ(service->SendPrinterChangeEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0082_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS;
    std::string jobId = "123";
    std::string type = PRINT_GET_FILE_EVENT_TYPE;
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    service->SetHelper(mockHelper);
    auto ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    subState = PRINT_JOB_CREATE_FILE_COMPLETED_FAILED;
    ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NONE);
    subState = PRINT_JOB_BLOCKED_UNKNOWN;
    ret = service->AdapterGetFileCallBack(jobId, state, subState);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0088_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    auto ret = service->RegisterExtCallback(extensionCid, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    std::string extensionCid2 = "123:20";
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_EXTENSION);
    std::string extensionId = "123";
    int32_t userId = service->GetCurrentUserId();
    std::string stateKey = PrintUtils::MakeExtensionStateKey(userId, extensionId);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_UNLOAD;
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_EXTENSION);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_LOADING;
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
    std::string extensionCid3 = "123:2";
    ret = service->RegisterExtCallback(extensionCid2, listener);
    EXPECT_EQ(ret, E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0090_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    std::string extensionId = "123";
    int32_t userId = service->GetCurrentUserId();
    std::string stateKey = PrintUtils::MakeExtensionStateKey(userId, extensionId);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_UNLOAD;
    auto ret = service->LoadExtSuccess(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
    service->extensionStateList_[stateKey] = PRINT_EXTENSION_LOADING;
    ret = service->LoadExtSuccess(extensionId);
    EXPECT_EQ(ret, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0091_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string jobId = "123";
    std::string type = PRINT_CALLBACK_ADAPTER;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_NE(listener, nullptr);
    service->On(jobId, type, listener);
    type = PRINTER_CHANGE_EVENT_TYPE;
    service->On(jobId, type, listener);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0093_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    EXPECT_NE(service->SendPrinterDiscoverEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0094_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->printUserDataMap_[100] = nullptr;
    std::shared_ptr<PrintUserData> userData = std::make_shared<PrintUserData>();
    service->printUserDataMap_[101] = userData;
    int event = 0;
    PrinterInfo info;
    EXPECT_NE(service->SendPrinterChangeEvent(event, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0095_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    PrinterInfo info;
    service->SendPrinterEvent(info);
    EXPECT_EQ(info.GetPrinterState(), PRINTER_UNKNOWN);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0096_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    PrinterInfo info;
    PrinterEvent printerEvent = PRINTER_EVENT_STATE_CHANGED;
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info, true), 0);
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info), 0);

    printerEvent = PRINTER_EVENT_LAST_USED_PRINTER_CHANGED;
    EXPECT_EQ(service->SendPrinterEventChangeEvent(printerEvent, info), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0097_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    PrintJob jobInfo;
    jobInfo.SetJobId("1");
    service->SendPrintJobEvent(jobInfo);
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(DelayedSingleton<EventListenerMgr>::GetInstance()->RegisterPrinterListener(PRINTER_JOB_STATE_CHANGE,
        listener));
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_BLOCKED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_COMPLETED);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_SUCCESS);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_FAILED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetSubState(PRINT_JOB_COMPLETED_CANCELLED);
    service->SendPrintJobEvent(jobInfo);
    jobInfo.SetJobState(PRINT_JOB_BLOCKED);
    service->SendPrintJobEvent(jobInfo);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0098_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    std::string extensionId = "123";
    std::string extInfo = "123";
    EXPECT_EQ(service->SendExtensionEvent(extensionId, extInfo), 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0113_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::shared_ptr<PrintServiceHelper> helper = std::make_shared<PrintServiceHelper>();
    service->helper_ = helper;
    std::string taskId = "";
    std::string type = PRINTER_CHANGE_EVENT_TYPE;
    auto ret = service->Off(taskId, type);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, OnQueryCallBackTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    DelayedSingleton<EventListenerMgr>::GetInstance()->ClearAllListeners();
    PrinterInfo info;
    EXPECT_TRUE(service->OnQueryCallBackEvent(info));
    info.SetPrinterMake("fake make");
    EXPECT_TRUE(service->OnQueryCallBackEvent(info));
    Json::Value option;
    option["bsunidriverSupport"] = "true";
    info.SetOption(PrintJsonUtil::WriteString(option));
    EXPECT_TRUE(service->OnQueryCallBackEvent(info));
}
#ifdef KIA_INTERCEPTOR_ENABLE

HWTEST_F(PrintServiceAbilityTest, RegisterKiaInterceptorCallbackTest, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    auto callback = sptr<MockKiaInterceptorCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);
    service->SetHelper(mockHelper);
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(service->RegisterKiaInterceptorCallback(nullptr), E_PRINT_NO_PERMISSION);
    EXPECT_EQ(service->RegisterKiaInterceptorCallback(nullptr), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(service->RegisterKiaInterceptorCallback(callback), E_PRINT_NONE);
}

#endif  // KIA_INTERCEPTOR_ENABLE

}  // namespace Print
}  // namespace OHOS
