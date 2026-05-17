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
#define private public
#define protected public
#include "printserviceability_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"
#include "print_callback.h"
#include "iprint_adapter_inner.h"
#include "print_extension_callback_stub.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr int MAX_SET_NUMBER = 128;
constexpr size_t U32_AT_SIZE = 4;
static constexpr const char *JOB_OPTIONS =
    "{\"jobName\":\"xx\",\"jobNum\":1,\"mediaType\":\"stationery\",\"documentCategory\":0,\"printQuality\":\"4\","
    "\"printerName\":\"testId\",\"printerUri\":\"ipp://192.168.0.1:111/ipp/print\","
    "\"documentFormat\":\"application/pdf\",\"files\":[\"/data/1.pdf\"]}";

void TestOn(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr <PrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->On(taskId, type, callback);
}

void TestOff(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->Off(taskId, type);
}

void TestCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintDocumentAdapter *printerAdapterPtr = new PrintDocumentAdapter();
    sptr <PrintCallback> callback = new(std::nothrow) PrintCallback(printerAdapterPtr);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterPrinterCallback(type, callback);
    PrintServiceAbility::GetInstance()->UnregisterPrinterCallback(type);

    std::vector <PrintExtensionInfo> printExtensionInfos;
    PrintServiceAbility::GetInstance()->QueryAllExtension(printExtensionInfos);
    std::vector <std::string> extensionIds;
    for (auto &printExtensionInfo: printExtensionInfos) {
        extensionIds.push_back(printExtensionInfo.GetExtensionId());
    }
    PrintServiceAbility::GetInstance()->StartDiscoverPrinter(extensionIds);

    sptr<PrintExtensionCallbackStub> extCallback = new(std::nothrow) PrintExtensionCallbackStub();
    for (auto &printExtensionInfo: printExtensionInfos) {
        PrintServiceAbility::GetInstance()->RegisterExtCallback(printExtensionInfo.GetExtensionId(), extCallback);
    }
    
    std::string extensionCID = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RegisterExtCallback(extensionCID, extCallback);
}

void TestLoadExtSuccess(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->LoadExtSuccess(extensionId);
}

void TestSendExtensionEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string extInfo = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SendExtensionEvent(extensionId, extInfo);
    PrintServiceAbility::GetInstance()->UpdatePrintUserMap();
}

void TestCancelUserPrintJobs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->CancelUserPrintJobs(userId);
    PrintServiceAbility::GetInstance()->CallStatusBar();
    AAFwk::Want want;
    want.SetElementName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
        dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->StartExtensionAbility(want);
}

void TestBlockUserPrintJobs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->BlockUserPrintJobs(userId);
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->RestartPrintJob(jobId);
}

void TestIsDisablePrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
#ifdef EDM_SERVICE_ENABLE
    PrintServiceAbility::GetInstance()->IsDisablePrint();
#endif // EDM_SERVICE_ENABLE
}

void TestReportBannedEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
#ifdef EDM_SERVICE_ENABLE
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReportBannedEvent(option);
    Json::Value optionJson;
    optionJson["jobName"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    option = PrintJsonUtil::WriteStringUTF8(optionJson);
    PrintServiceAbility::GetInstance()->ReportBannedEvent(option);
#endif // EDM_SERVICE_ENABLE
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("Multithreading is running at function TestAllFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestOn,
        &TestOff,
        &TestCallback,
        &TestLoadExtSuccess,
        &TestSendExtensionEvent,
        &TestCancelUserPrintJobs,
        &TestBlockUserPrintJobs,
        &TestIsDisablePrint,
        &TestReportBannedEvent,
    };
    TestHandler handler = dataProvider->PickValueInArray(tasks);
    handler(data, size, dataProvider);
}

}  // namespace Print
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Print::U32_AT_SIZE) {
    }

    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}