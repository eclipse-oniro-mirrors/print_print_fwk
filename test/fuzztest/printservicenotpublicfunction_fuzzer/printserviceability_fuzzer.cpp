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
#include "printer_capability.h"
#include "printer_preferences.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"
#include "print_callback.h"
#include "iprint_adapter_inner.h"
#include "printer_user_preferences.h"
#include "print_vendor_options_util.h"
#include "print_json_util.h"
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

void TestCheckIsDefaultPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsDefaultPrinter(printerId);
}

void TestCheckIsLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->CheckIsLastUsedPrinter(printerName);
}

void TestSetLastUsedPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->SetLastUsedPrinter(printerId);
}

void TestSendPrintJobEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintJob jobInfo;
    uint32_t jobStateArr[] = {PRINT_JOB_COMPLETED, PRINT_JOB_BLOCKED, PRINT_JOB_COMPLETED};
    for (auto jobState : jobStateArr) {
        jobInfo.SetJobState(jobState);
        PrintServiceAbility::GetInstance()->SendPrintJobEvent(jobInfo);
    }
    uint32_t jobState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    jobInfo.SetJobState(jobState);
    PrintServiceAbility::GetInstance()->SendPrintJobEvent(jobInfo);
}

void TestStartPrintJobCB(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->StartPrintJobCB(jobId, printJob);
}

void TestCheckPrinterUriDifferent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo->SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->CheckPrinterUriDifferent(printerInfo);
}

void TestUpdatePrinterCapability(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->UpdatePrinterCapability(printerId, printerInfo);
}

void TestReportCompletedPrint(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ReportCompletedPrint(printerId);
}

void TestNotifyAppJobQueueChanged(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string applyResult = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->NotifyAppJobQueueChanged(applyResult);
}

void TestSendPrinterChangeEvent(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    int event = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetDescription(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    PrintServiceAbility::GetInstance()->SendPrinterChangeEvent(event, printerInfo);
    PrintServiceAbility::GetInstance()->DestroyExtension();
}

void TestCheckJobQueueBlocked(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintJob printJob;
    printJob.SetJobId(jobId);
    printJob.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->CheckJobQueueBlocked(printJob);
}

void TestGetListeningState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    uint32_t subState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetListeningState(subState);
    uint32_t state = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    PrintServiceAbility::GetInstance()->GetListeningState(state, subState);
}

void TestUpdatePageSizeNameWithPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string pageSizeId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintPageSize pageSize;
    pageSize.SetId(pageSizeId);
    PrinterInfo printerInfo;
    PrintServiceAbility::GetInstance()->UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
}

void TestUpdatePrintJobOptionWithPrinterPreferences(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    Json::Value jobOptions;
    jobOptions[key] = value;
    PrinterInfo printerInfo;
    PrinterPreferences preferences;
    printerInfo.SetPreferences(preferences);
    PrintServiceAbility::GetInstance()->UpdatePrintJobOptionWithPrinterPreferences(jobOptions, printerInfo);
}

void TestConnectUsbPrinter(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ConnectUsbPrinter(printerId);
}

void TestClosePrintJobFd(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId(jobId);
    printJob->SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrintServiceAbility::GetInstance()->ClosePrintJobFd(printJob);
}

void TestMergeVendorOptionsForPrintJob(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    PrinterPreferences preferences;
    std::string vendorOptions = R"({"colorMode":"color","paperSize":"A4"})";
    preferences.SetVendorOptions(vendorOptions);

    PrintJob printJob;
    printJob.SetJobId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printJob.SetPrinterId(printerInfo.GetPrinterId());
    
    PrintServiceAbility::GetInstance()->MergeVendorOptionsForPrintJob(printerInfo, preferences, printJob);
}

void TestProcessVendorOptionsForPreference(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    PrinterPreferences preferences;
    std::string vendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    preferences.SetVendorOptions(vendorOptions);

    PrinterPreferences printerPrefs;
    PrintServiceAbility::GetInstance()->ProcessVendorOptionsForPreference(
        printerId, preferences, printerPrefs);
}

void TestNoParmFuncs(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintServiceAbility::GetInstance()->DelayEnterLowPowerMode();
    PrintServiceAbility::GetInstance()->ExitLowPowerMode();
    PrintServiceAbility::GetInstance()->UnloadSystemAbility();
}

void TestExtractCustomOptionsFromPreferences(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    PrinterCapability capability;
    std::string capOption = "{\"cupsOptions\":{\"advanceOptions\":\"[]\"}}";
    capability.SetOption(capOption);
    printerInfo.SetCapability(capability);
    
    PrinterPreferences preferences;
    std::string prefOption = "{\"testKey\":\"testValue\"}";
    preferences.SetOption(prefOption);
    
    PrinterUserPreferences userPrefs;
    PrintServiceAbility::GetInstance()->ExtractCustomOptionsFromPreferences(printerInfo, preferences, userPrefs);
}

void TestGetCustomOptionKeys(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterCapability capability;
    std::string capOption = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    capability.SetOption(capOption);
    
    capability.GetCustomOptionKeys();
}

void TestExtractCustomOptionsFromPreferenceJson(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::set<std::string> customOptionKeys;
    customOptionKeys.insert(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    customOptionKeys.insert(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    
    PrinterPreferences preferences;
    std::string prefOption = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    preferences.SetOption(prefOption);
    
    PrinterUserPreferences userPrefs;
    PrintServiceAbility::GetInstance()->
        ExtractCustomOptionsFromPreferenceJson(customOptionKeys, preferences, userPrefs);
}

void TestFillCustomOptionsToJson(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    std::string valueStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    SecureBlob value;
    value.SetData((const uint8_t *)valueStr.c_str(), valueStr.size());
    userPrefs.SetCustomOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH), value);
    Json::Value opsJson;
    PrintServiceAbility::GetInstance()->FillCustomOptionsToJson(userPrefs, opsJson);
}

void TestProcessSingleCustomOption(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    
    PrinterUserPreferences userPrefs;
    
    std::string choice = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    
    Json::Value optionJson;
    optionJson["choice"] = choice;
    optionJson["value"] = value;
    std::string optionJsonStr = PrintJsonUtil::WriteString(optionJson);
    
    PrintServiceAbility::GetInstance()->ProcessSingleCustomOption(key, optionJsonStr, userPrefs);
    
    std::string invalidJsonStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintServiceAbility::GetInstance()->ProcessSingleCustomOption(key, invalidJsonStr, userPrefs);
    
    std::string emptyValueJson = "{\"choice\":\"Custom\",\"value\":\"\"}";
    PrintServiceAbility::GetInstance()->ProcessSingleCustomOption(key, emptyValueJson, userPrefs);
    
    std::string nonCustomEmptyJson = "{\"choice\":\"Standard\",\"value\":\"\"}";
    PrintServiceAbility::GetInstance()->ProcessSingleCustomOption(key, nonCustomEmptyJson, userPrefs);
}

void TestPrinterUserPreferencesSetGetUserId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    userPrefs.SetUserId(userId);
    userPrefs.GetUserId();
}

void TestPrinterUserPreferencesSetGetPrinterId(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    userPrefs.SetPrinterId(printerId);
    userPrefs.GetPrinterId();
}

void TestPrinterUserPreferencesVendorOptions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    std::string vendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    userPrefs.SetVendorOptions(vendorOptions);
    userPrefs.GetVendorOptions();
    userPrefs.HasVendorOptions();
}

void TestPrinterUserPreferencesCustomOption(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string valueStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    SecureBlob value;
    value.SetData((const uint8_t *)valueStr.c_str(), valueStr.size());
    userPrefs.SetCustomOption(key, value);
    userPrefs.SetCustomOptionUnset(key);
    SecureBlob retrievedValue;
    userPrefs.GetCustomOption(key, retrievedValue);
    userPrefs.IsCustomOptionSet(key);
    userPrefs.RemoveCustomOption(key);
    userPrefs.GetAllCustomOptions();
}

void TestPrinterUserPreferencesJsonRoundtrip(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER));
    userPrefs.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    userPrefs.SetVendorOptions(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    Json::Value json = userPrefs.ConvertToJson();
    PrinterUserPreferences restored;
    restored.ConvertFromJson(json);
}

void TestPrinterUserPreferencesIsEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    userPrefs.SetUserId(dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER));
    userPrefs.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string vendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    userPrefs.SetVendorOptions(vendorOptions);
    userPrefs.IsEmpty();
    userPrefs.Dump();
}

void TestSecureBlobOperations(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string dataStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    SecureBlob blob1;
    blob1.SetData((const uint8_t *)dataStr.c_str(), dataStr.size());
    blob1.IsEmpty();
    blob1.ToString();
    SecureBlob blob2(blob1);
    SecureBlob blob3 = blob1;
    SecureBlob blob4(std::move(blob1));
    SecureBlob blob5 = std::move(blob2);
    blob3.Clear();
}

void TestSplitVendorOptions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string vendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerVendorOptions;
    std::string userVendorOptions;
    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);
}

void TestMergeVendorOptions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string defaultVendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string overrideVendorOptions = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(defaultVendorOptions, overrideVendorOptions);
}

void TestIsUserField(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrintVendorOptionsUtil::IsUserField(key);
}

void TestClassifyFields(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Json::Value vendorJson;
    std::string key1 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value1 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    vendorJson[key1] = value1;
    std::string key2 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value2 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    vendorJson[key2] = value2;
    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);
}

void TestNotPublicFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PRINT_HILOGI("multithreading is running at function TestNotPublicFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestCheckIsDefaultPrinter,
        &TestCheckIsLastUsedPrinter,
        &TestSetLastUsedPrinter,
        &TestSendPrintJobEvent,
        &TestStartPrintJobCB,
        &TestCheckPrinterUriDifferent,
        &TestUpdatePrinterCapability,
        &TestReportCompletedPrint,
        &TestNotifyAppJobQueueChanged,
        &TestSendPrinterChangeEvent,
        &TestCheckJobQueueBlocked,
        &TestGetListeningState,
        &TestUpdatePageSizeNameWithPrinterInfo,
        &TestUpdatePrintJobOptionWithPrinterPreferences,
        &TestConnectUsbPrinter,
        &TestClosePrintJobFd,
        &TestMergeVendorOptionsForPrintJob,
        &TestProcessVendorOptionsForPreference,
        &TestNoParmFuncs,
        &TestExtractCustomOptionsFromPreferences,
        &TestGetCustomOptionKeys,
        &TestExtractCustomOptionsFromPreferenceJson,
        &TestFillCustomOptionsToJson,
        &TestProcessSingleCustomOption,
        &TestPrinterUserPreferencesSetGetUserId,
        &TestPrinterUserPreferencesSetGetPrinterId,
        &TestPrinterUserPreferencesVendorOptions,
        &TestPrinterUserPreferencesCustomOption,
        &TestPrinterUserPreferencesJsonRoundtrip,
        &TestPrinterUserPreferencesIsEmpty,
        &TestSecureBlobOperations,
        &TestSplitVendorOptions,
        &TestMergeVendorOptions,
        &TestIsUserField,
        &TestClassifyFields,
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
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::TestNotPublicFunction(data, size, &dataProvider);
    return 0;
}
