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
#include "fuzzer/FuzzedDataProvider.h"
#include "scan_manager_client.h"
#include "scan_callback.h"
#include "scanner_info.h"
#include "scanmanagerclient_fuzzer.h"
#include "print_log.h"
#include <functional>

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestGetScannerList(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->InitScan();
    scanManagerPtr->GetScannerList();
    scanManagerPtr->ExitScan();
}

void TestGetScanOptionDesc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->InitScan();
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanOptionDescriptor desc;
    scanManagerPtr->OpenScanner(scannerId);
    scanManagerPtr->GetScanOptionDesc(scannerId, optionIndex, desc);
    scanManagerPtr->CloseScanner(scannerId);
    scanManagerPtr->ExitScan();
}

void TestOpScanOptionValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->InitScan();
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    auto op = static_cast<ScanOptionOpType>(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    ScanOptionValue value;
    scanManagerPtr->OpenScanner(scannerId);
    scanManagerPtr->OpScanOptionValue(scannerId, optionIndex, op, value);
    scanManagerPtr->CloseScanner(scannerId);
    scanManagerPtr->ExitScan();
}

void TestGetScanParameters(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->InitScan();
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanParameters para;
    scanManagerPtr->OpenScanner(scannerId);
    scanManagerPtr->GetScanParameters(scannerId, para);
    scanManagerPtr->CloseScanner(scannerId);
    scanManagerPtr->ExitScan();
}

void TestStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->InitScan();
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    bool batchMode = dataProvider->ConsumeBool();
    scanManagerPtr->OpenScanner(scannerId);
    scanManagerPtr->StartScan(scannerId, batchMode);
    scanManagerPtr->CancelScan(scannerId);
    scanManagerPtr->CloseScanner(scannerId);
    scanManagerPtr->ExitScan();
}

void TestOn(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction;
    sptr<IScanCallback> listener = new (std::nothrow) ScanCallback(callbackFunction);
    if (listener == nullptr) {
        return;
    }
    scanManagerPtr->On(taskId, type, listener);
}

void TestOff(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanManagerPtr->Off(taskId, type);
}

void TestGetScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanProgress prog;
    scanManagerPtr->GetScanProgress(scannerId, prog);
}

void TestAddScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanManagerPtr->AddScanner(serialNumber, discoverMode);
}

void TestDeleteScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanManagerPtr->DeleteScanner(serialNumber, discoverMode);
}

void TestGetAddedScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    int32_t count = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::vector<ScanDeviceInfo> allAddedScanner(count);
    scanManagerPtr->GetAddedScanner(allAddedScanner);
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestGetScannerList,
        &OHOS::Scan::TestGetScanOptionDesc,
        &OHOS::Scan::TestOpScanOptionValue,
        &OHOS::Scan::TestGetScanParameters,
        &OHOS::Scan::TestStartScan,
        &OHOS::Scan::TestOn,
        &OHOS::Scan::TestOff,
        &OHOS::Scan::TestGetScanProgress,
        &OHOS::Scan::TestAddScanner,
        &OHOS::Scan::TestDeleteScanner,
        &OHOS::Scan::TestGetAddedScanner
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}

