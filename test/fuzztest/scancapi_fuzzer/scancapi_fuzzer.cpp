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

#include <functional>
#include "fuzzer/FuzzedDataProvider.h"
#include "ohscan.h"
#include "scancapi_fuzzer.h"


namespace OHOS {
namespace Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void OHScanInitFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    OH_Scan_Init();
}

void DiscoveryCallBack(Scan_ScannerDevice** devices, int32_t deviceCount) {}

void OHScanStartScannerDiscoveryFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    OH_Scan_StartScannerDiscovery(DiscoveryCallBack);
}

void OHScanOpenScannerFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Scan_OpenScanner(scannerId.c_str());
}

void OHScanCloseScannerFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Scan_CloseScanner(scannerId.c_str());
}

void OHScanGetScannerParameterFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t errorCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    OH_Scan_GetScannerParameter(scannerId.c_str(), &errorCode);
}

void OHScanSetScannerParameterFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t option = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::string value = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Scan_SetScannerParameter(scannerId.c_str(), option, value.c_str());
}

void OHScanStartScanFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    bool batchMode = dataProvider->ConsumeBool();
    OH_Scan_StartScan(scannerId.c_str(), batchMode);
}

void OHScanCancelScanFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Scan_CancelScan(scannerId.c_str());
}

void OHScanGetScanPictureProgressFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    Scan_PictureScanProgress progress;
    progress.progress = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    progress.fd = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    progress.isFinal = dataProvider->ConsumeBool();
    OH_Scan_GetPictureScanProgress(scannerId.c_str(), &progress);
}

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
    OHOS::Scan::OHScanInitFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanStartScannerDiscoveryFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanOpenScannerFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanCloseScannerFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanGetScannerParameterFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanSetScannerParameterFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanStartScanFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanCancelScanFuzzTest(data, size, &dataProvider);
    OHOS::Scan::OHScanGetScanPictureProgressFuzzTest(data, size, &dataProvider);
    return 0;
}

