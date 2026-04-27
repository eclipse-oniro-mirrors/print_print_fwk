/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "fuzzer/FuzzedDataProvider.h"
#include "scanpicturedata_fuzzer.h"
#include "scan_picture_data.h"
#include "scan_progress.h"
#include "scan_constant.h"
#include "print_log.h"
#include <functional>

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestSetScanProgr(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    int64_t totalBytes = dataProvider->ConsumeIntegralInRange<int64_t>(0, MAX_SET_NUMBER);
    int64_t hundredPercent = dataProvider->ConsumeIntegralInRange<int64_t>(0, MAX_SET_NUMBER);
    int32_t curReadSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetScanProgr(totalBytes, hundredPercent, curReadSize);
    instance.CleanPictureData();
}

void TestSetScanTaskCode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    int32_t taskCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetScanTaskCode(taskCode);
    instance.CleanPictureData();
}

void TestSetNowScanProgressFinished(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    bool isFinal = dataProvider->ConsumeBool();
    instance.SetNowScanProgressFinished(isFinal);
    instance.CleanPictureData();
}

void TestSetLastScanProgressFinished(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    instance.PushScanPictureProgress();
    instance.SetLastScanProgressFinished();
    instance.CleanPictureData();
}

void TestSetImageRealPath(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    std::string filePath = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    instance.SetImageRealPath(filePath);
    instance.CleanPictureData();
}

void TestSetCallerPid(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    int32_t callerPid = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetCallerPid(callerPid);
    instance.CleanPictureData();
}

void TestGetPictureProgressInQueue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    int32_t callerPid = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetCallerPid(callerPid);
    instance.PushScanPictureProgress();
    ScanProgress scanProgress;
    instance.GetPictureProgressInQueue(scanProgress, callerPid);
    instance.CleanPictureData();
}

void TestCleanPictureData(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    instance.CleanPictureData();
}

void TestPushScanPictureProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    instance.PushScanPictureProgress();
    instance.PushScanPictureProgress();
    instance.CleanPictureData();
}

void TestFullWorkflow(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto& instance = ScanPictureData::GetInstance();
    int32_t callerPid = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetCallerPid(callerPid);
    instance.PushScanPictureProgress();
    std::string filePath = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    instance.SetImageRealPath(filePath);
    int32_t taskCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetScanTaskCode(taskCode);
    int64_t totalBytes = dataProvider->ConsumeIntegralInRange<int64_t>(0, MAX_SET_NUMBER);
    int64_t hundredPercent = dataProvider->ConsumeIntegralInRange<int64_t>(1, MAX_SET_NUMBER);
    int32_t curReadSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    instance.SetScanProgr(totalBytes, hundredPercent, curReadSize);
    bool isFinal = dataProvider->ConsumeBool();
    instance.SetNowScanProgressFinished(isFinal);
    ScanProgress scanProgress;
    instance.GetPictureProgressInQueue(scanProgress, callerPid);
    instance.CleanPictureData();
}
}

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
    OHOS::Scan::TestSetScanProgr(data, size, &dataProvider);
    OHOS::Scan::TestSetScanTaskCode(data, size, &dataProvider);
    OHOS::Scan::TestSetNowScanProgressFinished(data, size, &dataProvider);
    OHOS::Scan::TestSetLastScanProgressFinished(data, size, &dataProvider);
    OHOS::Scan::TestSetImageRealPath(data, size, &dataProvider);
    OHOS::Scan::TestSetCallerPid(data, size, &dataProvider);
    OHOS::Scan::TestGetPictureProgressInQueue(data, size, &dataProvider);
    OHOS::Scan::TestCleanPictureData(data, size, &dataProvider);
    OHOS::Scan::TestPushScanPictureProgress(data, size, &dataProvider);
    OHOS::Scan::TestFullWorkflow(data, size, &dataProvider);
    return 0;
}