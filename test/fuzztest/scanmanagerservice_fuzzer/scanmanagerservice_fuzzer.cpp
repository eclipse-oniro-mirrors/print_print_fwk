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
#include "scan_constant.h"
#include "scanmanagerservice_fuzzer.h"
#include "print_log.h"
#include "ipc_object_stub.h"
#include <functional>

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t FUZZ_MAX_SCAN_FORMAT_TYPE = 10;

void TestExportScanPicture(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fdCount = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::vector<int32_t> pictureFdList;
    for (int32_t i = 0; i < fdCount; i++) {
        int32_t fd = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER);
        pictureFdList.push_back(fd);
    }
    int32_t format = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, FUZZ_MAX_SCAN_FORMAT_TYPE);
    std::vector<int32_t> exportedFdList;
    scanManagerPtr->ExportScanPicture(scannerId, pictureFdList, format, exportedFdList);
}

void TestLoadServerFail(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->LoadServerFail();
}

void TestOnRemoteSaDied(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto scanManagerPtr = ScanManagerClient::GetInstance();
    if (scanManagerPtr == nullptr) {
        return;
    }
    scanManagerPtr->OnRemoteSaDied(nullptr);
    sptr<IPCObjectStub> stub = new IPCObjectStub(u"test_scan_remote");
    wptr<IRemoteObject> weakObj = stub;
    scanManagerPtr->OnRemoteSaDied(weakObj);
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
    }
    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestExportScanPicture,
        &OHOS::Scan::TestLoadServerFail,
        &OHOS::Scan::TestOnRemoteSaDied
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
