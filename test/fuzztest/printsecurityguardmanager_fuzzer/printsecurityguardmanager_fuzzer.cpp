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

#include "printsecurityguardmanager_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_security_guard_manager.h"
#include "print_constant.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 50;
constexpr int MAX_SET_NUMBER = 10;
constexpr uint32_t MAX_DUPLEX_MODE = 5;
constexpr uint32_t MAX_SUB_STATE = 100;
constexpr int MAX_JOB_COUNT = 5;
constexpr size_t U32_AT_SIZE = 4;

void TestReceiveBaseInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSecurityGuardManager manager;
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string callerPkg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    for (int i = 0; i < count; ++i) {
        fileList.push_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    }
    manager.receiveBaseInfo(jobId, callerPkg, fileList);
}

void TestReceiveAuditInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSecurityGuardManager manager;
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    manager.receiveBaseInfo(jobId, "callerPkg", fileList);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    PrintJob printJob;
    printJob.SetDuplexMode(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_DUPLEX_MODE));
    printJob.SetSubState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SUB_STATE));

    std::vector<std::string> fileInfos;
    int fileCount = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    for (int i = 0; i < fileCount; ++i) {
        fileInfos.push_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    }
    manager.receiveAuditInfo(jobId, printerInfo, printJob, fileInfos);
}

void TestReceiveJobStateUpdate(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSecurityGuardManager manager;
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    manager.receiveBaseInfo(jobId, "callerPkg", fileList);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    PrintJob printJob;
    printJob.SetSubState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SUB_STATE));

    manager.receiveJobStateUpdate(jobId, printerInfo, printJob);
}

void TestFullAuditFlow(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSecurityGuardManager manager;
    std::string jobId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string callerPkg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<std::string> fileList;
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    for (int i = 0; i < count; ++i) {
        fileList.push_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    }
    manager.receiveBaseInfo(jobId, callerPkg, fileList);

    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    PrintJob printJob;
    printJob.SetDuplexMode(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_DUPLEX_MODE));
    printJob.SetSubState(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SUB_STATE));

    std::vector<std::string> fileInfos;
    int fileCount = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER);
    for (int i = 0; i < fileCount; ++i) {
        fileInfos.push_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    }
    manager.receiveAuditInfo(jobId, printerInfo, printJob, fileInfos);
    manager.receiveJobStateUpdate(jobId, printerInfo, printJob);
}

void TestClearAll(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSecurityGuardManager manager;
    std::vector<std::string> fileList;
    int jobCount = dataProvider->ConsumeIntegralInRange<int>(1, MAX_JOB_COUNT);
    for (int i = 0; i < jobCount; ++i) {
        manager.receiveBaseInfo(
            "job-" + std::to_string(i),
            dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
            fileList);
    }
    manager.clearAll();
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestReceiveBaseInfo,
        &TestReceiveAuditInfo,
        &TestReceiveJobStateUpdate,
        &TestFullAuditFlow,
        &TestClearAll,
    };
    TestHandler handler = dataProvider->PickValueInArray(tasks);
    handler(data, size, dataProvider);
}

}  // namespace Print
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < OHOS::Print::U32_AT_SIZE) {
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
