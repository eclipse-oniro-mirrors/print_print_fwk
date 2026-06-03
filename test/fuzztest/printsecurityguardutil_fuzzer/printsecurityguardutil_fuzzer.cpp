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

#include "printsecurityguardutil_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_security_guard_util.h"
#include "print_constant.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 100;
constexpr int MAX_SUB_STATE_COUNT = 10;
constexpr uint32_t MAX_SUB_STATE_CODE = 200;
constexpr size_t U32_AT_SIZE = 4;

void TestGenerateErrorCodes(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::set<uint32_t> subStates;
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_SUB_STATE_COUNT);
    for (int i = 0; i < count; ++i) {
        subStates.insert(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SUB_STATE_CODE));
    }
    auto result = GenerateErrorCodes(subStates);
    // Just verify no crash
    (void)result;
}

void TestExtractFileName(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string filePath = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto result = PrintSecurityGuardUtil::ExtractFileName(filePath);
    (void)result;
}

void TestExtractFileListFromOption(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto result = PrintSecurityGuardUtil::ExtractFileListFromOption(option);
    (void)result;
}

void TestGetPrinterType(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string des = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto result = PrintSecurityGuardUtil::GetPrinterType(des);
    (void)result;
}

void TestIsPrintableFile(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string fileName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    auto result = PrintSecurityGuardUtil::IsPrintableFile(fileName);
    (void)result;
}

void TestGenerateErrorCodesWithCombinedState(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::set<uint32_t> subStates;
    // Generate possibly combined subState codes (>99)
    uint32_t combinedState = dataProvider->ConsumeIntegral<uint32_t>();
    subStates.insert(combinedState);
    auto result = GenerateErrorCodes(subStates);
    (void)result;
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestGenerateErrorCodes,
        &TestExtractFileName,
        &TestExtractFileListFromOption,
        &TestGetPrinterType,
        &TestIsPrintableFile,
        &TestGenerateErrorCodesWithCombinedState,
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
