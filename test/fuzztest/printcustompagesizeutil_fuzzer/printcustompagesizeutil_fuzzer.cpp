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

#include "printcustompagesizeutil_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_custom_page_size_util.h"
#include "print_json_util.h"
#include <functional>
#include <vector>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 100;
constexpr int MAX_PAGE_SIZE_COUNT = 10;
constexpr size_t U32_AT_SIZE = 4;

void TestUpdateOptionWithParsedInput(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_PAGE_SIZE_COUNT);
    if (count > 0) {
        std::vector<PrintPageSize> sizes;
        for (int i = 0; i < count; ++i) {
            sizes.emplace_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
                dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
                dataProvider->ConsumeIntegral<uint32_t>(), dataProvider->ConsumeIntegral<uint32_t>());
        }
        userPrefs.SetCustomPageSizes(sizes);
    }
    PrinterPreferences pref;
    std::string option = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    pref.SetOption(option);
    Json::Value opsJson(Json::objectValue);
    bool hasValidOption = !option.empty() && PrintJsonUtil::Parse(option, opsJson);
    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, hasValidOption);
}

void TestUpdateOptionWithMismatchedFlag(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> sizes;
    sizes.emplace_back(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
        dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH),
        dataProvider->ConsumeIntegral<uint32_t>(), dataProvider->ConsumeIntegral<uint32_t>());
    userPrefs.SetCustomPageSizes(sizes);
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);
    opsJson[dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH)] =
        dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    bool hasValidOption = dataProvider->ConsumeBool();
    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, hasValidOption);
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestUpdateOptionWithParsedInput,
        &TestUpdateOptionWithMismatchedFlag,
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
