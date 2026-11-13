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
#include "printcupsattribute_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_cups_attribute.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int MAX_DIMENSION = 100000;
constexpr int MAX_KEYWORD_COUNT = 8;

void TestParsePrinterStatusAttributes(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    ipp_t *response = ippNew();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string jobName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ippAddString(response, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, printerUri.c_str());
    ippAddString(response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-name", NULL, jobName.c_str());
    ippAddInteger(response, IPP_TAG_JOB, IPP_TAG_INTEGER, "copies",
        dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
    OHOS::Print::ParsePrinterStatusAttributes(response, status);
    ippDelete(response);
}

void TestParsePrinterAttributes(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    ipp_t *response = ippNew();
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string jobName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ippAddString(response, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, printerUri.c_str());
    ippAddString(response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-name", NULL, jobName.c_str());
    ippAddInteger(response, IPP_TAG_JOB, IPP_TAG_INTEGER, "copies",
        dataProvider->ConsumeIntegralInRange<int>(0, MAX_SET_NUMBER));
    PrinterCapability printerCaps;
    OHOS::Print::ParsePrinterAttributesFromIPP(response, printerCaps);
    ippDelete(response);
}

// Append fuzzed custom_min_/custom_max_ keyword bounds to media-supported.
static void AppendMediaSupportedKeywords(ipp_t *response, FuzzedDataProvider *dataProvider)
{
    int keywordCount = dataProvider->ConsumeIntegralInRange<int>(0, MAX_KEYWORD_COUNT);
    if (keywordCount <= 0) {
        return;
    }
    std::vector<const char *> mediaKeywords;
    std::vector<std::string> mediaStrings;
    for (int i = 0; i < keywordCount; ++i) {
        std::string bound = dataProvider->ConsumeBool() ? "custom_min_" : "custom_max_";
        int w = dataProvider->ConsumeIntegralInRange<int>(0, MAX_DIMENSION);
        int h = dataProvider->ConsumeIntegralInRange<int>(0, MAX_DIMENSION);
        std::string unit = dataProvider->ConsumeBool() ? "mm" : "in";
        mediaStrings.push_back(bound + std::to_string(w) + "x" + std::to_string(h) + unit);
    }
    for (const auto &s : mediaStrings) {
        mediaKeywords.push_back(s.c_str());
    }
    ippAddStrings(response, IPP_TAG_PRINTER, IPP_TAG_KEYWORD, "media-supported",
        static_cast<int>(mediaKeywords.size()), nullptr, mediaKeywords.data());
}

// Fuzz ParseCustomPageSizeRangeFromIPP: feed fuzzed media-supported keyword bounds to the parser.
void TestParseCustomPageSizeRange(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    ipp_t *response = ippNew();
    if (response == nullptr) {
        return;
    }
    AppendMediaSupportedKeywords(response, dataProvider);
    Json::Value options;
    OHOS::Print::ParseCustomPageSizeRangeFromIPP(response, options);
    ippDelete(response);
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

    if (size < OHOS::Print::U32_AT_SIZE || size > OHOS::Print::FOO_MAX_LEN) {
    }

    FuzzedDataProvider dataProvider(data, size);
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    PRINT_HILOGI("Multithreading is running in function LLVMFuzzerTestOneInput.");
    TestHandler tasks[] = {
        &OHOS::Print::TestParsePrinterStatusAttributes,
        &OHOS::Print::TestParsePrinterAttributes,
        &OHOS::Print::TestParseCustomPageSizeRange
    };
    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
