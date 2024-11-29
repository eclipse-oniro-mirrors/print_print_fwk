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

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

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
    OHOS::Print::ParsePrinterAttributes(response, printerCaps);
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
    OHOS::Print::TestParsePrinterStatusAttributes(data, size, &dataProvider);
    OHOS::Print::TestParsePrinterAttributes(data, size, &dataProvider);
    
    return 0;
}
