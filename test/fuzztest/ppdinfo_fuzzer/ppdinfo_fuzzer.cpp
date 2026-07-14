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

#include "ppdinfo_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "ppd_info.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr size_t U32_AT_SIZE = 4;

void TestGetManufacturer(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ppdInfo.SetManufacturer(manufacturer);
    auto result = ppdInfo.GetManufacturer();
    (void)result;
}

void TestGetNickName(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    std::string nickName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ppdInfo.SetNickName(nickName);
    auto result = ppdInfo.GetNickName();
    (void)result;
}

void TestGetPpdName(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ppdInfo.SetPpdName(ppdName);
    auto result = ppdInfo.GetPpdName();
    (void)result;
}

void TestReadFromParcel(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nickName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    Parcel parcel;
    parcel.WriteString(manufacturer);
    parcel.WriteString(nickName);
    parcel.WriteString(ppdName);
    bool result = ppdInfo.ReadFromParcel(parcel);
    (void)result;
}

void TestReadFromParcelEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    Parcel emptyParcel;
    bool result = ppdInfo.ReadFromParcel(emptyParcel);
    (void)result;
}

void TestMarshalling(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nickName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ppdInfo.SetPpdInfo(manufacturer, nickName, ppdName);

    Parcel parcel;
    bool result = ppdInfo.Marshalling(parcel);
    (void)result;
}

void TestMarshallingEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PpdInfo ppdInfo;
    Parcel parcel;
    bool result = ppdInfo.Marshalling(parcel);
    (void)result;
}

void TestUnmarshalling(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nickName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    Parcel parcel;
    parcel.WriteString(manufacturer);
    parcel.WriteString(nickName);
    parcel.WriteString(ppdName);
    auto result = PpdInfo::Unmarshalling(parcel);
    (void)result;
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestGetManufacturer,
        &TestGetNickName,
        &TestGetPpdName,
        &TestReadFromParcel,
        &TestReadFromParcelEmpty,
        &TestMarshalling,
        &TestMarshallingEmpty,
        &TestUnmarshalling,
    };
    TestHandler handler = dataProvider->PickValueInArray(tasks);
    handler(data, size, dataProvider);
}

}  // namespace Print
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < OHOS::Print::U32_AT_SIZE) {
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::TestAllFunction(data, size, &dataProvider);
    return 0;
}
