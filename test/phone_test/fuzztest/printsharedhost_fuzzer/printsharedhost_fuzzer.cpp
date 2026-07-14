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

#include "printsharedhost_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_shared_host.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr size_t U32_AT_SIZE = 4;

void TestGetIp(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sharedHost.SetIp(ip);
    auto result = sharedHost.GetIp();
    (void)result;
}

void TestGetShareName(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string shareName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sharedHost.SetShareName(shareName);
    auto result = sharedHost.GetShareName();
    (void)result;
}

void TestGetWorkgroupName(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string workgroupName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sharedHost.SetWorkgroupName(workgroupName);
    auto result = sharedHost.GetWorkgroupName();
    (void)result;
}

void TestReadFromParcel(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string shareName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string workgroupName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    Parcel parcel;
    parcel.WriteString(ip);
    parcel.WriteString(shareName);
    parcel.WriteString(workgroupName);
    bool result = sharedHost.ReadFromParcel(parcel);
    (void)result;
}

void TestReadFromParcelEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    Parcel emptyParcel;
    bool result = sharedHost.ReadFromParcel(emptyParcel);
    (void)result;
}

void TestMarshalling(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string shareName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string workgroupName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sharedHost.SetIp(ip);
    sharedHost.SetShareName(shareName);
    sharedHost.SetWorkgroupName(workgroupName);

    Parcel parcel;
    bool result = sharedHost.Marshalling(parcel);
    (void)result;
}

void TestMarshallingEmpty(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    Parcel parcel;
    bool result = sharedHost.Marshalling(parcel);
    (void)result;
}

void TestUnmarshalling(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string shareName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string workgroupName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    Parcel parcel;
    parcel.WriteString(ip);
    parcel.WriteString(shareName);
    parcel.WriteString(workgroupName);
    auto result = PrintSharedHost::Unmarshalling(parcel);
    (void)result;
}

void TestDump(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintSharedHost sharedHost;
    std::string ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string shareName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string workgroupName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    sharedHost.SetIp(ip);
    sharedHost.SetShareName(shareName);
    sharedHost.SetWorkgroupName(workgroupName);
    sharedHost.Dump();
}

void TestAllFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestGetIp,
        &TestGetShareName,
        &TestGetWorkgroupName,
        &TestReadFromParcel,
        &TestReadFromParcelEmpty,
        &TestMarshalling,
        &TestMarshallingEmpty,
        &TestUnmarshalling,
        &TestDump,
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
