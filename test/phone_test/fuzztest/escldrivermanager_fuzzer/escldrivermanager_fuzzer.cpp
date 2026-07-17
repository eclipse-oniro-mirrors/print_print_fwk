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

#define private public
#include "fuzzer/FuzzedDataProvider.h"
#include "escldrivermanager_fuzzer.h"
#include "escl_driver_manager.h"
#include "scan_discover_data.h"
#include "print_log.h"
#include <functional>

namespace OHOS {
namespace Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int32_t FUZZ_MAX_TCP_PORT = 65535;
constexpr int32_t FUZZ_TCP_PORT_OVER_MAX = 65536;
constexpr int32_t FUZZ_TCP_PORT_UNDER_MIN = -1;

void TestGenerateEsclScannerInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP rawInfo;
    rawInfo.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    rawInfo.port = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    rawInfo.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanDeviceInfo info;
    EsclDriverManager::GenerateEsclScannerInfo(rawInfo, info);

    ScanDeviceInfoTCP rawInfoFmt;
    rawInfoFmt.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    rawInfoFmt.port = std::to_string(dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_TCP_PORT));
    rawInfoFmt.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanDeviceInfo infoFmt;
    EsclDriverManager::GenerateEsclScannerInfo(rawInfoFmt, infoFmt);
}

void TestIsEsclScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::IsEsclScanner(scannerId);

    std::string fuzzName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string fuzzIP = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fuzzPort = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_TCP_PORT);
    std::string validId = "airscan:eSCL:" + fuzzName + ":http://" + fuzzIP + ":" + std::to_string(fuzzPort) + "/eSCL/";
    EsclDriverManager::IsEsclScanner(validId);

    std::string nonEsclId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::IsEsclScanner(nonEsclId);
}

 void TestExtractIpAndPort(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
 {
     std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
     std::string ipAddress;
     int32_t portNumber = 0;
     EsclDriverManager::ExtractIpAndPort(scannerId, ipAddress, portNumber);
 }

void TestExtractIpAndPortWithValidFormat(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string fuzzIP = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fuzzPort = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_TCP_PORT);
    std::string validId = "http://" + fuzzIP + ":" + std::to_string(fuzzPort) + "/eSCL/";
    std::string ipAddress;
    int32_t portNumber = 0;
    EsclDriverManager::ExtractIpAndPort(validId, ipAddress, portNumber);

    std::string invalidId1 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::ExtractIpAndPort(invalidId1, ipAddress, portNumber);

    std::string invalidId2 = "http://" + dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::ExtractIpAndPort(invalidId2, ipAddress, portNumber);

    std::string fuzzId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::ExtractIpAndPort(fuzzId, ipAddress, portNumber);
}

void TestExtractIpAndPortWithEdgeCases(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string ipAddress;
    int32_t portNumber = 0;

    std::string fuzzIP = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fuzzPort = dataProvider->ConsumeIntegralInRange<int32_t>(FUZZ_TCP_PORT_UNDER_MIN, FUZZ_TCP_PORT_OVER_MAX);
    std::string edgeId = "http://" + fuzzIP + ":" + std::to_string(fuzzPort) + "/eSCL/";
    EsclDriverManager::ExtractIpAndPort(edgeId, ipAddress, portNumber);

    std::string fuzzPortStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string fuzzIP2 = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string nonNumericId = "http://" + fuzzIP2 + ":" + fuzzPortStr + "/eSCL/";
    EsclDriverManager::ExtractIpAndPort(nonNumericId, ipAddress, portNumber);

    std::string fuzzId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::ExtractIpAndPort(fuzzId, ipAddress, portNumber);
}

void TestAddEsclScannerInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string uniqueId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanDeviceInfo esclInfo;
    esclInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    esclInfo.uniqueId = uniqueId;
    esclInfo.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScannerDiscoverData::GetInstance().SetEsclDevice(uniqueId, esclInfo);

    std::vector<ScanDeviceInfo> discoveredScanners;
    ScanDeviceInfo existing;
    existing.uniqueId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    discoveredScanners.push_back(existing);

    EsclDriverManager::AddEsclScannerInfo(discoveredScanners);
    ScannerDiscoverData::GetInstance().ClearEsclDevices();
}

void TestAddEsclScannerInfoNoDup(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string esclUid = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string fuzzIP = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fuzzPort = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_TCP_PORT);
    ScanDeviceInfo esclInfo;
    esclInfo.deviceId = "airscan:eSCL:" + dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH)
        + ":http://" + fuzzIP + ":" + std::to_string(fuzzPort) + "/eSCL/";
    esclInfo.uniqueId = esclUid;
    esclInfo.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScannerDiscoverData::GetInstance().SetEsclDevice(esclUid, esclInfo);

    std::vector<ScanDeviceInfo> discovered;
    ScanDeviceInfo existing;
    existing.uniqueId = esclUid;
    existing.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    discovered.push_back(existing);

    EsclDriverManager::AddEsclScannerInfo(discovered);

    std::vector<ScanDeviceInfo> discoveredNoDup;
    ScanDeviceInfo notDup;
    notDup.uniqueId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    discoveredNoDup.push_back(notDup);

    EsclDriverManager::AddEsclScannerInfo(discoveredNoDup);
    ScannerDiscoverData::GetInstance().ClearEsclDevices();
}

void TestInitializeEsclScannerDriver(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    EsclDriverManager::InitializeEsclScannerDriver();
}

void TestIsAdfMode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EsclDriverManager::IsAdfMode(scannerId);

    std::string fuzzName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string fuzzIP = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fuzzPort = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_TCP_PORT);
    std::string validId = "airscan:eSCL:" + fuzzName + ":http://" + fuzzIP + ":" + std::to_string(fuzzPort) + "/eSCL/";
    EsclDriverManager::IsAdfMode(validId);
}

void TestIsAdfEmpty(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string ipAddress = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t portNumber = dataProvider->ConsumeIntegralInRange<int32_t>(1, FUZZ_MAX_TCP_PORT);
    EsclDriverManager::IsAdfEmpty(ipAddress, portNumber);
}
}  // namespace Scan
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("multithreading is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestGenerateEsclScannerInfo,
        &OHOS::Scan::TestIsEsclScanner,
        &OHOS::Scan::TestExtractIpAndPort,
        &OHOS::Scan::TestExtractIpAndPortWithValidFormat,
        &OHOS::Scan::TestExtractIpAndPortWithEdgeCases,
        &OHOS::Scan::TestAddEsclScannerInfo,
        &OHOS::Scan::TestAddEsclScannerInfoNoDup,
        &OHOS::Scan::TestInitializeEsclScannerDriver,
        &OHOS::Scan::TestIsAdfMode,
        &OHOS::Scan::TestIsAdfEmpty
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
