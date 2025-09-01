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
#define private public
#define protected public
#include "fuzzer/FuzzedDataProvider.h"
#include "scanusbmanager_fuzzer.h"
#include "scan_usb_manager.h"
#include "scan_service_ability.h"


namespace OHOS {
namespace Scan {
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;

    void TestDealUsbDevStatusChange(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
        DelayedSingleton<ScanUsbManager>::GetInstance()->RefreshUsbDevice();
        std::string devStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool isAttach = dataProvider->ConsumeBool();
        std::string devStrOne = "2-3";
        DelayedSingleton<ScanUsbManager>::GetInstance()->DealUsbDevStatusChange(devStr, isAttach);
        DelayedSingleton<ScanUsbManager>::GetInstance()->DealUsbDevStatusChange(devStrOne, true);
        DelayedSingleton<ScanUsbManager>::GetInstance()->DealUsbDevStatusChange(devStrOne, false);
        USB::USBDevicePipe usbDevicePipe;
        DelayedSingleton<ScanUsbManager>::GetInstance()->GetDeviceSerialNumber(usbDevicePipe);
    }

    void TestUsbUpdateUsbScannerId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string usbDeviceName = "2-4";
        std::string serialNumber = "QWERTY";
        ScanDeviceInfo scanDeviceInfo;
        scanDeviceInfo.deviceId = "pantu:libusb:002:004";
        scanDeviceInfo.serialNumber = serialNumber;
        ScannerDiscoverData::GetInstance().SetUsbDevice(serialNumber, scanDeviceInfo);
        ScanUsbManager::GetInstance()->UpdateUsbScannerId(serialNumber, usbDeviceName);

        std::string fuzzUsbDeviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string fuzzSerialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanDeviceInfo fuzzScanDeviceInfo;
        scanDeviceInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanDeviceInfo.serialNumber = fuzzSerialNumber;
        ScannerDiscoverData::GetInstance().SetUsbDevice(fuzzSerialNumber, fuzzScanDeviceInfo);
        ScanUsbManager::GetInstance()->UpdateUsbScannerId(fuzzSerialNumber, fuzzUsbDeviceName);
    }

    void TestUsbDisConnectUsbScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string usbDeviceName = "2-3";
        std::string serialNumber = "ASDFGH";
        ScanDeviceInfo scanDeviceInfo;
        scanDeviceInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanDeviceInfo.serialNumber = serialNumber;
        ScannerDiscoverData::GetInstance().SetUsbDevice(serialNumber, scanDeviceInfo);
        ScanUsbManager::GetInstance()->DisConnectUsbScanner(usbDeviceName);

        std::string fuzzUsbDeviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string fuzzSerialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanDeviceInfo fuzzScanDeviceInfo;
        scanDeviceInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanDeviceInfo.serialNumber = fuzzSerialNumber;
        ScannerDiscoverData::GetInstance().SetUsbDevice(fuzzSerialNumber, fuzzScanDeviceInfo);
        ScanUsbManager::GetInstance()->DisConnectUsbScanner(fuzzUsbDeviceName);
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Scan::TestDealUsbDevStatusChange(data, size, &dataProvider);
    OHOS::Scan::TestUsbUpdateUsbScannerId(data, size, &dataProvider);
    OHOS::Scan::TestUsbDisConnectUsbScanner(data, size, &dataProvider);

    return 0;
}

