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
#include "scanserviceability_fuzzer.h"
#include "scan_service_ability.h"
#include "scan_callback_proxy.h"
#include "scan_service_ability_mock.h"

namespace OHOS {
namespace Scan {
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr int MAX_SET_NUMBER = 100;

    void TestInitScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        ScanServiceAbility::GetInstance()->ExitScan();
    }

    void TestGetScannerList(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        ScanServiceAbility::GetInstance()->GetScannerList();
    }

    void TestStopDiscover(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        ScanServiceAbility::GetInstance()->StopDiscover();
    }

    void TestOpenScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->OpenScanner(scannerId);
    }

    void TestCloseScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->OpenScanner(scannerId);
        ScanServiceAbility::GetInstance()->CloseScanner(scannerId);
    }

    void TestGetScanOptionDesc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanOptionDescriptor desc;
        ScanServiceAbility::GetInstance()->GetScanOptionDesc(scannerId, optionIndex, desc);
    }

    void TestStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool batchMode = dataProvider->ConsumeBool();
        ScanServiceAbility::GetInstance()->StartScan(scannerId, batchMode);
    }

    void TestGetSingleFrameFD(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        uint32_t frameSize = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->GetSingleFrameFD(scannerId, frameSize, fd);
    }

    void TestCancelScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->CancelScan(scannerId);
    }

    void TestSetScanIOMode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool isNonBlocking = dataProvider->ConsumeBool();
        ScanServiceAbility::GetInstance()->SetScanIOMode(scannerId, isNonBlocking);
    }

    void TestGetScanSelectFd(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t fd = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->GetScanSelectFd(scannerId, fd);
    }

    void TestOn(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        sptr<IScanCallback> listener = iface_cast<IScanCallback>(impl);
        ScanServiceAbility::registeredListeners_[type] = listener;
        ScanServiceAbility::GetInstance()->On(taskId, type, listener);
        ScanServiceAbility::registeredListeners_.clear();
    }

    void TestOff(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        sptr<IRemoteObject> impl;
        ScanCallbackProxy scanCallbackProxy(impl);
        sptr<IScanCallback> listener = iface_cast<IScanCallback>(impl);
        ScanServiceAbility::registeredListeners_[type] = listener;
        ScanServiceAbility::GetInstance()->Off(taskId, type);
    }

    void TestGetScannerState(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->InitScan(scanVersion);
        int32_t scannerState = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->GetScannerState(scannerState);
    }

    void TestOnStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool batchMode = dataProvider->ConsumeBool();
        auto scanSaPtr = ScanServiceAbility::GetInstance();
        if (scanSaPtr == nullptr) {
            return;
        }
        scanSaPtr->OnStartScan(scannerId, batchMode);
        int32_t userId = scanSaPtr->GetCurrentUserId();
        scanSaPtr->ObtainUserCacheDirectory(userId);
        userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanSaPtr->ObtainUserCacheDirectory(userId);
        constexpr int32_t DEFAULT_USERID = 100;
        userId = DEFAULT_USERID;
        scanSaPtr->ObtainUserCacheDirectory(userId);
    }

    void TestSendDeviceInfoTCP(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfoTCP info;
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendDeviceInfoTCP(info, event);
    }

    void TestSendDeviceInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo  info;
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendDeviceInfo(info, event);
    }

    void TestSendDeviceInfoSync(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfoSync  info;
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendDeviceInfoSync(info, event);
    }

    void TestDisConnectUsbScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string newDeviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->DisConnectUsbScanner(serialNumber, newDeviceId);
    }

    void TestUpdateUsbScannerId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanDeviceInfoSync usbSyncInfo;
        usbSyncInfo.discoverMode = discoverMode;
        ScanServiceAbility::GetInstance()->UpdateScannerId(usbSyncInfo);
        usbSyncInfo.discoverMode = "USB";
        ScanServiceAbility::GetInstance()->UpdateScannerId(usbSyncInfo);
        usbSyncInfo.discoverMode = "TCP";
        ScanServiceAbility::GetInstance()->UpdateScannerId(usbSyncInfo);
    }

    void TestSendInitEvent(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t scanVersion = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendInitEvent(scanVersion, event);
    }

    void TestSendDeviceSearchEnd(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string message = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendDeviceSearchEnd(message, event);
    }

    void TestSetScannerSerialNumber(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo tcpInfo;
        tcpInfo.deviceId = "pantum6500:tcp 192.168.223.1 9200-M6700DW";
        std::string ip = "192.168.223.1";
        ScanDeviceInfoTCP scanDeviceInfoTCP;
        scanDeviceInfoTCP.deviceName = "Pantum 6666 54QWER";
        ScanMdnsService::InsertIpToScannerInfo(ip, scanDeviceInfoTCP);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(tcpInfo);

        tcpInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanDeviceInfoTCP.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(tcpInfo);

        ScanDeviceInfo usbInfo;
        usbInfo.deviceId = "pantum6500:libusb:002:003";
        ScanServiceAbility::usbSnMap["2-3"] = "QWERTY";
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);

        usbInfo.deviceId = "pantum6500:libusb:002:004";
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);
        usbInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);
    }

    void TestReInitScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->ServiceInit();
        ScanServiceAbility::GetInstance()->InitServiceHandler();
        ScanServiceAbility::GetInstance()->OnStart();
        ScanServiceAbility::GetInstance()->OnStop();
        ScanServiceAbility::GetInstance()->ManualStart();
        ScanServiceAbility::GetInstance()->ReInitScan();
        ScanServiceAbility::GetInstance()->SaneGetScanner();
    }

    void TestCheckPermission(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string permissionName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->CheckPermission(permissionName);
    }

    void TestGeneratePictureBatch(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        int32_t status = E_SCAN_NONE;
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string file_name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string output_file = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanProgress* scanProPtr = nullptr;
        ScanServiceAbility::GetInstance()->GeneratePictureSingle(scannerId, file_name, output_file, status, scanProPtr);
    }

    void TestAddFoundScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo info;
        info.serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->AddFoundScanner(info);
    }

    void TestSendDeviceList(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo infoItem;
        std::vector<ScanDeviceInfo> info;
        info.push_back(infoItem);
        std::string event = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SendDeviceList(info, event);
    }

    void TestAddScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->AddScanner(serialNumber, discoverMode);
    }

    void TestUpdateScannerName(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->UpdateScannerName(serialNumber, discoverMode, deviceName);
    }

    void TestCleanScanTask(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->CleanScanTask(scannerId);
    }

    void TestGetAddedScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo addedScanner;
        std::string newDeviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        addedScanner.SetDeviceId(newDeviceId);
        std::vector<ScanDeviceInfo> allAddedScanner;
        allAddedScanner.push_back(addedScanner);
        ScanServiceAbility::GetInstance()->GetAddedScanner(allAddedScanner);
    }

    void TestNotPublicFunction(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        if (dataProvider == nullptr) {
            return;
        }
        OHOS::Scan::TestReInitScan(data, size, dataProvider);
        OHOS::Scan::TestCheckPermission(data, size, dataProvider);
        OHOS::Scan::TestGeneratePictureBatch(data, size, dataProvider);
        OHOS::Scan::TestAddFoundScanner(data, size, dataProvider);
        OHOS::Scan::TestSendDeviceList(data, size, dataProvider);
        OHOS::Scan::TestAddScanner(data, size, dataProvider);
        OHOS::Scan::TestUpdateScannerName(data, size, dataProvider);
        OHOS::Scan::TestCleanScanTask(data, size, dataProvider);
        OHOS::Scan::TestGetAddedScanner(data, size, dataProvider);
    }

    void TestCleanUpAfterScan(FuzzedDataProvider* dataProvider)
    {
        if (dataProvider == nullptr) {
            return;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->RestartScan(scannerId);
        int32_t nowScanId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanProgress* scanProPtr = new ScanProgress();
        ScanServiceAbility::GetInstance()->FindScanTask(scanProPtr, nowScanId);
        int32_t scanStatus = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->CleanUpAfterScan(scanStatus, scanProPtr);
        delete scanProPtr;
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
    OHOS::Scan::ScanServiceAbilityMock::MockPermission();
    OHOS::Scan::TestInitScan(data, size, &dataProvider);
    OHOS::Scan::TestGetScannerList(data, size, &dataProvider);
    OHOS::Scan::TestStopDiscover(data, size, &dataProvider);
    OHOS::Scan::TestOpenScanner(data, size, &dataProvider);
    OHOS::Scan::TestCloseScanner(data, size, &dataProvider);
    OHOS::Scan::TestGetScanOptionDesc(data, size, &dataProvider);
    OHOS::Scan::TestStartScan(data, size, &dataProvider);
    OHOS::Scan::TestGetSingleFrameFD(data, size, &dataProvider);
    OHOS::Scan::TestCancelScan(data, size, &dataProvider);
    OHOS::Scan::TestSetScanIOMode(data, size, &dataProvider);
    OHOS::Scan::TestGetScanSelectFd(data, size, &dataProvider);
    OHOS::Scan::TestOn(data, size, &dataProvider);
    OHOS::Scan::TestOff(data, size, &dataProvider);
    OHOS::Scan::TestGetScannerState(data, size, &dataProvider);
    OHOS::Scan::TestOnStartScan(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceInfoTCP(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceInfo(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceInfoSync(data, size, &dataProvider);
    OHOS::Scan::TestDisConnectUsbScanner(data, size, &dataProvider);
    OHOS::Scan::TestUpdateUsbScannerId(data, size, &dataProvider);
    OHOS::Scan::TestSendInitEvent(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceSearchEnd(data, size, &dataProvider);
    OHOS::Scan::TestSetScannerSerialNumber(data, size, &dataProvider);
    OHOS::Scan::TestNotPublicFunction(data, size, &dataProvider);
    OHOS::Scan::TestCleanUpAfterScan(&dataProvider);
    return 0;
}