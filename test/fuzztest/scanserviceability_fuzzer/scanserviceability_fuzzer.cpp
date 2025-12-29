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
#include "scan_mdns_service.h"
#include "mdns_common.h"
#include "scan_task.h"

namespace OHOS {
namespace Scan {
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr int MAX_SET_NUMBER = 100;

    void TestOpenScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->InitScan();
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->OpenScanner(scannerId);
    }

    void TestCloseScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->InitScan();
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->OpenScanner(scannerId);
        ScanServiceAbility::GetInstance()->CloseScanner(scannerId);
    }

    void TestGetScanOptionDesc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->InitScan();
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanOptionDescriptor desc;
        ScanServiceAbility::GetInstance()->GetScanOptionDesc(scannerId, optionIndex, desc);
    }

    void TestStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->InitScan();
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool batchMode = dataProvider->ConsumeBool();
        ScanServiceAbility::GetInstance()->StartScan(scannerId, batchMode);
    }

    void TestCancelScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanServiceAbility::GetInstance()->InitScan();
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->CancelScan(scannerId);
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

    void TestOnStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        bool batchMode = dataProvider->ConsumeBool();
        auto scanSaPtr = ScanServiceAbility::GetInstance();
        if (scanSaPtr == nullptr) {
            return;
        }
        scanSaPtr->StartScan(scannerId, batchMode);
        scanSaPtr->GetCurrentUserId();
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
        usbSyncInfo.discoverMode = ScannerDiscoveryMode::USB_MODE;
        ScanServiceAbility::GetInstance()->UpdateScannerId(usbSyncInfo);
        usbSyncInfo.discoverMode = ScannerDiscoveryMode::TCP_MODE;
        ScanServiceAbility::GetInstance()->UpdateScannerId(usbSyncInfo);
    }

    void TestSetScannerSerialNumber(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo tcpInfo;
        tcpInfo.deviceId = "pantum6500:tcp 192.168.223.1 9200-M6700DW";
        std::string ip = "192.168.223.1";
        ScanDeviceInfoTCP scanDeviceInfoTCP;
        scanDeviceInfoTCP.deviceName = "Pantum 6666 54QWER";
        ScanMdnsService::GetInstance().SetScannerInfoMap(ip, scanDeviceInfoTCP);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(tcpInfo);

        tcpInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ip = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanDeviceInfoTCP.deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(tcpInfo);

        ScanDeviceInfo usbInfo;
        usbInfo.deviceId = "pantum6500:libusb:002:003";
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);

        usbInfo.deviceId = "pantum6500:libusb:002:004";
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);
        usbInfo.deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->SetScannerSerialNumber(usbInfo);
    }

    void TestCheckPermission(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string permissionName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->CheckPermission(permissionName);
    }

    void TestGeneratePictureBatch(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        bool batchMode = dataProvider->ConsumeBool();
        ScanTask scanTask(scannerId, userId, batchMode);
        ScanServiceAbility::GetInstance()->GeneratePictureSingle(scanTask);
        ScanServiceAbility::GetInstance()->GeneratePictureBatch(scanTask);
    }

    void TestAddFoundScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo info;
        info.serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::vector<ScanDeviceInfo> scanDeviceInfos;
        ScanServiceAbility::GetInstance()->AddFoundScanner(info, scanDeviceInfos);
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

    void TestGetAddedScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        ScanDeviceInfo addedScanner;
        std::string newDeviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        addedScanner.SetDeviceId(newDeviceId);
        std::vector<ScanDeviceInfo> allAddedScanner;
        allAddedScanner.push_back(addedScanner);
        ScanServiceAbility::GetInstance()->GetAddedScanner(allAddedScanner);
    }

    void TestNoParmFuncs(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->InitScan();
        ScanServiceAbility::GetInstance()->ServiceInit();
        ScanServiceAbility::GetInstance()->InitServiceHandler();
        ScanServiceAbility::GetInstance()->OnStart();
        ScanServiceAbility::GetInstance()->ManualStart();
        ScanServiceAbility::GetInstance()->SaneGetScanner();
        ScanServiceAbility::GetInstance()->GetScannerList();
        ScanServiceAbility::GetInstance()->ExitScan();
        ScanServiceAbility::GetInstance()->OnStop();
    }

    void TestNotPublicFunction(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        if (dataProvider == nullptr) {
            return;
        }
        OHOS::Scan::TestNoParmFuncs(data, size, dataProvider);
        OHOS::Scan::TestCheckPermission(data, size, dataProvider);
        OHOS::Scan::TestGeneratePictureBatch(data, size, dataProvider);
        OHOS::Scan::TestAddFoundScanner(data, size, dataProvider);
        OHOS::Scan::TestSendDeviceList(data, size, dataProvider);
        OHOS::Scan::TestAddScanner(data, size, dataProvider);
        OHOS::Scan::TestGetAddedScanner(data, size, dataProvider);
    }

    void TestCleanUpAfterScan(FuzzedDataProvider* dataProvider)
    {
        if (dataProvider == nullptr) {
            return;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->RestartScan(scannerId);
        int32_t scanStatus = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        bool batchMode = dataProvider->ConsumeBool();
        ScanTask scanTask(scannerId, userId, batchMode);
        ScanServiceAbility::GetInstance()->CleanUpAfterScan(scanTask, scanStatus);
    }

    void TestActionSetAuto(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanServiceAbility::GetInstance()->ActionSetAuto(scannerId, optionIndex);
    }

    void TestActionGetValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanOptionValue scanOptionValue;
        scanOptionValue.SetScanOptionValueType(ScanOptionValueType::SCAN_VALUE_BOOL);
        int32_t valueSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanOptionValue.SetValueSize(valueSize);
        scanOptionValue.SetBoolValue(true);
        ScanServiceAbility::GetInstance()->ActionGetValue(scannerId, scanOptionValue, optionIndex);

        ScanOptionValue scanOptionValue1;
        scanOptionValue1.SetScanOptionValueType(ScanOptionValueType::SCAN_VALUE_NUM);
        valueSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanOptionValue1.SetValueSize(valueSize);
        int32_t numValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanOptionValue1.SetNumValue(numValue);
        ScanServiceAbility::GetInstance()->ActionGetValue(scannerId, scanOptionValue1, optionIndex);

        ScanOptionValue scanOptionValue2;
        scanOptionValue2.SetScanOptionValueType(ScanOptionValueType::SCAN_VALUE_STR);
        valueSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        scanOptionValue2.SetValueSize(valueSize);
        std::string strValue = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        scanOptionValue2.SetStrValue(strValue);
        ScanServiceAbility::GetInstance()->ActionGetValue(scannerId, scanOptionValue2, optionIndex);
    }

    void TestActionSetValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanOptionValue scanOptionValue;
        ScanServiceAbility::GetInstance()->ActionSetValue(scannerId, scanOptionValue, optionIndex);
    }

    void TestOpScanOptionValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanOptionValue scanOptionValue;
        ScanServiceAbility::GetInstance()->OpScanOptionValue(scannerId, optionIndex,
            ScanOptionOpType::SCAN_ACTION_GET_VALUE, scanOptionValue);
    }

    void TestGetScanParameters(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanParameters scanParameters;
        ScanServiceAbility::GetInstance()->GetScanParameters(scannerId, scanParameters);
    }

    void TestGetScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanProgress scanProg;
        ScanServiceAbility::GetInstance()->GetScanProgress(scannerId, scanProg);
    }

    void TestDeleteScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        ScanServiceAbility::GetInstance()->DeleteScanner(serialNumber, discoverMode);
    }

    void TestStartScanTask(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        bool batchMode = dataProvider->ConsumeBool();
        ScanTask scanTask(scannerId, userId, batchMode);
        ScanServiceAbility::GetInstance()->StartScanTask(scanTask);
    }

    void TestDoScanTask(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        bool batchMode = dataProvider->ConsumeBool();
        ScanTask scanTask(scannerId, userId, batchMode);
        ScanServiceAbility::GetInstance()->DoScanTask(scanTask);
    }

    void TestGetPicFrame(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        int32_t scanStatus = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanParameters scanParameters;
        int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        bool batchMode = dataProvider->ConsumeBool();
        ScanTask scanTask(scannerId, userId, batchMode);
        ScanServiceAbility::GetInstance()->GetPicFrame(scanTask, scanStatus, scanParameters);
    }

    void TestMdnsDiscoveryHandleServiceFound(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
    {
        MDnsServiceInfo info;
        info.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.txtRecord = dataProvider->ConsumeBytes<uint8_t>(MAX_STRING_LENGTH);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanMDnsDiscoveryObserver observer(info);
        observer.HandleServiceFound(info, retCode);
    }

    void TestMdnsResolveHandleResolveResult(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
    {
        MDnsServiceInfo info;
        info.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.txtRecord = dataProvider->ConsumeBytes<uint8_t>(MAX_STRING_LENGTH);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanMDnsResolveObserver observer(info);
        observer.HandleResolveResult(info, retCode);
    }

    void TestMdnsDiscoveryHandleServiceLost(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
    {
        MDnsServiceInfo info;
        info.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.txtRecord = dataProvider->ConsumeBytes<uint8_t>(MAX_STRING_LENGTH);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanMDnsDiscoveryObserver observer(info);
        observer.HandleServiceLost(info, retCode);
    }

    void TestMdnsLossResolveHandleResolveResult(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
    {
        MDnsServiceInfo info;
        info.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.txtRecord = dataProvider->ConsumeBytes<uint8_t>(MAX_STRING_LENGTH);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanMDnsLossResolveObserver observer(info);
        observer.HandleResolveResult(info, retCode);
    }

    void TestHandDiscoveryleStopDiscover(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
    {
        MDnsServiceInfo info;
        info.name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        info.txtRecord = dataProvider->ConsumeBytes<uint8_t>(MAX_STRING_LENGTH);
        int32_t retCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        ScanMDnsDiscoveryObserver observer(info);
        observer.HandleStopDiscover(info, retCode);
    }

    void TestAllMdnsService(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        TestMdnsDiscoveryHandleServiceFound(data, size, dataProvider);
        TestMdnsResolveHandleResolveResult(data, size, dataProvider);
        TestMdnsDiscoveryHandleServiceLost(data, size, dataProvider);
        TestMdnsLossResolveHandleResolveResult(data, size, dataProvider);
        TestHandDiscoveryleStopDiscover(data, size, dataProvider);
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
    OHOS::Scan::TestOpenScanner(data, size, &dataProvider);
    OHOS::Scan::TestCloseScanner(data, size, &dataProvider);
    OHOS::Scan::TestGetScanOptionDesc(data, size, &dataProvider);
    OHOS::Scan::TestStartScan(data, size, &dataProvider);
    OHOS::Scan::TestCancelScan(data, size, &dataProvider);
    OHOS::Scan::TestOn(data, size, &dataProvider);
    OHOS::Scan::TestOff(data, size, &dataProvider);
    OHOS::Scan::TestOnStartScan(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceInfo(data, size, &dataProvider);
    OHOS::Scan::TestSendDeviceInfoSync(data, size, &dataProvider);
    OHOS::Scan::TestDisConnectUsbScanner(data, size, &dataProvider);
    OHOS::Scan::TestUpdateUsbScannerId(data, size, &dataProvider);
    OHOS::Scan::TestSetScannerSerialNumber(data, size, &dataProvider);
    OHOS::Scan::TestNotPublicFunction(data, size, &dataProvider);
    OHOS::Scan::TestCleanUpAfterScan(&dataProvider);
    OHOS::Scan::TestActionSetAuto(data, size, &dataProvider);
    OHOS::Scan::TestActionGetValue(data, size, &dataProvider);
    OHOS::Scan::TestOpScanOptionValue(data, size, &dataProvider);
    OHOS::Scan::TestGetScanParameters(data, size, &dataProvider);
    OHOS::Scan::TestGetScanProgress(data, size, &dataProvider);
    OHOS::Scan::TestDeleteScanner(data, size, &dataProvider);
    OHOS::Scan::TestStartScanTask(data, size, &dataProvider);
    OHOS::Scan::TestDoScanTask(data, size, &dataProvider);
    OHOS::Scan::TestGetPicFrame(data, size, &dataProvider);
    OHOS::Scan::TestAllMdnsService(data, size, &dataProvider);
    return 0;
}