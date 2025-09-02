/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <regex>
#include "scan_log.h"
#include "usb_errors.h"
#include "scan_constant.h"
#include "scan_service_ability.h"
#include "cJSON.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "scan_system_data.h"
#include "scan_usb_manager.h"
#include "scanner_info.h"
#include "scan_service_utils.h"
#include "scan_util.h"

namespace OHOS::Scan {
using namespace OHOS;
using namespace OHOS::USB;

ScanUsbManager::ScanUsbManager()
{}

ScanUsbManager::~ScanUsbManager()
{}

void ScanUsbManager::Init()
{
    if (isInit) {
        return;
    }
    SCAN_HILOGI("listen usb device attach detach");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_ATTACHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_DETACHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    usbDevStatusListener = std::make_shared<ScanEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(usbDevStatusListener)) {
        SCAN_HILOGE("subscribe common event failed");
        return;
    }
    RefreshUsbDevice();
    isInit = true;
}

void ScanUsbManager::RefreshUsbDevice()
{
    SCAN_HILOGI("RefreshDeviceList start");
    std::vector<UsbDevice> devlist;
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    auto ret = UsbSrvClient.GetDevices(devlist);
    if (ret != ERR_OK) {
        SCAN_HILOGE("RefreshDeviceList GetDevices failed with ret = %{public}d.", ret);
        return;
    }
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    usbSnMap_.clear();
    SCAN_HILOGI("RefreshDeviceList DeviceList size = %{public}zu.", devlist.size());
    for (auto &dev : devlist) {
        std::string serialNumber = GetSerialNumber(dev);
        if (serialNumber.empty()) {
            SCAN_HILOGW("Seria number is empty, port = %{private}s", dev.GetName().c_str());
            continue;
        }
        SCAN_HILOGD("RefreshDeviceList serialNumber = %{private}s.", serialNumber.c_str());
        std::string devicePort = dev.GetName();
        dev.SetmSerial(serialNumber);
        usbSnMap_[devicePort] = dev;
    }
}

std::string ScanUsbManager::GetScannerNameBySn(const std::string &serialNumber)
{
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    for (const auto &[port, device] : usbSnMap_) {
        std::string sn = device.GetmSerial();
        if (serialNumber == sn) {
            std::ostringstream oss;
            oss << "USB-" << device.GetManufacturerName() << " " << device.GetProductName() << "-";
            constexpr int32_t INDEX_SIX = 6;
            if (serialNumber.size() <= INDEX_SIX) {
                oss << serialNumber;
            } else {
                oss << serialNumber.substr(serialNumber.size() - INDEX_SIX);
            }
            return oss.str();
        }
    }
    return "";
}

std::string ScanUsbManager::GetSerialNumber(UsbDevice &usbDevice)
{
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    SCAN_HILOGI("getSerialNumber dev.GetName() = %{public}s.", usbDevice.GetName().c_str());
    USBDevicePipe usbDevicePipe;
    int32_t openDeviceRet = UsbSrvClient.OpenDevice(usbDevice, usbDevicePipe);
    if (openDeviceRet != UEC_OK) {
        SCAN_HILOGE("openDevice fail with ret = %{public}d", openDeviceRet);
        return "";
    }
    std::string serialNumber = GetDeviceSerialNumber(usbDevicePipe);
    bool closeDeviceRet = UsbSrvClient.Close(usbDevicePipe);
    SCAN_HILOGD("openDevice ret = %{public}d", closeDeviceRet);
    size_t pos = serialNumber.find_last_not_of('\0');
    size_t newSize = (pos == std::string::npos) ? 0 : pos + 1;
    serialNumber.resize(newSize);
    return serialNumber;
}

std::string ScanUsbManager::GetDeviceSerialNumber(USBDevicePipe &usbDevicePipe)
{
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    uint16_t indexInStringDescriptor = USB_VALUE_DESCRIPTOR_INDEX_SERIAL_NUMBER;
    uint8_t requestType = USB_REQUESTTYPE_DEVICE_TO_HOST;
    uint8_t request = USB_REQUEST_GET_DESCRIPTOR;
    uint16_t value = (USB_VALUE_DESCRIPTOR_TYPE_STRING << HTTP_COMMON_CONST_VALUE_8) | indexInStringDescriptor;
    uint16_t index = USB_INDEX_LANGUAGE_ID_ENGLISH;
    int32_t timeOut = HTTP_COMMON_CONST_VALUE_500;
    const HDI::Usb::V1_0::UsbCtrlTransfer tctrl = {requestType, request, value, index, timeOut};
    std::vector<uint8_t> bufferData(HTTP_COMMON_CONST_VALUE_100, 0);
    int32_t ret = UsbSrvClient.ControlTransfer(usbDevicePipe, tctrl, bufferData);
    if (ret != 0 || bufferData[0] == 0) {
        SCAN_HILOGE("ControlTransfer failed ret = %{public}d, buffer length = %{public}d", ret, bufferData[0]);
        return "";
    }

    std::vector<uint8_t> arr((bufferData[0] - HTTP_COMMON_CONST_VALUE_2) / HTTP_COMMON_CONST_VALUE_2);
    int arrIndex = 0;
    for (int i = 2; i < bufferData[0];) {
        arr[arrIndex++] = bufferData[i];
        i += HTTP_COMMON_CONST_VALUE_2;
    }
    std::string serialNumber(arr.begin(), arr.end());
    return serialNumber;
}

std::string ScanUsbManager::GetSerialNumberByPort(const std::string &port)
{
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    auto it = usbSnMap_.find(port);
    if (it == usbSnMap_.end()) {
        SCAN_HILOGW("Cannot find sn by %{public}s", port.c_str());
        return "";
    }
    return it->second.GetmSerial();
}

std::string ScanUsbManager::GetPortBySerialNumber(const std::string &serialNumber)
{
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    for (const auto &[port, device] : usbSnMap_) {
        if (serialNumber == device.GetmSerial()) {
            return port;
        }
    }
    return "";
}

bool ScanUsbManager::IsDeviceAvailable(const std::string &firstId, const std::string &secondId)
{
    int32_t busNum = 0;
    int32_t devAddr = 0;
    if (!ScanUtil::ConvertToInt(firstId, busNum) || !ScanUtil::ConvertToInt(secondId, devAddr)) {
        SCAN_HILOGE("[%{public}s][%{public}s] format error", firstId.c_str(), secondId.c_str());
        return false;
    }
    UsbDevice usbDevice;
    usbDevice.SetBusNum(static_cast<uint8_t>(busNum));
    usbDevice.SetDevAddr(static_cast<uint8_t>(devAddr));
    USBDevicePipe usbDevicePipe;
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    int32_t openDeviceRet = UsbSrvClient.OpenDevice(usbDevice, usbDevicePipe);
    if (openDeviceRet != UEC_OK) {
        SCAN_HILOGE("openDevice fail with ret = %{public}d", openDeviceRet);
        return false;
    }
    bool closeDeviceRet = UsbSrvClient.Close(usbDevicePipe);
    SCAN_HILOGD("openDevice ret = %{public}d", closeDeviceRet);
    return true;
}

void ScanUsbManager::UpdateUsbScannerId(std::string serialNumber, std::string usbDevicePort)
{
    if (serialNumber.empty() || usbDevicePort.empty()) {
        SCAN_HILOGE("UpdateUsbScannerId serialNumber or usbDevicePort is null.");
        return;
    }
    if (scannerDiscoverData_.HasUsbDevice(serialNumber)) {
        ScanDeviceInfo info;
        scannerDiscoverData_.GetUsbDevice(serialNumber, info);
        SCAN_HILOGD("DealUsbDevStatusChange attached find out usbDevicePort = %{private}s, deviceId = %{private}s.",
            usbDevicePort.c_str(),
            info.deviceId.c_str());
        std::string newDeviceId = ScanServiceUtils::ReplaceDeviceIdUsbPort(info.deviceId, usbDevicePort);
        ScanDeviceInfoSync syncInfo;
        syncInfo.deviceId = newDeviceId;
        syncInfo.uniqueId = serialNumber;
        syncInfo.oldDeviceId = info.deviceId;
        syncInfo.discoverMode = ScannerDiscoveryMode::USB_MODE;
        syncInfo.syncMode = ScannerSyncMode::UPDATE_MODE;
        ScanServiceAbility::GetInstance()->UpdateScannerId(syncInfo);
    } else {
        SCAN_HILOGD("not find scanner, start discover");
        ScanServiceAbility::GetInstance()->GetScannerList();
    }
}

void ScanUsbManager::DisConnectUsbScanner(std::string usbDevicePort)
{
    if (usbDevicePort.empty()) {
        SCAN_HILOGD("DisConnectUsbScanner usbDevicePort is null.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    auto usbSnMapit = usbSnMap_.find(usbDevicePort);
    if (usbSnMapit != usbSnMap_.end()) {
        std::string serialNumber = usbSnMapit->second.GetmSerial();
        if (scannerDiscoverData_.HasUsbDevice(serialNumber)) {
            ScanDeviceInfo info;
            scannerDiscoverData_.GetUsbDevice(serialNumber, info);
            ScanServiceAbility::GetInstance()->DisConnectUsbScanner(serialNumber, info.deviceId);
        }
        usbSnMap_.erase(usbDevicePort);
        SCAN_HILOGD("DealUsbDevStatusChange detached usbDevicePort = %{private}s, serialNumber = %{private}s",
            usbDevicePort.c_str(),
            serialNumber.c_str());
    }
}

void ScanUsbManager::ConnectUsbScanner(UsbDevice &device)
{
    std::string serialNumber = GetSerialNumber(device);
    if (serialNumber.empty()) {
        SCAN_HILOGD("ConnectUsbScanner serialNumber is null.");
        return;
    }
    std::string port = device.GetName();
    UpdateUsbScannerId(serialNumber, port);
    std::lock_guard<std::mutex> autoLock(usbSnMapLock_);
    device.SetmSerial(serialNumber);
    usbSnMap_.insert({port, device});
    SCAN_HILOGD("ConnectUsbScanner usbDevicePort = %{private}s, serialNumber = %{private}s",
        port.c_str(),
        serialNumber.c_str());
}

void ScanUsbManager::DealUsbDevStatusChange(const std::string &devStr, bool isAttach)
{
    SCAN_HILOGD("DealUsbDevStatusChange isAttach = %{public}d, devStr = %{public}s.", isAttach, devStr.c_str());
    cJSON *devJson = cJSON_Parse(devStr.c_str());
    if (!devJson) {
        SCAN_HILOGE("Create devJson error");
        return;
    }
    UsbDevice *dev = new UsbDevice(devJson);
    std::string usbDevicePort = dev->GetName();
    if (!isAttach) {
        DisConnectUsbScanner(usbDevicePort);
    } else {
        ConnectUsbScanner(*dev);
    }
    cJSON_Delete(devJson);
    delete dev;
    dev = nullptr;
}

}  // namespace OHOS::Scan