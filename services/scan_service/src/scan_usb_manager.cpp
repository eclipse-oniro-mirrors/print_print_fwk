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
    SCAN_HILOGI("RefreshDeviceList DeviceList size = %{public}zu.", devlist.size());
    for (auto dev : devlist) {
        std::string serialNumber = GetSerialNumber(dev);
        if (serialNumber == "") {
            SCAN_HILOGW("Seria number is empty.");
            continue;
        }
        SCAN_HILOGI("RefreshDeviceList serialNumber = %{private}s.", serialNumber.c_str());
        std::string devicePort = dev.GetName();
        std::regex pattern("\\d+-\\d+");
        if (std::regex_match(devicePort, pattern)) {
            SCAN_HILOGI("RefreshDeviceList dev.GetName() %{private}s ", devicePort.c_str());
            ScanServiceAbility::usbSnMap[devicePort] = serialNumber;
        } else {
            SCAN_HILOGW("Incorrect port number format.");
        }
    }
}

void ScanUsbManager::RefreshUsbDevicePort()
{
    SCAN_HILOGI("RefreshUsbDevicePort start");
    ScanSystemData::usbSnToPortMap_.clear();
    std::vector<UsbDevice> devlist;
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    auto ret = UsbSrvClient.GetDevices(devlist);
    if (ret != ERR_OK) {
        SCAN_HILOGE("RefreshUsbDevicePort GetDevices failed with ret = %{public}d.", ret);
        return;
    }
    SCAN_HILOGI("RefreshUsbDevicePort DeviceList size = %{public}zu.", devlist.size());
    for (auto dev : devlist) {
        SCAN_HILOGI("RefreshUsbDevicePort dev.GetName() %{private}s ", dev.GetName().c_str());
        std::string serialNumber = GetSerialNumber(dev);
        if (serialNumber == "") {
            SCAN_HILOGW("Seria number is empty.");
            continue;
        }
        SCAN_HILOGI("RefreshUsbDevicePort serialNumber = %{private}s.", serialNumber.c_str());
        std::string devicePort = dev.GetName();
        std::regex pattern("\\d+-\\d+");
        if (std::regex_match(devicePort, pattern)) {
            ScanSystemData::usbSnToPortMap_[serialNumber] = devicePort;
        } else {
            SCAN_HILOGW("Incorrect port number format.");
        }
    }
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
    SCAN_HILOGI("openDevice ret = %{public}d", openDeviceRet);
    std::string serialNumber = GetDeviceSerialNumber(usbDevicePipe);
    return serialNumber;
}

std::string ScanUsbManager::GetDeviceSerialNumber(USBDevicePipe &usbDevicePipe)
{
    auto &UsbSrvClient = UsbSrvClient::GetInstance();
    SCAN_HILOGI("Enter GetDeviceSerialNumber");
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
    std::string scannerInfo(arr.begin(), arr.end());
    SCAN_HILOGI("bufferData scanerInfo: %{public}s\n", scannerInfo.c_str());
    return scannerInfo;
}

void ScanUsbManager::FormatUsbPort(std::string &port)
{
    for (auto size = port.size(); size < USB_DEVICEID_FIRSTID_LEN_3; size++) {
        std::string newString = "0";
        newString.append(port);
        port = newString;
    }
}

std::string ScanUsbManager::getNewDeviceId(std::string oldDeviceId, std::string usbDevicePort)
{
    std::string deviceIdHead = oldDeviceId.substr(0, oldDeviceId.find_last_of(":")
                                                    - USB_DEVICEID_FIRSTID_LEN_3);
    std::string firstPort = usbDevicePort.substr(0, usbDevicePort.find("-"));
    std::string secondPort = usbDevicePort.substr(usbDevicePort.find("-") + 1, usbDevicePort.size() - 1);
    SCAN_HILOGI("firstPort = %{public}s, secondPort = %{public}s.",
                firstPort.c_str(), secondPort.c_str());
    FormatUsbPort(firstPort);
    FormatUsbPort(secondPort);
    return deviceIdHead + firstPort + ":" + secondPort;
}

void ScanUsbManager::UpdateUsbScannerId(std::string serialNumber, std::string usbDevicePort)
{
    if (serialNumber.empty() || usbDevicePort.empty()) {
        SCAN_HILOGE("UpdateUsbScannerId serialNumber or usbDevicePort is null.");
        return;
    }
    std::string uniqueId = "USB" + serialNumber;
    if (ScanSystemData::GetInstance().UpdateScannerIdByUsbDevicePort(uniqueId, usbDevicePort)) {
        if (!ScanSystemData::GetInstance().SaveScannerMap()) {
            SCAN_HILOGW("Failed to update the Json file.");
        }
    }
    auto it = ScanServiceAbility::saneGetUsbDeviceInfoMap.find(serialNumber);
    if (it != ScanServiceAbility::saneGetUsbDeviceInfoMap.end()) {
#ifdef DEBUG_ENABLE
        SCAN_HILOGD("DealUsbDevStatusChange attached find out usbDevicePort = %{public}s, serialNumber = %{public}s "
                    "deviceId = %{public}s.",
                    usbDevicePort.c_str(), serialNumber.c_str(), it->second.deviceId.c_str());
#endif
        std::string newDeviceId = getNewDeviceId(it->second.deviceId, usbDevicePort);
        ScanServiceAbility::GetInstance()->UpdateUsbScannerId(serialNumber, newDeviceId);
        for (auto &t : ScanServiceAbility::usbSnMap) {
            if (t.second == serialNumber) {
                SCAN_HILOGD("UpdateUsbScannerId usbSnMap erase %{public}s.", t.first.c_str());
                ScanServiceAbility::usbSnMap.erase(t.first);
                break;
            }
        }
        ScanServiceAbility::usbSnMap[usbDevicePort] = serialNumber;
    } else {
        SCAN_HILOGD("DealUsbDevStatusChange attached find out usbDevicePort = %{public}s, serialNumber = %{public}s."
                    "No matched device in saneGetUsbDeviceInfoMap.", usbDevicePort.c_str(), serialNumber.c_str());
        ScanServiceAbility::GetInstance()->GetScannerList();
    }
}

void ScanUsbManager::DisConnectUsbScanner(std::string usbDevicePort)
{
    if (usbDevicePort.empty()) {
        SCAN_HILOGE("DisConnectUsbScanner usbDevicePort is null.");
        return;
    }
    auto usbSnMapit = ScanServiceAbility::usbSnMap.find(usbDevicePort);
    if (usbSnMapit != ScanServiceAbility::usbSnMap.end()) {
        std::string serialNumber = usbSnMapit->second;
        if (!serialNumber.empty()) {
            auto it = ScanServiceAbility::saneGetUsbDeviceInfoMap.find(serialNumber);
            if (it != ScanServiceAbility::saneGetUsbDeviceInfoMap.end()) {
                ScanServiceAbility::GetInstance()->DisConnectUsbScanner(serialNumber, it->second.deviceId);
                ScanServiceAbility::usbSnMap.erase(usbDevicePort);
            }
        }
#ifdef DEBUG_ENABLE
        SCAN_HILOGD("DealUsbDevStatusChange detached usbDevicePort = %{public}s, serialNumber = %{public}s. end",
                    usbDevicePort.c_str(), serialNumber.c_str());
#endif
    }
}

void ScanUsbManager::DealUsbDevStatusChange(const std::string &devStr, bool isAttach)
{
    SCAN_HILOGD("DealUsbDevStatusChange isAttach = %{public}d, devStr = %{public}s.",
                isAttach, devStr.c_str());
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
        std::string serialNumber = GetSerialNumber(*dev);
        if (!serialNumber.empty()) {
            UpdateUsbScannerId(serialNumber, usbDevicePort);
        }
    }
    cJSON_Delete(devJson);
    delete dev;
    dev = nullptr;
}

}