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
 
#ifndef SCAN_USB_MANAGER_H_
#define SCAN_USB_MANAGER_H_

#include <map>
#include <string>
#include <utility>
#include "usb_srv_client.h"
#include "singleton.h"
#include "scan_event_subscriber.h"
#include "scan_discover_data.h"

namespace OHOS::Scan {

class ScanUsbManager final : public DelayedSingleton<ScanUsbManager> {
public:
    ScanUsbManager();
    ~ScanUsbManager();
    void Init();
    void DealUsbDevStatusChange(const std::string &devStr, bool isAttach);
    bool IsDeviceAvailable(const std::string& firstId, const std::string& secondId);
    std::string GetPortBySerialNumber(const std::string& serialNumber);
    std::string GetSerialNumberByPort(const std::string& port);
    std::string GetScannerNameBySn(const std::string& serialNumber);
private:
    void RefreshUsbDevice();
    void UpdateUsbScannerId(std::string serialNumber, std::string usbDevicePort);
    void DisConnectUsbScanner(std::string usbDeviceName);
    void ConnectUsbScanner(OHOS::USB::UsbDevice& device);
    std::string GetSerialNumber(OHOS::USB::UsbDevice &usbDevice);
    std::string GetDeviceSerialNumber(OHOS::USB::USBDevicePipe &usbDevicePipe);
    std::shared_ptr<ScanEventSubscriber> usbDevStatusListener;
    
    bool isInit = false;
    std::map<std::string, OHOS::USB::UsbDevice> usbSnMap_;
    ScannerDiscoverData& scannerDiscoverData_ = ScannerDiscoverData::GetInstance();
    std::mutex usbSnMapLock_;
};

}

#endif // SCAN_USB_MANAGER_H_