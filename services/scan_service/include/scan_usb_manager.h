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

namespace OHOS::Scan {

class ScanUsbManager final : public DelayedSingleton<ScanUsbManager> {
public:
    ScanUsbManager();
    ~ScanUsbManager();
    void RefreshUsbDevice();
    std::string GetSerialNumber(USB::UsbDevice &usbDevice);
    void DealUsbDevStatusChange(const std::string &devStr, bool isAttach);
    void RefreshUsbDevicePort();
    void Init();
private:
    std::string GetDeviceSerialNumber(USB::USBDevicePipe &usbDevicePipe);
    void formatUsbPort(std::string &port);
    std::string getNewDeviceId(std::string oldDeviceId, std::string usbDeviceName);
    void UpdateUsbScannerId(std::string serialNumber, std::string usbDeviceName);
    void DisConnectUsbScanner(std::string usbDeviceName);
    std::shared_ptr<ScanEventSubscriber> usbDevStatusListener;
    bool isInit = false;
};

}

#endif // SCAN_USB_MANAGER_H_