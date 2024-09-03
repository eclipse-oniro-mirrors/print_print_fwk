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
 

#ifndef PRINT_USB_MANAGER_H_
#define PRINT_USB_MANAGER_H_
#ifdef IPPOVERUSB_ENABLE

#include <map>
#include <string>
#include <utility>
#include "singleton.h"
#include "usb_srv_client.h"
#include "httplib.h"
#include "print_ipp_over_usb_constant.h"

namespace OHOS::Print {

struct PrinterTranIndex {
    int32_t sendDocConfigIndex = INVAILD_VALUE;
    int32_t sendDocInterfaceIndex = INVAILD_VALUE;
    int32_t commonConfigIndex = INVAILD_VALUE;
    int32_t commonInterfaceIndex = INVAILD_VALUE;
};

enum class Operation {
    Get_Printer_Attributes,
    Send_Document,
    Common
};

class PrintUsbManager final : public DelayedSingleton<PrintUsbManager> {
public:
    PrintUsbManager();
    ~PrintUsbManager();

    void Init();
    bool isExistIppOverUsbPrinter(std::string printerName);
    bool ConnectUsbPinter(const std::string &printerName);
    void DisConnectUsbPinter(const std::string &printerName);
    int32_t BulkTransferWrite(std::string printerName, const Operation operation,
        std::vector<uint8_t> &vectorRequestBuffer);
    int32_t BulkTransferRead(std::string printerName, const Operation operation,
        std::vector<uint8_t> &vectorRequestBuffer);

    void DealUsbDevStatusChange(const std::string &devStr, bool isAttach);
    std::string GetPrinterName(const std::string &name);

private:
    void RefreshUsbPrinterDevice();
    bool isPrintDevice(USB::UsbDevice &usbdevice, std::string &printerName);
    std::string GetProductName(USB::UsbDevice &usbDevice);
    std::string QueryPrinterInfoFromStringDescriptor(
        USB::USBDevicePipe &usbDevicePipe, uint16_t indexInStringDescriptor);
    void DisConnectLastUsbPinter(const std::string &printerName);
    bool AllocateInterface(const std::string &printerName, USB::UsbDevice &usbdevice,
        USB::USBDevicePipe &usbDevicePipe);

private:
    bool isInit = false;
    std::map<std::string, USB::UsbDevice> printDeviceMap;
    std::map<std::string, std::vector<std::pair<int32_t, int32_t>>> printerIndexMap;
    std::map<std::string, USB::USBDevicePipe> printPipeMap;
    std::map<std::string, PrinterTranIndex> printTranIndexMap;
    std::string currentPrinterName;
};

}

#endif // IPPOVERUSB_ENABLE
#endif // PRINT_USB_MANAGER_H_