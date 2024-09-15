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

#ifdef IPPOVERUSB_ENABLE
#include "print_usb_manager.h"
#include "print_log.h"
#include "usb_errors.h"
#include "print_ipp_over_usb_util.h"
#include "cJSON.h"

namespace OHOS::Print {
using namespace OHOS;
using namespace OHOS::USB;

PrintUsbManager::PrintUsbManager()
{}

PrintUsbManager::~PrintUsbManager()
{}

void PrintUsbManager::Init()
{
    if (isInit) {
        PRINT_HILOGD("has init");
    }
    isInit = true;
    RefreshUsbPrinterDevice();
}

bool PrintUsbManager::isExistIppOverUsbPrinter(std::string printerName)
{
    PRINT_HILOGD("isExistIppOverUsbPrinter printerName = %{public}s", printerName.c_str());
    if (!printerName.empty() && printDeviceMap.find(printerName) != printDeviceMap.end()) {
        return true;
    }
    return false;
}


bool PrintUsbManager::isPrintDevice(USB::UsbDevice &usbdevice, std::string &printerName)
{
    int32_t configCount = usbdevice.GetConfigCount();
    std::vector<std::pair<int32_t, int32_t>> indexVec;
    int32_t ippusbInterfaceCount = 0;
    PRINT_HILOGD("name = %{public}s.", usbdevice.GetName().c_str());
    for (int32_t configIndex = 0; configIndex < configCount; configIndex++) {
        int32_t interfaceCount = static_cast<int32_t>(usbdevice.GetConfigs()[configIndex].GetInterfaceCount());
        PRINT_HILOGD("configIndex = %{public}d.", configIndex);
        for (int32_t interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++) {
            PRINT_HILOGD("interfaceIndex = %{public}d.", interfaceIndex);
            UsbInterface usbInterface = usbdevice.GetConfigs()[configIndex].GetInterfaces()[interfaceIndex];
            PRINT_HILOGD("isPrintDevice class = %{public}d, subclass = %{public}d, protocol = %{public}d",
                usbInterface.GetClass(), usbInterface.GetSubClass(), usbInterface.GetProtocol());
            bool isSupportIpp = (usbInterface.GetClass() == USB_DEVICE_CLASS_PRINT &&
                usbInterface.GetSubClass() == USB_DEVICE_SUBCLASS_PRINT &&
                usbInterface.GetProtocol() == USB_DEVICE_PROTOCOL_PRINT);
            if (isSupportIpp) {
                auto indexPair = std::make_pair(configIndex, interfaceIndex);
                indexVec.push_back(indexPair);
                ippusbInterfaceCount++;
            }
        }
    }
    // Two or more interfaces are required
    if (ippusbInterfaceCount >= USB_INTERFACE_MIN_COUNT) {
        printerName = GetProductName(usbdevice);
        PRINT_HILOGI("support IppPrint printerName = %{public}s.", printerName.c_str());
        if (printerName.empty()) {
            return false;
        }
        printerIndexMap[printerName] = indexVec;
        return true;
    }
    return false;
}

void PrintUsbManager::RefreshUsbPrinterDevice()
{
    std::vector<UsbDevice> devlist;
    int32_t ret = ERR_OK;
    if (isUsbEnable) {
        ret = UsbSrvClient::GetInstance().GetDevices(devlist);
    }
    if (ERR_OK != ret) {
        PRINT_HILOGE("RefreshDeviceList GetDevices failed with ret = %{public}d.", ret);
        return;
    } else if (devlist.empty()) {
        PRINT_HILOGE("RefreshDeviceList GetDevices empty with ret = %{public}d.", ret);
        return;
    }
    for (auto dev : devlist) {
        std::string printerName;
        if (isPrintDevice(dev, printerName)) {
            printDeviceMap[printerName] = dev;
        }
    }
}

std::string PrintUsbManager::GetProductName(UsbDevice &usbDevice)
{
    PRINT_HILOGI("getProductName dev.GetName() = %{public}s.", usbDevice.GetName().c_str());
    USBDevicePipe usbDevicePipe;
    int32_t openDeviceRet = UEC_OK;
    if (isUsbEnable) {
        openDeviceRet = UsbSrvClient::GetInstance().OpenDevice(usbDevice, usbDevicePipe);
    }
    PRINT_HILOGI("openDevice ret = %{public}d", openDeviceRet);
    if (openDeviceRet != UEC_OK) {
        PRINT_HILOGE("openDevice fail with ret = %{public}d", openDeviceRet);
        return "";
    }
    std::string productName =
        QueryPrinterInfoFromStringDescriptor(usbDevicePipe, USB_VALUE_DESCRIPTOR_INDEX_PRODUCT_NAME);
    std::string serialNumber =
        QueryPrinterInfoFromStringDescriptor(usbDevicePipe, USB_VALUE_DESCRIPTOR_INDEX_SERIAL_NUMBER);
    size_t len = serialNumber.length();
    if (len > HTTP_COMMON_CONST_VALUE_4) {
        serialNumber = serialNumber.substr(len - HTTP_COMMON_CONST_VALUE_4);
    }
    std::string printerName = productName + "-" + serialNumber;
    PRINT_HILOGI("getProductName printerName = %{public}s.", printerName.c_str());
    return printerName;
}

std::string PrintUsbManager::QueryPrinterInfoFromStringDescriptor(
    USBDevicePipe &usbDevicePipe, uint16_t indexInStringDescriptor)
{
    PRINT_HILOGI("enter QueryPrinterInfoFromStringDescriptor");
    uint8_t requestType = USB_REQUESTTYPE_DEVICE_TO_HOST;
    uint8_t request = USB_REQUEST_GET_DESCRIPTOR;
    uint16_t value = (USB_VALUE_DESCRIPTOR_TYPE_STRING << HTTP_COMMON_CONST_VALUE_8) | indexInStringDescriptor;
    uint16_t index = USB_INDEX_LANGUAGE_ID_ENGLISH;
    int32_t timeOut = HTTP_COMMON_CONST_VALUE_500;
    const HDI::Usb::V1_0::UsbCtrlTransfer tctrl = {requestType, request, value, index, timeOut};
    std::vector<uint8_t> bufferData(HTTP_COMMON_CONST_VALUE_100, 0);
    int32_t ret = 0;
    if (isUsbEnable) {
        ret = UsbSrvClient::GetInstance().ControlTransfer(usbDevicePipe, tctrl, bufferData);
    }
    if (ret != 0 || bufferData[INDEX_0] == 0 ||
        ((bufferData[INDEX_0] - HTTP_COMMON_CONST_VALUE_2) / HTTP_COMMON_CONST_VALUE_2) < 0) {
        PRINT_HILOGE("ControlTransfer failed ret = %{public}d, buffer length = %{public}d", ret, bufferData[0]);
        return "";
    }

    std::vector<uint8_t> arr((bufferData[INDEX_0] - HTTP_COMMON_CONST_VALUE_2) / HTTP_COMMON_CONST_VALUE_2);
    int arrIndex = 0;
    for (int i = INDEX_2; i < bufferData[INDEX_0];) {
        arr[arrIndex++] = bufferData[i];
        i += HTTP_COMMON_CONST_VALUE_2;
    }
    std::string printerInfo(arr.begin(), arr.end());
    PRINT_HILOGI("bufferData printerInfo: %{public}s\n", printerInfo.c_str());
    return printerInfo;
}

bool PrintUsbManager::AllocateInterface(const std::string &printerName, UsbDevice &usbdevice,
    USBDevicePipe &usbDevicePipe)
{
    PrinterTranIndex tranIndex;
    for (auto index : printerIndexMap[printerName]) {
        int32_t configIndex = index.first;
        int32_t interfaceIndex = index.second;
        UsbInterface ippInterface =
            usbdevice.GetConfigs()[configIndex].GetInterfaces()[interfaceIndex];
        int32_t ret = UEC_OK;
        if (isUsbEnable) {
            ret = UsbSrvClient::GetInstance().ClaimInterface(usbDevicePipe, ippInterface, true);
        }
        if (ret != UEC_OK) {
            PRINT_HILOGE("ClaimInterface fail, ret = %{public}d", ret);
            continue;
        }
        if (tranIndex.commonConfigIndex == INVAILD_VALUE) {
            tranIndex.commonConfigIndex = configIndex;
            tranIndex.commonInterfaceIndex = interfaceIndex;
        } else if (tranIndex.sendDocConfigIndex == INVAILD_VALUE) {
            tranIndex.sendDocConfigIndex = configIndex;
            tranIndex.sendDocInterfaceIndex = interfaceIndex;
            break;
        }
    }
    if (tranIndex.commonConfigIndex == INVAILD_VALUE || tranIndex.sendDocConfigIndex == INVAILD_VALUE) {
        PRINT_HILOGE("connect usb printerName = %{public}s fail!", printerName.c_str());
        if (tranIndex.commonConfigIndex != INVAILD_VALUE) {
            int32_t configIndex = tranIndex.commonConfigIndex;
            UsbInterface commonInterface =
                usbdevice.GetConfigs()[configIndex].GetInterfaces()[tranIndex.commonInterfaceIndex];
            if (isUsbEnable) {
                UsbSrvClient::GetInstance().ReleaseInterface(usbDevicePipe, commonInterface);
            }
        }
        if (isUsbEnable) {
            UsbSrvClient::GetInstance().Close(usbDevicePipe);
        }
        return false;
    }

    printPipeMap[printerName] = usbDevicePipe;
    printTranIndexMap[printerName] = tranIndex;
    return true;
}

bool PrintUsbManager::ConnectUsbPinter(const std::string &printerName)
{
    PRINT_HILOGD("connect usb printerName = %{public}s", printerName.c_str());
    if (!printerName.empty() && printPipeMap.find(printerName) != printPipeMap.end()) {
        PRINT_HILOGD("printerName = %{public}s is opened", printerName.c_str());
        return true;
    }
    if (!printerName.empty() && printDeviceMap.find(printerName) != printDeviceMap.end()) {
        UsbDevice usbdevice = printDeviceMap[printerName];
        USBDevicePipe usbDevicePipe;
        int32_t openDeviceRet = UEC_OK;
        if (isUsbEnable) {
            openDeviceRet = UsbSrvClient::GetInstance().OpenDevice(usbdevice, usbDevicePipe);
        }
        PRINT_HILOGD("openDevice ret = %{public}d", openDeviceRet);
        if (openDeviceRet == UEC_OK) {
            return AllocateInterface(printerName, usbdevice, usbDevicePipe);
        } else {
            PRINT_HILOGE("ipp usb openDevice fail with ret = %{public}d", openDeviceRet);
            return false;
        }
    }
    return false;
}

void PrintUsbManager::DisConnectUsbPinter(const std::string &printerName)
{
    if (!printerName.empty() && printDeviceMap.find(printerName) != printDeviceMap.end() &&
        printPipeMap.find(printerName) != printPipeMap.end() &&
        printTranIndexMap.find(printerName) != printTranIndexMap.end()) {
        UsbDevice usbdevice = printDeviceMap[printerName];
        USBDevicePipe usbDevicePipe = printPipeMap[printerName];
        PrinterTranIndex tranIndex = printTranIndexMap[printerName];
        UsbInterface commonInterface =
            usbdevice.GetConfigs()[tranIndex.commonConfigIndex].GetInterfaces()[tranIndex.commonInterfaceIndex];
        UsbInterface sendDocIterface =
            usbdevice.GetConfigs()[tranIndex.sendDocConfigIndex].GetInterfaces()[tranIndex.sendDocInterfaceIndex];
        if (isUsbEnable) {
            UsbSrvClient::GetInstance().ReleaseInterface(usbDevicePipe, commonInterface);
            UsbSrvClient::GetInstance().ReleaseInterface(usbDevicePipe, sendDocIterface);
            UsbSrvClient::GetInstance().Close(usbDevicePipe);
        }
        printPipeMap.erase(printerName);
        printTranIndexMap.erase(printerName);
    }
}

int32_t PrintUsbManager::BulkTransferWrite(std::string printerName, const Operation operation,
    std::vector<uint8_t> &vectorRequestBuffer)
{
    if (printDeviceMap.find(printerName) == printDeviceMap.end()) {
        return INVAILD_VALUE;
    }
    UsbDevice usbdevice = printDeviceMap[printerName];
    int32_t currentConfigIndex = INVAILD_VALUE;
    int32_t currentInterfaceIndex = INVAILD_VALUE;
    PrinterTranIndex tranIndex = printTranIndexMap[printerName];
    if (operation == Operation::Send_Document) {
        currentConfigIndex = tranIndex.sendDocConfigIndex;
        currentInterfaceIndex = tranIndex.sendDocInterfaceIndex;
    } else {
        currentConfigIndex = tranIndex.commonConfigIndex;
        currentInterfaceIndex = tranIndex.commonInterfaceIndex;
    }
    UsbInterface useInterface = usbdevice.GetConfigs()[currentConfigIndex].GetInterfaces()[currentInterfaceIndex];
    USBEndpoint point1 = useInterface.GetEndpoints().at(INDEX_0);
    USBEndpoint point2 = useInterface.GetEndpoints().at(INDEX_1);
    USBEndpoint pointWrite;
    if (point1.GetDirection() == 0) {
        pointWrite = point1;
    } else {
        pointWrite = point2;
    }
    USBDevicePipe usbDevicePipe = printPipeMap[printerName];
    int32_t writeRet = 0;
    if (isUsbEnable) {
        writeRet = UsbSrvClient::GetInstance().BulkTransfer(usbDevicePipe, pointWrite, vectorRequestBuffer,
            USB_BULKTRANSFER_WRITE_TIMEOUT);
    }
    return writeRet;
}

int32_t PrintUsbManager::BulkTransferRead(std::string printerName, const Operation operation,
    std::vector<uint8_t> &readTempBUffer)
{
    if (printDeviceMap.find(printerName) == printDeviceMap.end()) {
        return INVAILD_VALUE;
    }
    UsbDevice usbdevice = printDeviceMap[printerName];
    int32_t currentConfigIndex = INVAILD_VALUE;
    int32_t currentInterfaceIndex = INVAILD_VALUE;
    PrinterTranIndex tranIndex = printTranIndexMap[printerName];
    if (operation == Operation::Send_Document) {
        currentConfigIndex = tranIndex.sendDocConfigIndex;
        currentInterfaceIndex = tranIndex.sendDocInterfaceIndex;
    } else {
        currentConfigIndex = tranIndex.commonConfigIndex;
        currentInterfaceIndex = tranIndex.commonInterfaceIndex;
    }
    UsbInterface useInterface = usbdevice.GetConfigs()[currentConfigIndex].GetInterfaces()[currentInterfaceIndex];
    USBEndpoint point1 = useInterface.GetEndpoints().at(INDEX_0);
    USBEndpoint point2 = useInterface.GetEndpoints().at(INDEX_1);
    USBEndpoint pointRead;
    if (point1.GetDirection() == 0) {
        pointRead = point2;
    } else {
        pointRead = point1;
    }
    USBDevicePipe usbDevicePipe = printPipeMap[printerName];
    int32_t readFromUsbRes = 0;
    if (isUsbEnable) {
        readFromUsbRes = UsbSrvClient::GetInstance().BulkTransfer(usbDevicePipe, pointRead, readTempBUffer,
            USB_BULKTRANSFER_READ_TIMEOUT);
    }
    return readFromUsbRes;
}

void PrintUsbManager::DealUsbDevStatusChange(const std::string &devStr, bool isAttach)
{
    PRINT_HILOGD("DealUsbDevStatusChange isAttach = %{public}d, devStr = %{public}s.",
        isAttach, devStr.c_str());
    cJSON *devJson = cJSON_Parse(devStr.c_str());
    if (devJson == nullptr) {
        PRINT_HILOGE("Create devJson error");
        return;
    }
    UsbDevice *dev = new (std::nothrow) UsbDevice(devJson);
    if (dev == nullptr) {
        PRINT_HILOGE("Create dev error");
        cJSON_Delete(devJson);
        return;
    }
    if (!isAttach) {
        std::string printerName = GetPrinterName(dev->GetName());
        PRINT_HILOGI("DealUsbDevStatusChange detached dev->GetName() = %{public}s, printerName = %{public}s.",
            dev->GetName().c_str(), printerName.c_str());
        if (!printerName.empty()) {
            DisConnectUsbPinter(printerName);
            printDeviceMap.erase(printerName);
            printerIndexMap.erase(printerName);
        }
    } else {
        std::string printerName;
        if (isPrintDevice(*dev, printerName)) {
            printDeviceMap[printerName] = *dev;
            PRINT_HILOGI("DealUsbDevStatusChange attached dev->GetName() = %{public}s , printerName = %{public}s.",
                dev->GetName().c_str(), printerName.c_str());
        }
    }
    cJSON_Delete(devJson);
    delete dev;
    dev = nullptr;
}

std::string PrintUsbManager::GetPrinterName(const std::string &name)
{
    for (const auto& pair : printDeviceMap) {
        if (pair.second.GetName() == name) {
            return pair.first;
        }
    }
    return "";
}
}

#endif // IPPOVERUSB_ENABLE