/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "print_service_manager.h"
#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <queue>
#include <mutex>
#include <thread>
#include <utility>
#include "unistd.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

namespace OHOS::Print {
std::mutex PrintServiceManager::instanceLock_;
PrintServiceManager *PrintServiceManager::instance_ = nullptr;
PrintServiceManager::PrintServiceManager()
{
}

PrintServiceManager::~PrintServiceManager()
{
}

PrintServiceManager *PrintServiceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) PrintServiceManager;
        }
    }
    return instance_;
}

int32_t PrintServiceManager::Dummy()
{
    int32_t taskId = -1;
    return taskId;
}

bool PrintServiceManager::ConnectPrinter(uint32_t printerId)
{
    PRINT_HILOGE("PrintServiceManager ConnectPrinter started.");
    return true;
}

bool PrintServiceManager::DisconnectPrinter(uint32_t printerId)
{
    PRINT_HILOGE("PrintServiceManager DisconnectPrinter started.");
    return true;
}

bool PrintServiceManager::StartDiscoverPrinter(std::vector<uint32_t> extensionList)
{
    PRINT_HILOGE("PrintServiceManager StartDiscoverPrinter started.");
    return true;
}

bool PrintServiceManager::StopDiscoverPrinter()
{
    PRINT_HILOGE("PrintServiceManager StopDiscoverPrinter started.");
    return true;
}

bool PrintServiceManager::QueryExtensionAbilityInfos(std::vector<PrinterExtensionInfo> &arrayExtensionInfo)
{
    PRINT_HILOGE("PrintServiceManager QueryAllExtension enter.");
    PrinterExtensionInfo printerExtensionInfo;
    arrayExtensionInfo.push_back(printerExtensionInfo);
    arrayExtensionInfo[0].SetExtensionId(5);
    arrayExtensionInfo[0].SetVendorId(55);
    std::string vendorName = "vendorName = print 1.0";
    std::string version = "version = 1.0.0";
    arrayExtensionInfo[0].SetVendorName(vendorName);
    arrayExtensionInfo[0].SetVendorIcon(555);
    arrayExtensionInfo[0].SetVersion(version);
    PRINT_HILOGE("PrintServiceManager QueryAllExtension started.");
    return true;
}

bool PrintServiceManager::StartPrintJob(PrintJob jobinfo)
{
    PRINT_HILOGE("PrintServiceManager StartPrintJob started.");
    return true;
}

bool PrintServiceManager::CancelPrintJob(PrintJob jobinfo)
{
    PRINT_HILOGE("PrintServiceManager CancelPrintJob started.");
    return true;
}

bool PrintServiceManager::AddPrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    PRINT_HILOGE("PrintServiceManager AddPrinters started.");
    return true;
}

bool PrintServiceManager::RemovePrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    PRINT_HILOGE("PrintServiceManager RemovePrinters started.");
    return true;
}

bool PrintServiceManager::UpdatePrinterState(uint32_t printerId, uint32_t state)
{
    PRINT_HILOGE("PrintServiceManager UpdatePrinterState started.");
    return true;
}

bool PrintServiceManager::UpdatePrinterJobState(uint32_t jobId, uint32_t state)
{
    PRINT_HILOGE("PrintServiceManager UpdatePrinterJobState started.");
    return true;
}

bool PrintServiceManager::RequestPreview(PrintJob jobinfo, std::string &previewResult)
{
    previewResult = "Preview OK!";
    PRINT_HILOGE("PrintServiceManager RequestPreview started.");
    return true;
}

bool PrintServiceManager::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability)
{
    auto instance = PrintServiceManager::GetInstance();
    if (instance == nullptr) {
        PRINT_HILOGE("PrintServiceManager is null");
        return false;
    }

    printerCapability.SetColorMode(10);
    printerCapability.SetDuplexMode(11);
    
    PrintMargin printMargin;
    printMargin.SetTop(5);
    printMargin.SetBottom(5);
    printMargin.SetLeft(5);
    printMargin.SetRight(5);   
    printerCapability.SetMinMargin(printMargin);

    PrinterPageSize printerPageSize;
    printerPageSize.SetId(6);
    printerPageSize.SetName("name");
    printerPageSize.SetWidth(6);
    printerPageSize.SetHeight(6);
    printerCapability.SetPageSize(printerPageSize);

    PrinterResolution printerResolution;
    printerResolution.SetId(6);
    printerResolution.SetHorizontalDpi(6);
    printerResolution.SetVerticalDpi(6);
    printerCapability.SetResolution(printerResolution);

    printerCapability.Dump();
    printerCapability.GetMinMargin().Dump();
    printerCapability.GetPageSize()[0].Dump();
    printerCapability.GetResolution()[0].Dump();
    PRINT_HILOGE("PrintServiceManager RequestPreview started.");
    return true;
}
} // namespace OHOS::Request::Print
