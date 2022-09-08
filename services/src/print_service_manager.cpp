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
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
std::mutex PrintServiceManager::instanceLock_;
PrintServiceManager *PrintServiceManager::instance_ = nullptr;
PrintServiceManager::PrintServiceManager() {}

PrintServiceManager::~PrintServiceManager() {}

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

bool PrintServiceManager::On(
    const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener)
{
    PRINT_HILOGE("PrintServiceManager on started.");
    return true;
}

bool PrintServiceManager::Off(const std::string &type)
{
    PRINT_HILOGE("PrintServiceManager on started.");
    return true;
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

bool PrintServiceManager::QueryExtensionAbilityInfos(std::vector<PrintExtensionInfo> &arrayExtensionInfo)
{
    PRINT_HILOGE("PrintServiceManager QueryAllExtension enter.");
    PrintExtensionInfo printExtensionInfo;
    arrayExtensionInfo.push_back(printExtensionInfo);
    arrayExtensionInfo[NapiPrintUtils::ARGC_ZERO].SetExtensionId(NapiPrintUtils::MAX_ARGC);
    arrayExtensionInfo[NapiPrintUtils::ARGC_ZERO].SetVendorId(NapiPrintUtils::MAX_ARGC);
    std::string vendorName = "vendorName = print 1.0";
    std::string version = "version = 1.0.0";
    arrayExtensionInfo[NapiPrintUtils::ARGC_ZERO].SetVendorName(vendorName);
    arrayExtensionInfo[NapiPrintUtils::ARGC_ZERO].SetVendorIcon(NapiPrintUtils::MAX_ARGC);
    arrayExtensionInfo[NapiPrintUtils::ARGC_ZERO].SetVersion(version);
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

bool PrintServiceManager::AddPrinters(std::vector<PrinterInfo> arrayPrintInfo)
{
    PRINT_HILOGE("PrintServiceManager AddPrinters started.");
    return true;
}

bool PrintServiceManager::RemovePrinters(std::vector<PrinterInfo> arrayPrintInfo)
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

    printerCapability.SetColorMode(NapiPrintUtils::MAX_ARGC);
    printerCapability.SetDuplexMode(NapiPrintUtils::MAX_ARGC);

    PrintMargin PrintMargin;
    PrintMargin.SetTop(NapiPrintUtils::MAX_ARGC);
    PrintMargin.SetBottom(NapiPrintUtils::MAX_ARGC);
    PrintMargin.SetLeft(NapiPrintUtils::MAX_ARGC);
    PrintMargin.SetRight(NapiPrintUtils::MAX_ARGC);
    printerCapability.SetMinMargin(PrintMargin);

    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    pageSize.SetId("6");
    pageSize.SetName("name");
    pageSize.SetWidth(NapiPrintUtils::MAX_ARGC);
    pageSize.SetHeight(NapiPrintUtils::MAX_ARGC);
    pageSizeList.push_back(pageSize);

    printerCapability.SetPageSize(pageSizeList);

    std::vector<PrintResolution> resolutionList;
    PrintResolution res;
    res.SetId(NapiPrintUtils::MAX_ARGC);
    res.SetHorizontalDpi(NapiPrintUtils::MAX_ARGC);
    res.SetVerticalDpi(NapiPrintUtils::MAX_ARGC);
    resolutionList.push_back(res);
    printerCapability.SetResolution(resolutionList);

    printerCapability.Dump();
    PRINT_HILOGE("PrintServiceManager RequestPreview started.");
    return true;
}

void PrintServiceManager::InstallCallback(uint32_t taskId, PrintTaskCallback eventCb)
{
    PRINT_HILOGE("PrintServiceManager InstallCallback started.");
}
} // namespace OHOS::Print
