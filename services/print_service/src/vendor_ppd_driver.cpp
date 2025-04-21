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

#include "vendor_ppd_driver.h"
#include "print_log.h"

using namespace OHOS::Print;

VendorPpdDriver::VendorPpdDriver() {}

VendorPpdDriver::~VendorPpdDriver() {}

bool VendorPpdDriver::OnQueryCapability(const std::string &printerId, int timeout)
{
    PRINT_HILOGI("OnQueryCapability enter.");
    PRINT_HILOGD("OnQueryCapability printerId=%{private}s", printerId.c_str());
    std::vector<std::string> ppds;
    if (!QueryPpdByPrinterId(printerId, ppds)) {
        PRINT_HILOGW("OnQueryCapability query ppd fail. printerId = %{private}s", printerId.c_str());
        return false;
    }
    if (!AddPrinterToCups(printerId, ppds[0])) {
        PRINT_HILOGE("OnQueryCapability add printer fail.");
        return false;
    }
    std::shared_ptr<PrinterInfo> printerInfo = QueryPrinterCapabilityFromPpd(printerId, ppds[0]);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("get printerInfo failed.");
        return false;
    }
    printerInfo->SetPrinterId(printerId);
    if (!UpdateCapability(printerInfo)) {
        PRINT_HILOGE("OnQueryCapability update capability fail.");
        return false;
    }
    PRINT_HILOGI("OnQueryCapability success.");
    return true;
}

bool VendorPpdDriver::OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys)
{
    std::vector<std::string> ppds;
    if (propertyKeys.empty()) {
        PRINT_HILOGW("OnQueryProperties propertyKeys is empty.");
        return false;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGE("OnQueryProperties vendorManager is null.");
        return false;
    }
    // ppds always contains only one ppd from function QueryPPDInformation
    if (!vendorManager->QueryPPDInformation(propertyKeys[0].c_str(), ppds)) {
        PRINT_HILOGE("OnQueryProperties query ppd fail. printerId = %{public}s, printerMake = %{public}s",
            printerId.c_str(), propertyKeys[0].c_str());
        return false;
    }
    PRINT_HILOGD("OnQueryProperties ppd=%{public}s", ppds[0].c_str());
    auto iter = privatePrinterPpdMap.find(printerId);
    if (iter != privatePrinterPpdMap.end()) {
        privatePrinterPpdMap.erase(iter);
    }
    privatePrinterPpdMap.insert(std::make_pair(printerId, std::vector(ppds)));
    return true;
}

std::string VendorPpdDriver::GetVendorName()
{
    return VENDOR_PPD_DRIVER;
}

bool VendorPpdDriver::QueryPpdByPrinterId(const std::string &printerId, std::vector<std::string> &ppds)
{
    PRINT_HILOGI("QueryPpdByPrinterId enter.");
    auto iter = privatePrinterPpdMap.find(printerId);
    if (iter != privatePrinterPpdMap.end()) {
        ppds = std::vector(iter->second);
        PRINT_HILOGI("QueryPpdByPrinterId success.");
        return true;
    }
    PRINT_HILOGW("QueryPpdByPrinterId fail.");
    return false;
}

bool VendorPpdDriver::AddPrinterToCups(const std::string &printerId, const std::string &ppdData)
{
    PRINT_HILOGI("AddPrinterToCups enter.");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("AddPrinterToCups vendorManager is null.");
        return false;
    }
    std::shared_ptr<PrinterInfo> discoveredPrinterInfo = vendorManager->
        QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (discoveredPrinterInfo == nullptr) {
        PRINT_HILOGW("AddPrinterToCups query fail.");
        return false;
    }
    auto printerInfo = *discoveredPrinterInfo;
    PRINT_HILOGD("AddPrinterToCups uri=%{public}s, name=%{public}s", printerInfo.GetUri().c_str(),
        printerInfo.GetPrinterName().c_str());
    if (vendorManager->AddPrinterToCupsWithPpd(GetVendorName(), printerInfo.GetPrinterId(), ppdData) !=
        EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("AddPrinterToCups add printer fail.");
        return false;
    }
    PRINT_HILOGI("AddPrinterToCups success.");
    return true;
}

std::shared_ptr<PrinterInfo> VendorPpdDriver::QueryPrinterCapabilityFromPpd(const std::string &printerId,
    const std::string &ppdData)
{
    PRINT_HILOGI("QueryPrinterCapabilityFromPpd enter.");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("QueryPrinterCapabilityFromPpd vendorManager is null.");
        return nullptr;
    }
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    PrinterInfo info;
    if (vendorManager->QueryPrinterInfoByPrinterId(GetVendorName(), printerId, info) != E_PRINT_NONE) {
        PRINT_HILOGE("QueryPrinterCapabilityFromPpd query printer info fail.");
        return nullptr;
    }
    *printerInfo = info;
    PRINT_HILOGI("QueryPrinterCapabilityFromPpd success.");
    return printerInfo;
}

bool VendorPpdDriver::UpdateCapability(std::shared_ptr<PrinterInfo> printerInfo)
{
    PRINT_HILOGI("UpdateCapability enter.");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("UpdateCapability vendorManager is null.");
        return false;
    }
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo fail");
        return false;
    }
    PRINT_HILOGI("UpdateCapability valid printerInfo.");
    if (vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("UpdateCapability UpdatePrinterToDiscovery fail.");
        return false;
    }
    PRINT_HILOGI("UpdateCapability success.");
    return true;
}