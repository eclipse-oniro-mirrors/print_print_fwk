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
const int DISCOVERY_INTERVAL_MS = 5000;

VendorPpdDriver::VendorPpdDriver() {}

VendorPpdDriver::~VendorPpdDriver()
{
    UnInit();
}

bool VendorPpdDriver::Init(IPrinterVendorManager *manager)
{
    if (!VendorDriverBase::Init(manager)) {
        PRINT_HILOGE("VendorDriverBase init fail");
        return false;
    }
    return true;
}

void VendorPpdDriver::UnInit()
{
    OnStopDiscovery();
    VendorDriverBase::UnInit();
}

std::string VendorPpdDriver::GetVendorName()
{
    return VENDOR_PPD_DRIVER;
}

bool VendorPpdDriver::OnQueryCapability(const std::string &printerId, int timeout)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    auto printerInfo = vendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (printerInfo != nullptr && TryConnectByPpdDriver(*printerInfo)) {
        PRINT_HILOGI("Connect by ppdDriver success.");
        return false;
    }
    return true;
}

int32_t VendorPpdDriver::OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    connectingVendorGroup = vendorName;
    connectingPrinterInfo = std::make_shared<PrinterInfo>(printerInfo);
    return 0;
}

bool VendorPpdDriver::QueryProperty(const std::string &printerId, const std::string &key, std::string &value)
{
    if (connectingPrinterInfo == nullptr) {
        PRINT_HILOGW("connectingPrinterInfo is null");
        return false;
    }
    if (connectingPrinterInfo->GetPrinterId() != printerId) {
        PRINT_HILOGW("not connecting printer");
        return false;
    }
    if (key == PRINTER_PROPERTY_KEY_CUPS_PPD_NAME) {
        auto makeAndModel = connectingPrinterInfo->GetPrinterMake();
        value = QueryPpdName(makeAndModel);
        return !value.empty();
    }
    return false;
}

std::string VendorPpdDriver::QueryPpdName(const std::string &makeAndModel)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return std::string();
    }
    std::string ppdName;
    if (!vendorManager->QueryPPDInformation(makeAndModel, ppdName)) {
        PRINT_HILOGW("QueryPPDInformation fail. printerMake = %{public}s", makeAndModel.c_str());
        return std::string();
    }
    return ppdName;
}

void VendorPpdDriver::UpdateAllPrinterStatus()
{
    // not need update vendor backend printer by monitor. use default status by discovered state.
    return;
}

void VendorPpdDriver::DiscoverBackendPrinters()
{
    std::vector<PrinterInfo> printers = {};
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    if (vendorManager->DiscoverBackendPrinters(GetVendorName(), printers) != E_PRINT_NONE) {
        PRINT_HILOGW("Discovery backend printer fail.");
        return;
    }
    std::unique_lock<std::mutex> lock(updateDiscoveryMutex_);
    for (auto &isDiscoveredPair : discoveredPrinters_) {
        isDiscoveredPair.second = false;
    }
    // add or update new printer is discovered
    for (const auto &printer : printers) {
        discoveredPrinters_[printer.GetPrinterId()] = true;
        vendorManager->AddPrinterToDiscovery(GetVendorName(), printer);
    }
    // remove non-discovered printer
    for (const auto &isDiscoveredPair : discoveredPrinters_) {
        if (!isDiscoveredPair.second) {
            vendorManager->RemovePrinterFromDiscovery(GetVendorName(), isDiscoveredPair.first);
        }
    }
}

void VendorPpdDriver::OnStartDiscovery()
{
    PRINT_HILOGD("OnStartDiscovery enter");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("OnStartDiscovery vendorManager is null.");
        return;
    }
    std::unique_lock<std::mutex> lock(discoveryStateChangeMutex_);
    if (!isDiscovering_) {
        isDiscovering_ = true;
        discoveryThread_ = std::thread(&VendorPpdDriver::DiscoveryProcess, this);
    } else {
        PRINT_HILOGW("allready start backend discovery.");
    }
}

void VendorPpdDriver::OnStopDiscovery()
{
    PRINT_HILOGD("OnStopDiscovery enter");
    std::unique_lock<std::mutex> lock(discoveryStateChangeMutex_);
    if (!isDiscovering_) {
        PRINT_HILOGW("already stop discovery");
        return;
    }
    isDiscovering_ = false;
    waitDiscoveryCondition_.notify_all();
    if (discoveryThread_.joinable()) {
        discoveryThread_.join();
    }
}

void VendorPpdDriver::DiscoveryProcess()
{
    PRINT_HILOGI("DiscoveryProcess Enter");
    while (WaitNext()) {
        DiscoverBackendPrinters();
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("VendorManager is null. DiscoveryProcess Quit");
        return;
    }
    std::unique_lock<std::mutex> lock(updateDiscoveryMutex_);
    for (const auto &isDiscoveredPair : discoveredPrinters_) {
        vendorManager->RemovePrinterFromDiscovery(GetVendorName(), isDiscoveredPair.first);
    }
    PRINT_HILOGI("DiscoveryProcess Quit");
}

bool VendorPpdDriver::WaitNext()
{
    {
        std::unique_lock<std::mutex> lock(waitDiscoveryMutex_);
        waitDiscoveryCondition_.wait_for(lock, std::chrono::milliseconds(DISCOVERY_INTERVAL_MS),
            [this] { return !isDiscovering_; });
    }
    if (!isDiscovering_) {
        return false;
    }
    return true;
}

bool VendorPpdDriver::TryConnectByPpdDriver(const PrinterInfo &printerInfo)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    OnPrinterDiscovered(GetVendorName(), printerInfo);
    std::string printerId = printerInfo.GetPrinterId();
    std::string ppdName;
    if (!QueryProperty(printerId, PRINTER_PROPERTY_KEY_CUPS_PPD_NAME, ppdName)) {
        PRINT_HILOGI("no matched ppd");
        return false;
    }
    if (vendorManager->AddPrinterToCupsWithPpd(GetVendorName(), VendorManager::ExtractPrinterId(printerId),
        ppdName, "") != EXTENSION_ERROR_NONE) {
        PRINT_HILOGI("AddPrinterToCupsWithPpd fail.");
        return false;
    }
    PRINT_HILOGI("AddPrinterToCupsWithPpd success.");
    return true;
}
