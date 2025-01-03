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

#include <chrono>
#include "vendor_manager.h"
#include "vendor_helper.h"
#include "vendor_bsuni_driver.h"
#include "vendor_ipp_everywhere.h"
#include "vendor_ppd_driver.h"
#include "vendor_wlan_group.h"
#include "print_log.h"
#include "print_utils.h"

using namespace OHOS::Print;
namespace {
const std::string VENDOR_MANAGER_PREFIX = "fwk.";
const std::string GLOBAL_ID_DELIMITER = ":";
const int MONITOR_CHECK_INTERVAL_MS = 1000;
const size_t IP_LENGTH_MIN = 7;
}

VendorManager::VendorManager()
{
    wlanGroupDriver = std::make_shared<VendorWlanGroup>(this);
}

VendorManager::~VendorManager()
{
    UnInit();
}

std::string VendorManager::GetGlobalVendorName(const std::string &vendorName)
{
    return VENDOR_MANAGER_PREFIX + vendorName;
}
std::string VendorManager::GetGlobalPrinterId(const std::string &globalVendorName, const std::string &printerId)
{
    return globalVendorName + GLOBAL_ID_DELIMITER + printerId;
}
std::string VendorManager::ExtractVendorName(const std::string &globalVendorName)
{
    auto pos = globalVendorName.find(VENDOR_MANAGER_PREFIX);
    if (pos != 0 || globalVendorName.length() <= VENDOR_MANAGER_PREFIX.length()) {
        return "";
    }
    return globalVendorName.substr(VENDOR_MANAGER_PREFIX.length());
}

std::string VendorManager::ExtractGlobalVendorName(const std::string &globalPrinterId)
{
    auto pos = globalPrinterId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }
    return globalPrinterId.substr(0, pos);
}

std::string VendorManager::ExtractPrinterId(const std::string &globalPrinterId)
{
    auto pos = globalPrinterId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos || globalPrinterId.length() <= pos + 1) {
        return globalPrinterId;
    }
    return globalPrinterId.substr(pos + 1);
}

bool VendorManager::Init(IPrintServiceAbility *sa, bool loadDefault)
{
    PRINT_HILOGI("Init enter");
    printServiceAbility = sa;
    if (!loadDefault) {
        return true;
    }
    bool expectLoaded = false;
    if (!defaultLoaded.compare_exchange_strong(expectLoaded, true)) {
        PRINT_HILOGI("load already");
        return true;
    }
    PRINT_HILOGI("load default vendor...");
    if (wlanGroupDriver != nullptr) {
        wlanGroupDriver->Init(this);
        wlanGroupDriver->OnCreate();
    }
    auto vendorBsUni = std::make_shared<VendorBsuniDriver>();
    if (!LoadVendorDriver(vendorBsUni)) {
        PRINT_HILOGW("BsUni driver load fail");
    }
    auto vendorIppEverywhere = std::make_shared<VendorIppEveryWhere>();
    if (!LoadVendorDriver(vendorIppEverywhere)) {
        PRINT_HILOGW("IppEverywhere driver load fail");
    }
    auto vendorPpdDriver = std::make_shared<VendorPpdDriver>();
    if (!LoadVendorDriver(vendorPpdDriver)) {
        PRINT_HILOGW("ppd driver load fail");
    }
    PRINT_HILOGI("Init quit");
    return true;
}

void VendorManager::UnInit()
{
    PRINT_HILOGI("UnInit enter");
    StopStatusMonitor();
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    for (auto const &pair : vendorMap) {
        PRINT_HILOGD("UnInit %{public}s", pair.first.c_str());
        if (pair.second == nullptr) {
            PRINT_HILOGW("vendor extension is null");
            continue;
        }
        pair.second->OnDestroy();
        pair.second->UnInit();
    }
    vendorMap.clear();
    if (wlanGroupDriver != nullptr) {
        wlanGroupDriver->OnDestroy();
        wlanGroupDriver->UnInit();
    }
    printServiceAbility = nullptr;
    defaultLoaded = false;
    PRINT_HILOGI("UnInit quit");
}

bool VendorManager::LoadVendorDriver(std::shared_ptr<VendorDriverBase> vendorDriver)
{
    if (vendorDriver == nullptr) {
        PRINT_HILOGW("vendorDriver is null");
        return false;
    }
    if (!vendorDriver->Init(this)) {
        PRINT_HILOGW("vendorDriver init fail");
        return false;
    }
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    vendorMap.insert(std::make_pair(vendorDriver->GetVendorName(), vendorDriver));
    vendorDriver->OnCreate();
    return true;
}
bool VendorManager::UnloadVendorDriver(const std::string &vendorName)
{
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    auto iter = vendorMap.find(vendorName);
    if (iter == vendorMap.end()) {
        return false;
    }
    auto vendorDriver = iter->second;
    vendorMap.erase(iter);
    if (vendorDriver != nullptr) {
        vendorDriver->OnDestroy();
        vendorDriver->UnInit();
    }
    return true;
}

bool VendorManager::ConnectPrinter(const std::string &globalPrinterId)
{
    PRINT_HILOGI("ConnectPrinter enter");
    std::string printerId = ExtractPrinterId(globalPrinterId);
    if (printerId.empty()) {
        PRINT_HILOGW("empty printer id");
        return false;
    }
    auto vendorDriver = FindDriverByPrinterId(globalPrinterId);
    if (vendorDriver == nullptr) {
        PRINT_HILOGW("vendorDriver is null");
        return false;
    }
    PRINT_HILOGD("OnQueryCapability: %{public}s", printerId.c_str());
    return vendorDriver->OnQueryCapability(printerId, 0);
}

bool VendorManager::ConnectPrinterByIp(const std::string &printerIp, const std::string &protocol)
{
    PRINT_HILOGI("ConnectPrinterByIp enter");
    if (printerIp.size() < IP_LENGTH_MIN) {
        PRINT_HILOGW("ip length incorrect");
        return false;
    }
    if (wlanGroupDriver == nullptr) {
        PRINT_HILOGE("no driver to connect printer by ip");
        return false;
    }
    return wlanGroupDriver->OnQueryCapabilityByIp(printerIp, protocol);
}

bool VendorManager::QueryPrinterInfo(const std::string &globalPrinterId, int timeout)
{
    PRINT_HILOGI("QueryPrinterInfo enter");
    std::string printerId = ExtractPrinterId(globalPrinterId);
    if (printerId.empty()) {
        PRINT_HILOGW("empty printer id");
        return false;
    }
    auto vendorDriver = FindDriverByPrinterId(globalPrinterId);
    if (vendorDriver == nullptr) {
        PRINT_HILOGW("vendorDriver is null");
        return false;
    }
    PRINT_HILOGD("OnQueryCapability: %{public}s", printerId.c_str());
    vendorDriver->OnQueryCapability(printerId, timeout);
    PRINT_HILOGI("QueryPrinterInfo quit");
    return true;
}

void VendorManager::StartDiscovery()
{
    PRINT_HILOGI("StartDiscovery enter");
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    for (auto const &pair : vendorMap) {
        PRINT_HILOGD("StartDiscovery %{public}s", pair.first.c_str());
        if (pair.second == nullptr) {
            PRINT_HILOGW("vendor extension is null");
            continue;
        }
        pair.second->OnStartDiscovery();
    }
    PRINT_HILOGI("StartDiscovery quit");
}
void VendorManager::StopDiscovery()
{
    PRINT_HILOGI("StopDiscovery enter");
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    for (auto const &pair : vendorMap) {
        if (pair.second == nullptr) {
            PRINT_HILOGW("vendor extension is null");
            continue;
        }
        pair.second->OnStopDiscovery();
    }
    PRINT_HILOGI("StopDiscovery quit");
}

int32_t VendorManager::AddPrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    PRINT_HILOGI("AddPrinterToDiscovery enter");
    if (vendorName == VENDOR_BSUNI_DRIVER && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->OnPrinterDiscovered(vendorName, printerInfo);
    }
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    if (!printServiceAbility->AddVendorPrinterToDiscovery(GetGlobalVendorName(vendorName), printerInfo)) {
        PRINT_HILOGW("AddPrinterToDiscovery fail");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    PRINT_HILOGI("AddPrinterToDiscovery quit");
    return EXTENSION_ERROR_NONE;
}

int32_t VendorManager::UpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    PRINT_HILOGI("UpdatePrinterToDiscovery enter");
    if (vendorName == VENDOR_BSUNI_DRIVER && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->OnUpdatePrinterToDiscovery(vendorName, printerInfo);
    }
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    auto targetVendorName = IsWlanGroupDriver(printerInfo.GetPrinterId()) ? VENDOR_WLAN_GROUP : vendorName;
    std::string globalVendorName = GetGlobalVendorName(targetVendorName);
    std::string printerId = printerInfo.GetPrinterId();
    if (GetConnectingMethod(printerId) == IP_AUTO && IsConnectingPrinter(printer, "") &&
        printServiceAbility->AddIpPrinterToSystemData(globalVendorName, printerInfo)) {
        PRINT_HILOGI("AddIpPrinterToSystemData succeed");
        return EXTENSION_ERROR_NONE;
    }
    if (!printServiceAbility->UpdateVendorPrinterToDiscovery(globalVendorName, printerInfo)) {
        PRINT_HILOGW("UpdatePrinterToDiscovery fail");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    PRINT_HILOGI("UpdatePrinterToDiscovery quit");
    return EXTENSION_ERROR_NONE;
}

int32_t VendorManager::RemovePrinterFromDiscovery(const std::string &vendorName, const std::string &printerId)
{
    PRINT_HILOGI("RemovePrinterFromDiscovery enter");
    if (vendorName == VENDOR_BSUNI_DRIVER && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->OnPrinterRemoved(vendorName, printerId);
    }
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    if (!printServiceAbility->RemoveVendorPrinterFromDiscovery(GetGlobalVendorName(vendorName), printerId)) {
        PRINT_HILOGW("RemovePrinterFromDiscovery fail");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    PRINT_HILOGI("RemovePrinterFromDiscovery quit");
    return EXTENSION_ERROR_NONE;
}

int32_t VendorManager::AddPrinterToCupsWithPpd(const std::string &vendorName, const std::string &printerId,
                                               const std::string &ppdData)
{
    PRINT_HILOGI("AddPrinterToCupsWithPpd enter");
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    auto targetVendorName = IsWlanGroupDriver(ExtractPrinterId(printerId)) ? VENDOR_WLAN_GROUP : vendorName;
    std::string globalVendorName = GetGlobalVendorName(targetVendorName);
    if (IsPrivatePpdDriver(vendorName)) {
        PRINT_HILOGD("AddPrinterToCupsWithPpd vendorName=%{public}s", vendorName.c_str());
        PRINT_HILOGD("AddPrinterToCupsWithPpd printerId=%{public}s", printerId.c_str());
        if (!printServiceAbility->AddVendorPrinterToCupsWithSpecificPpd(globalVendorName,
            VendorManager::ExtractPrinterId(printerId), ppdData)) {
            PRINT_HILOGW("AddPrinterToCupsWithPpd fail");
            return EXTENSION_ERROR_CALLBACK_FAIL;
        }
    } else {
        if (!printServiceAbility->AddVendorPrinterToCupsWithPpd(globalVendorName, printerId, ppdData)) {
            PRINT_HILOGW("AddPrinterToCupsWithPpd fail");
            return EXTENSION_ERROR_CALLBACK_FAIL;
        }
    }
    PRINT_HILOGI("AddPrinterToCupsWithPpd quit");
    return EXTENSION_ERROR_NONE;
}

int32_t VendorManager::RemovePrinterFromCups(const std::string &vendorName, const std::string &printerId)
{
    PRINT_HILOGI("RemovePrinterFromCups enter");
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    auto targetVendorName = IsWlanGroupDriver(printerId) ? VENDOR_WLAN_GROUP : vendorName;
    std::string globalVendorName = GetGlobalVendorName(targetVendorName);
    if (!printServiceAbility->RemoveVendorPrinterFromCups(globalVendorName, printerId)) {
        PRINT_HILOGW("RemovePrinterFromCups fail");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    PRINT_HILOGI("RemovePrinterFromCups quit");
    return EXTENSION_ERROR_NONE;
}

bool VendorManager::OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                                        const std::string &ppdData)
{
    PRINT_HILOGI("OnPrinterPpdQueried enter");
    if (vendorName == VENDOR_BSUNI_DRIVER && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->OnPrinterPpdQueried(vendorName, printerId, ppdData);
    }
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return false;
    }
    std::string globalVendorName = GetGlobalVendorName(vendorName);
    std::string globalPrinterId = GetGlobalPrinterId(globalVendorName, printerId);
    PRINT_HILOGD("global printer id %{public}s", globalPrinterId.c_str());
    if (!IsConnectingPrinter(globalPrinterId, "")) {
        PRINT_HILOGW("not connecting");
        return false;
    }
    if (GetConnectingMethod(printerId) == IP_AUTO &&
        printServiceAbility->AddIpPrinterToCupsWithPpd(globalVendorName, printerId, ppdData)) {
        PRINT_HILOGI("AddIpPrinterToCupsWithPpd succeed");
        return true;
    }
    if (!printServiceAbility->AddVendorPrinterToCupsWithPpd(globalVendorName, printerId, ppdData)) {
        PRINT_HILOGW("AddPrinterToCupsWithPpd fail");
        return false;
    }
    PRINT_HILOGI("OnPrinterPpdQueried quit");
    return true;
}

bool VendorManager::OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                           const PrinterVendorStatus &status)
{
    auto targetVendorName = IsWlanGroupDriver(printerId) ? VENDOR_WLAN_GROUP : vendorName;
    std::string globalVendorName = GetGlobalVendorName(targetVendorName);
    if (printServiceAbility != nullptr) {
        return printServiceAbility->OnVendorStatusUpdate(globalVendorName, printerId, status);
    }
    return true;
}

std::shared_ptr<VendorDriverBase> VendorManager::FindDriverByPrinterId(const std::string &globalPrinterId)
{
    std::string globalVendorName = ExtractGlobalVendorName(globalPrinterId);
    std::string vendorName = ExtractVendorName(globalVendorName);
    if (vendorName.empty()) {
        PRINT_HILOGW("Invalid printer id");
        return nullptr;
    }
    return FindDriverByVendorName(vendorName);
}

std::shared_ptr<VendorDriverBase> VendorManager::FindDriverByVendorName(const std::string &vendorName)
{
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    if (vendorName == VENDOR_WLAN_GROUP) {
        return wlanGroupDriver;
    }
    auto iter = vendorMap.find(vendorName);
    if (iter == vendorMap.end()) {
        PRINT_HILOGW("cannot find vendor extension: %{public}s", vendorName.c_str());
        return nullptr;
    }
    return iter->second;
}

void VendorManager::StartStatusMonitor()
{
    PRINT_HILOGI("StartStatusMonitor Enter");
    {
        std::unique_lock<std::mutex> lock(statusMonitorMutex);
        if (statusMonitorOn) {
            PRINT_HILOGW("already on");
            return;
        }
        statusMonitorOn = true;
    }
    PRINT_HILOGI("StartStatusMonitor Now");
    statusMonitorThread = std::thread(&VendorManager::StatusMonitorProcess, this);
    PRINT_HILOGI("StartStatusMonitor Quit");
}

void VendorManager::StopStatusMonitor()
{
    PRINT_HILOGI("StopStatusMonitor Enter");
    {
        std::unique_lock<std::mutex> lock(statusMonitorMutex);
        statusMonitorOn = false;
    }
    statusMonitorCondition.notify_one();
    if (statusMonitorThread.joinable()) {
        statusMonitorThread.join();
    }
    PRINT_HILOGI("StopStatusMonitor Quit");
}

void VendorManager::StatusMonitorProcess()
{
    PRINT_HILOGI("StatusMonitorProcess Enter");
    while (WaitNext()) {
        UpdateAllPrinterStatus();
    }
    PRINT_HILOGI("StatusMonitorProcess Quit");
}

void VendorManager::UpdateAllPrinterStatus()
{
    std::lock_guard<std::mutex> lock(vendorMapMutex);
    for (auto const &pair : vendorMap) {
        if (pair.second == nullptr) {
            PRINT_HILOGW("vendor extension is null");
            continue;
        }
        pair.second->UpdateAllPrinterStatus();
    }
}

bool VendorManager::WaitNext()
{
    std::unique_lock<std::mutex> lock(statusMonitorMutex);
    if (!statusMonitorOn) {
        return false;
    }
    statusMonitorCondition.wait_for(lock, std::chrono::milliseconds(MONITOR_CHECK_INTERVAL_MS));
    if (!statusMonitorOn) {
        return false;
    }
    return true;
}

bool VendorManager::IsPrivatePpdDriver(const std::string &vendorName)
{
    return vendorName == VENDOR_PPD_DRIVER;
}

bool VendorManager::MonitorPrinterStatus(const std::string &globalPrinterId, bool on)
{
    std::string globalVendorName = ExtractGlobalVendorName(globalPrinterId);
    std::string printerId = ExtractPrinterId(globalPrinterId);
    if (globalVendorName.empty() || printerId.empty()) {
        PRINT_HILOGW("invalid printer id: %{private}s", globalPrinterId.c_str());
        return false;
    }
    std::string vendorName = ExtractVendorName(globalVendorName);
    if (vendorName.empty()) {
        PRINT_HILOGW("vendor name empty");
        return false;
    }
    auto vendorDriver = FindDriverByVendorName(vendorName);
    if (vendorDriver == nullptr) {
        PRINT_HILOGW("vendor driver is null");
        return false;
    }
    return vendorDriver->MonitorPrinterStatus(printerId, on);
}

bool VendorManager::IsConnectingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri)
{
    if (globalPrinterIdOrIp.find(VENDOR_BSUNI_DRIVER) != std::string::npos && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->IsConnectingPrinter(globalPrinterIdOrIp, uri);
    }
    PRINT_HILOGI("IsConnectingPrinter globalPrinterIdOrIp: %{public}s, connectingPrinter: %{public}s",
        globalPrinterIdOrIp.c_str(), connectingPrinter.c_str());
    std::lock_guard<std::mutex> lock(simpleObjectMutex);
    if (isConnecting && !connectingPrinter.empty()) {
        if (connectingMethod == ID_AUTO) {
            return globalPrinterIdOrIp == connectingPrinter;
        } else if (connectingMethod == IP_AUTO) {
            return (globalPrinterIdOrIp.find(connectingPrinter) != std::string::npos) ||
                (connectingPrinter.find(globalPrinterIdOrIp) != std::string::npos);
        } else {
            return uri.find(connectingPrinter) != std::string::npos;
        }
    }
    return false;
}

void VendorManager::SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp)
{
    if (globalPrinterIdOrIp.find(VENDOR_BSUNI_DRIVER) != std::string::npos && wlanGroupDriver != nullptr) {
        wlanGroupDriver->SetConnectingPrinter(method, globalPrinterIdOrIp);
        return;
    }
    std::lock_guard<std::mutex> lock(simpleObjectMutex);
    connectingMethod = method;
    connectingPrinter = globalPrinterIdOrIp;
    isConnecting = true;
}

void VendorManager::ClearConnectingPrinter()
{
    PRINT_HILOGD("ClearConnectingPrinter");
    std::lock_guard<std::mutex> lock(simpleObjectMutex);
    isConnecting = false;
}

bool VendorManager::QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap)
{
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return false;
    }
    return printServiceAbility->QueryPrinterCapabilityByUri(uri, printerCap);
}

bool VendorManager::QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status)
{
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("printServiceAbility is null");
        return false;
    }
    return printServiceAbility->QueryPrinterStatusByUri(uri, status);
}

std::shared_ptr<PrinterInfo> VendorManager::QueryDiscoveredPrinterInfoById(const std::string &vendorName,
    const std::string &printerId)
{
    auto targetVendorName = IsWlanGroupDriver(printerId) ? VENDOR_WLAN_GROUP : vendorName;
    auto globalPrinterId = PrintUtils::GetGlobalId(VendorManager::GetGlobalVendorName(targetVendorName), printerId);
    return printServiceAbility->QueryDiscoveredPrinterInfoById(globalPrinterId);
}

int32_t VendorManager::QueryPrinterInfoByPrinterId(const std::string &vendorName, const std::string &printerId,
    PrinterInfo &info)
{
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("QueryPrinterInfoByPrinterId printServiceAbility is null");
        return false;
    }
    auto targetVendorName = IsWlanGroupDriver(printerId) ? VENDOR_WLAN_GROUP : vendorName;
    auto globalPrinterId = PrintUtils::GetGlobalId(VendorManager::GetGlobalVendorName(targetVendorName), printerId);
    return printServiceAbility->QueryPrinterInfoByPrinterId(globalPrinterId, info);
}

bool VendorManager::QueryPPDInformation(const char *makeModel, std::vector<std::string> &ppds)
{
    if (printServiceAbility == nullptr) {
        PRINT_HILOGW("QueryPPDInformation printServiceAbility is null");
        return false;
    }
    return printServiceAbility->QueryPPDInformation(makeModel, ppds);
}

bool VendorManager::IsWlanGroupDriver(const std::string &bothPrinterId)
{
    if (wlanGroupDriver == nullptr) {
        return false;
    }
    return wlanGroupDriver->IsGroupDriver(bothPrinterId);
}

ConnectMethod VendorManager::GetConnectingMethod(const std::string &globalPrinterIdOrIp)
{
    if (globalPrinterIdOrIp.find(VENDOR_BSUNI_DRIVER) != std::string::npos && wlanGroupDriver != nullptr) {
        return wlanGroupDriver->GetConnectingMethod(globalPrinterIdOrIp);
    }
    if (!IsConnectingPrinter(globalPrinterIdOrIp, "")) {
        PRINT_HILOGW("not connecting");
        return ID_AUTO;
    }
    return connectingMethod;
}