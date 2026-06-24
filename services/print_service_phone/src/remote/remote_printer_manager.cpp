/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "remote_printer_manager.h"
#include "remote_service_adapter.h"
#include "remote_constants.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_page_size.h"
#include "print_utils.h"
#include "print_service_ability.h"
#include <thread>
#include <chrono>
#include <algorithm>

namespace OHOS::Print {

namespace {
const std::vector<uint32_t> DEFAULT_QUALITY_LIST = {
    PRINT_QUALITY_DRAFT, PRINT_QUALITY_NORMAL, PRINT_QUALITY_HIGH
};

const std::vector<std::string> DEFAULT_MEDIA_TYPE_LIST = {
    "stationery", "stationery-recycled", "thick"
};

const std::vector<uint32_t> DEFAULT_DUPLEX_MODE_LIST = {
    DUPLEX_MODE_NONE, DUPLEX_MODE_LONG_EDGE, DUPLEX_MODE_SHORT_EDGE
};

std::vector<PrintPageSize> BuildDefaultPageSizeList()
{
    std::vector<PrintPageSize> pageSizeList;
    PrintPageSize pageSize;
    const PAGE_SIZE_ID pageSizeIds[] = {
        PAGE_SIZE_ID_ISO_A4, PAGE_SIZE_ID_ISO_A5, PAGE_SIZE_ID_ISO_A6,
        PAGE_SIZE_ID_JIS_B5, PAGE_SIZE_ID_JIS_B6,
        PAGE_SIZE_ID_NA_LETTER, PAGE_SIZE_ID_ROC_16K
    };
    for (const auto &id : pageSizeIds) {
        if (PrintPageSize::FindPageSizeById(id, pageSize)) {
            pageSizeList.push_back(pageSize);
        }
    }
    return pageSizeList;
}

const std::vector<PrintPageSize> DEFAULT_PAGE_SIZE_LIST = BuildDefaultPageSizeList();
}

RemotePrinterManager::RemotePrinterManager()
{
    PRINT_HILOGI("RemotePrinterManager constructor");
    serviceAdapter_ = RemoteServiceAdapter::GetInstance();
    
    std::call_once(initFlag_, [this]() {
        PRINT_CHECK_NULL_RETURN_VOID(serviceAdapter_);
        if (serviceAdapter_->BindService()) {
            PRINT_HILOGI("RemotePrinterManager initialized successfully");
        } else {
            PRINT_HILOGE("BindService failed in constructor");
        }
    });
}

RemotePrinterManager::~RemotePrinterManager()
{
    Destroy();
}

bool RemotePrinterManager::Destroy()
{
    PRINT_HILOGI("RemotePrinterManager Destroy");
    StopPrinterDiscovery();
    
    if (discoveryThread_.joinable()) {
        discoveryThread_.join();
    }
    
    std::lock_guard<std::mutex> lock(printerMapLock_);
    printerMap_.clear();
    return true;
}

PrinterStatus RemotePrinterManager::ConvertStatusToPrinterStatus(const std::string &statusStr)
{
    if (statusStr == REMOTE_STATUS_ONLINE) {
        return PRINTER_STATUS_IDLE;
    } else if (statusStr == REMOTE_STATUS_OFFLINE) {
        return PRINTER_STATUS_UNAVAILABLE;
    }
    PRINT_HILOGW("Unknown status: %{public}s, use UNAVAILABLE", statusStr.c_str());
    return PRINTER_STATUS_UNAVAILABLE;
}

void RemotePrinterManager::SetDefaultCapability(PrinterCapability &capability)
{
    capability.SetSupportedQuality(DEFAULT_QUALITY_LIST);
    capability.SetSupportedPageSize(DEFAULT_PAGE_SIZE_LIST);
    capability.SetSupportedMediaType(DEFAULT_MEDIA_TYPE_LIST);
    capability.SetSupportedDuplexMode(DEFAULT_DUPLEX_MODE_LIST);
}

bool RemotePrinterManager::BuildPrinterInfo(const Json::Value &item, PrinterInfo &printerInfo)
{
    if (!item.isObject()) {
        return false;
    }

    std::string devId;
    std::string devName;
    std::string statusStr;
    if (!PrintJsonUtil::FindJsonStringMember(item, "devId", devId)) {
        return false;
    }
    if (!PrintJsonUtil::FindJsonStringMember(item, "devName", devName)) {
        return false;
    }
    if (!PrintJsonUtil::FindJsonStringMember(item, "status", statusStr)) {
        return false;
    }
    if (!PrintJsonUtil::IsMember(item, "devInfo") || !item["devInfo"].isObject()) {
        return false;
    }

    Json::Value devInfo = item["devInfo"];
    std::string sn;
    std::string prodId;
    if (!PrintJsonUtil::FindJsonStringMember(devInfo, "sn", sn)) {
        return false;
    }
    if (!PrintJsonUtil::FindJsonStringMember(devInfo, "prodId", prodId)) {
        return false;
    }

    printerInfo.SetPrinterId(devId);
    printerInfo.SetPrinterName(devName);
    printerInfo.SetAlias(devName);
    printerInfo.SetPrinterStatus(static_cast<uint32_t>(ConvertStatusToPrinterStatus(statusStr)));
    printerInfo.SetUri(sn);
    printerInfo.SetPrinterUuid(sn);
    printerInfo.SetPrinterMake(prodId);

    PrinterCapability capability;
    SetDefaultCapability(capability);
    printerInfo.SetCapability(capability);

    if (PrintJsonUtil::IsMember(item, "services")) {
        std::string servicesStr = PrintJsonUtil::WriteString(item["services"]);
        printerInfo.SetOptionField("services", servicesStr);
    }
    return true;
}

bool RemotePrinterManager::StartPrinterDiscovery()
{
    PRINT_HILOGI("RemotePrinterManager StartPrinterDiscovery");
    std::lock_guard<std::mutex> lock(controlMutex_);
    if (isDiscoveryRunning_) {
        PRINT_HILOGW("Discovery already running, trigger immediate query");
        int32_t result = serviceAdapter_->RequestPrinterList();
        PRINT_HILOGI("Immediate RequestPrinterList result: %{public}d", result);
        return true;
    }
    
    if (discoveryThread_.joinable()) {
        discoveryThread_.join();
    }
    
    isDiscoveryRunning_ = true;
    discoveryThread_ = std::thread([this]() {
        DiscoveryLoop();
    });
    return true;
}

bool RemotePrinterManager::StopPrinterDiscovery()
{
    PRINT_HILOGI("RemotePrinterManager StopPrinterDiscovery");
    std::lock_guard<std::mutex> lock(controlMutex_);
    isDiscoveryRunning_ = false;
    return true;
}

void RemotePrinterManager::DiscoveryLoop()
{
    PRINT_HILOGI("RemotePrinterManager DiscoveryLoop started");
    while (isDiscoveryRunning_) {
        int32_t result = serviceAdapter_->RequestPrinterList();
        PRINT_HILOGI("RequestPrinterList result: %{public}d", result);
        std::this_thread::sleep_for(std::chrono::milliseconds(DISCOVERY_INTERVAL_MS));
    }
    PRINT_HILOGI("RemotePrinterManager DiscoveryLoop stopped");
}

std::shared_ptr<PrinterInfo> RemotePrinterManager::GetPrinterInfo(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(printerMapLock_);
    auto it = printerMap_.find(printerId);
    if (it != printerMap_.end()) {
        return it->second;
    }
    return nullptr;
}

bool RemotePrinterManager::UpdatePrinterStatus(const std::string &printerId, PrinterStatus status)
{
    PRINT_HILOGI("RemotePrinterManager UpdatePrinterStatus: %{public}s, status=%{public}d",
                 printerId.c_str(), status);
    
    std::lock_guard<std::mutex> lock(printerMapLock_);
    auto it = printerMap_.find(printerId);
    if (it == printerMap_.end()) {
        PRINT_HILOGW("Printer not found: %{public}s", printerId.c_str());
        return false;
    }
    
    it->second->SetPrinterStatus(static_cast<uint32_t>(status));
    return true;
}

bool RemotePrinterManager::OnPrinterListReceived(const Json::Value &jsonArray)
{
    PRINT_HILOGI("RemotePrinterManager OnPrinterListReceived");
    
    std::vector<std::string> currentDevIds;
    
    for (const auto &item : jsonArray) {
        PrinterInfo printerInfo;
        if (!BuildPrinterInfo(item, printerInfo)) {
            continue;
        }
        
        std::string devId = printerInfo.GetPrinterId();
        PRINT_HILOGI("[Printer: %{public}s] discovered", devId.c_str());
        currentDevIds.push_back(devId);
        
        std::lock_guard<std::mutex> lock(printerMapLock_);
        printerMap_[devId] = std::make_shared<PrinterInfo>(printerInfo);
    }

    for (const auto &devId : currentDevIds) {
        int32_t result = serviceAdapter_->RequestPrinterStatus(devId);
        PRINT_HILOGI("RequestPrinterStatus for %{public}s result: %{public}d", devId.c_str(), result);
    }
    
    RemoveDeprecatedPrinters(currentDevIds);
    return true;
}

void RemotePrinterManager::RemoveDeprecatedPrinters(const std::vector<std::string> &currentDevIds)
{
    std::lock_guard<std::mutex> lock(printerMapLock_);
    for (auto it = printerMap_.begin(); it != printerMap_.end();) {
        if (std::find(currentDevIds.begin(), currentDevIds.end(), it->first) == currentDevIds.end()) {
            PRINT_HILOGI("[Printer: %{public}s] removed", it->first.c_str());
            std::string globalId = PrintUtils::GetGlobalId(REMOTE_EXT_BUNDLE_NAME, it->first);
            PrintServiceAbility::GetInstance()->RemoveRemotePrinterInfo(globalId);
            it = printerMap_.erase(it);
        } else {
            ++it;
        }
    }
}

bool RemotePrinterManager::OnPrinterStatusReceived(const Json::Value &jsonArray)
{
    PRINT_HILOGI("RemotePrinterManager OnPrinterStatusReceived");
    
    auto serviceAbility = PrintServiceAbility::GetInstance();
    PRINT_CHECK_NULL_AND_RETURN(serviceAbility, false);
    
    for (const auto &item : jsonArray) {
        if (!item.isObject()) {
            continue;
        }
        
        std::string devId;
        std::string statusStr;
        
        if (!PrintJsonUtil::FindJsonStringMember(item, "devId", devId)) {
            continue;
        }
        
        PRINT_HILOGI("Printer devId: %{public}s", devId.c_str());
        
        if (!PrintJsonUtil::FindJsonStringMember(item, "status", statusStr)) {
            continue;
        }
        
        PrinterStatus printerStatus = ConvertStatusToPrinterStatus(statusStr);
        UpdatePrinterStatus(devId, printerStatus);
        
        auto printerInfo = GetPrinterInfo(devId);
        if (printerInfo == nullptr) {
            PRINT_HILOGW("Printer not found in cache: %{public}s", devId.c_str());
            continue;
        }
        
        std::string globalId = PrintUtils::GetGlobalId(REMOTE_EXT_BUNDLE_NAME, devId);
        if (printerStatus == PRINTER_STATUS_IDLE) {
            serviceAbility->AddRemotePrinterInfo(*printerInfo, REMOTE_EXT_BUNDLE_NAME);
        } else if (printerStatus == PRINTER_STATUS_UNAVAILABLE) {
            serviceAbility->RemoveRemotePrinterInfo(globalId);
        }
    }
    return true;
}

void RemotePrinterManager::ClearAllPrinters()
{
    PRINT_HILOGI("RemotePrinterManager ClearAllPrinters");
    
    auto serviceAbility = PrintServiceAbility::GetInstance();
    PRINT_CHECK_NULL_RETURN_VOID(serviceAbility);
    
    std::lock_guard<std::mutex> lock(printerMapLock_);
    for (const auto &printer : printerMap_) {
        std::string globalId = PrintUtils::GetGlobalId(REMOTE_EXT_BUNDLE_NAME, printer.first);
        PRINT_HILOGI("[Printer: %{public}s] removed", printer.first.c_str());
        serviceAbility->RemoveRemotePrinterInfo(globalId);
    }
    printerMap_.clear();
}

} // namespace OHOS::Print