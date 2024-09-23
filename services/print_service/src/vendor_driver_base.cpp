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

#include <vector>
#include "vendor_driver_base.h"
#include "vendor_helper.h"
#include "vendor_manager.h"
#include "print_log.h"

namespace {
const int MONITOR_CHECK_INTERVAL_MS = 15000;
const int MONITOR_OFFLINE_TIMEOUT_MS = 60000;
}

using namespace OHOS::Print;

VendorDriverBase::VendorDriverBase() {}

VendorDriverBase::~VendorDriverBase() {}

bool VendorDriverBase::Init(IPrinterVendorManager *manager)
{
    vendorManager = manager;
    return true;
}
void VendorDriverBase::UnInit()
{
    vendorManager = nullptr;
}

void VendorDriverBase::OnCreate() {}
void VendorDriverBase::OnDestroy() {}

void VendorDriverBase::OnStartDiscovery() {}
void VendorDriverBase::OnStopDiscovery() {}

bool VendorDriverBase::OnQueryCapability(const std::string &printerId, int timeout)
{
    return false;
}
bool VendorDriverBase::OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol)
{
    return false;
}
bool VendorDriverBase::OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys)
{
    return false;
}

void VendorDriverBase::UpdateAllPrinterStatus()
{
    std::lock_guard<std::mutex> lock(statusMapMutex);
    uint64_t currentTime = GetNowTime();
    for (auto const &pair : vendorStatusMap) {
        auto vendorStatus = pair.second;
        if (vendorStatus == nullptr) {
            PRINT_HILOGW("status is null, %{private}s", pair.first.c_str());
            continue;
        }
        if (currentTime < vendorStatus->lastCheckTime + MONITOR_CHECK_INTERVAL_MS) {
            continue;
        }
        if (currentTime < vendorStatus->lastUpdateTime + MONITOR_CHECK_INTERVAL_MS) {
            continue;
        }
        vendorStatus->lastCheckTime = currentTime;
        std::vector<std::string> list;
        list.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
        OnQueryProperties(pair.first, list);
        if (currentTime < vendorStatus->lastUpdateTime + MONITOR_OFFLINE_TIMEOUT_MS) {
            continue;
        }
        vendorStatus->state = PRINTER_UNAVAILABLE;
        if (vendorManager != nullptr) {
            vendorManager->OnPrinterStatusChanged(GetVendorName(), pair.first, *vendorStatus);
        }
    }
}

bool VendorDriverBase::MonitorPrinterStatus(const std::string &printerId, bool on)
{
    std::lock_guard<std::mutex> lock(statusMapMutex);
    auto iter = vendorStatusMap.find(printerId);
    if (iter == vendorStatusMap.end()) {
        if (on) {
            vendorStatusMap[printerId] = std::make_shared<PrinterVendorStatus>();
            PRINT_HILOGD("monitor on: %{public}s", printerId.c_str());
            return true;
        }
    } else {
        if (!on) {
            vendorStatusMap.erase(iter);
            PRINT_HILOGD("monitor off: %{public}s", printerId.c_str());
            return true;
        }
    }
    return false;
}

std::shared_ptr<PrinterVendorStatus> VendorDriverBase::GetMonitorVendorStatus(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(statusMapMutex);
    auto iter = vendorStatusMap.find(printerId);
    if (iter != vendorStatusMap.end()) {
        return iter->second;
    }
    return nullptr;
}

std::string VendorDriverBase::GetGlobalVendorName()
{
    return VendorManager::GetGlobalVendorName(GetVendorName());
}

std::string VendorDriverBase::GetGlobalPrinterId(const std::string &printerId)
{
    return VendorManager::GetGlobalPrinterId(GetGlobalVendorName(), printerId);
}

void VendorDriverBase::OnPrinterStateQueried(const std::string &printerId, Print_PrinterState state)
{
    PRINT_HILOGD("state queried: %{public}d for %{public}s", static_cast<int>(state), printerId.c_str());
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    auto vendorStatus = GetMonitorVendorStatus(printerId);
    if (vendorStatus != nullptr) {
        vendorStatus->state = state;
        bool updated = vendorManager->OnPrinterStatusChanged(GetVendorName(), printerId, *vendorStatus);
        vendorStatus->lastUpdateTime = GetNowTime();
        if (state == PRINTER_IDLE && !updated) {
            OnQueryCapability(printerId, 0);
        }
    } else {
        PRINT_HILOGW("vendorStatus is null");
    }
}