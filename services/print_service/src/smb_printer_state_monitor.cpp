/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <thread>
#include "print_system_data.h"
#include "smb_host_search_helper.h"
#include "smb_printer_discoverer.h"
#include "smb_printer_state_monitor.h"

namespace OHOS::Print {
constexpr int32_t CHECK_HOST_ALIVE_INTERVAL = 2;
SmbPrinterStateMonitor::~SmbPrinterStateMonitor()
{
    if (isMonitoring_.load()) {
        StopSmbPrinterStatusMonitor();
    }
}

SmbPrinterStateMonitor& SmbPrinterStateMonitor::GetInstance()
{
    static SmbPrinterStateMonitor instance;
    return instance;
}

void SmbPrinterStateMonitor::StartSmbPrinterStatusMonitor(std::function<void(const PrinterInfo& printerInfo)> notify)
{
    std::lock_guard<std::mutex> lock(threadMutex_);
    if (isMonitoring_.load()) {
        PRINT_HILOGI("The monitoring thread is running");
        return;
    }
    PRINT_HILOGI("start monitor caller apps");
    isMonitoring_.store(true);
    monitorThread_ = std::thread(&SmbPrinterStateMonitor::MonitorSmbPrinters, this, notify);
}

void SmbPrinterStateMonitor::StopSmbPrinterStatusMonitor()
{
    {
        std::lock_guard<std::mutex> lock(threadMutex_);
        if (!isMonitoring_.load()) {
            PRINT_HILOGI("Monitor is not running");
            return;
        }
        isMonitoring_.store(false);
    }
    
    if (monitorThread_.joinable()) {
        PRINT_HILOGI("Waiting for smb printer monitor thread to finish");
        monitorThread_.join();
        PRINT_HILOGI("smb printer Monitor thread stopped successfully");
    } else {
        PRINT_HILOGW("Monitor thread is not joinable");
    }
}


void SmbPrinterStateMonitor::MonitorSmbPrinters(std::function<void(const PrinterInfo& printerInfo)> notify)
{
    if (!notify) {
        PRINT_HILOGE("notify is nullptr");
        return;
    }
    SmbHostSearchHelper helper;
    do {
        std::unordered_map<std::string, std::pair<PrinterInfo, HostStatus>> localCopy;
        {
            std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
            localCopy = monitorSmbPrinters_;
        }
        std::unordered_set<std::string> uniqueIps;
        for (const auto& [id, localSmbPrinterPair] : localCopy) {
            std::string ip = SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(localSmbPrinterPair.first.GetPrinterId());
            uniqueIps.insert(ip);
        }
        std::unordered_map<std::string, HostStatus> hostStatusMap;
        for (const auto& ip : uniqueIps) {
            hostStatusMap[ip] = helper.TestSmbHostAlive(ip) ? HostStatus::ALIVE : HostStatus::DEAD;
        }
        std::vector<std::pair<PrinterInfo, HostStatus>> notifyPrinters;
        for (auto& [id, localSmbPrinterPair] : localCopy) {
            std::string ip = SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(id);
            auto testHostStatusResult = hostStatusMap.find(ip);
            if (testHostStatusResult == hostStatusMap.end()) {
                continue;
            }
            if (localSmbPrinterPair.second == testHostStatusResult->second) {
                continue;
            }
            uint32_t newPrinterStatus = testHostStatusResult->second == HostStatus::ALIVE ?
                PrinterStatus::PRINTER_STATUS_IDLE : PrinterStatus::PRINTER_STATUS_UNAVAILABLE;
            localSmbPrinterPair.first.SetPrinterStatus(newPrinterStatus);
            notifyPrinters.push_back({localSmbPrinterPair.first, testHostStatusResult->second});
        }
        {
            std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
            for (const auto& notifyPrinterPair : notifyPrinters) {
                auto it = monitorSmbPrinters_.find(notifyPrinterPair.first.GetPrinterId());
                if (it != monitorSmbPrinters_.end()) {
                    it->second = notifyPrinterPair;
                    notify(notifyPrinterPair.first);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_HOST_ALIVE_INTERVAL));
    } while (isMonitoring_.load());
}

void SmbPrinterStateMonitor::SetSmbPrinterInMonitorList(const PrinterInfo& info)
{
    std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
    std::string id = info.GetPrinterId();
    if (id.find("smb") == std::string::npos) {
        PRINT_HILOGE("is not smb printer");
        return;
    }
    HostStatus hostStatus = HostStatus::DEAD;
    if (info.GetPrinterStatus() != PrinterStatus::PRINTER_STATUS_UNAVAILABLE) {
        hostStatus = HostStatus::ALIVE;
    }
    monitorSmbPrinters_[id] = {info, hostStatus};
}

void SmbPrinterStateMonitor::EraseSmbPrinterInMonitorListById(const std::string& printerId)
{
    std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
    monitorSmbPrinters_.erase(printerId);
}
} // namespace OHOS::Print
