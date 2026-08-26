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
constexpr int32_t THREAD_WAIT_INTERVAL_MS = 100;
constexpr int32_t THREAD_WAIT_MAX_COUNT = 1800;

// Wait for monitor thread to exit, maximum wait time is 3 minutes (1800 * 100ms)
SmbPrinterStateMonitor::~SmbPrinterStateMonitor()
{
    isMonitoring_.store(false);
    int waitCount = 0;
    while (threadRunning_.load() && waitCount < THREAD_WAIT_MAX_COUNT) {
        std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_WAIT_INTERVAL_MS));
        waitCount++;
    }
}

SmbPrinterStateMonitor& SmbPrinterStateMonitor::GetInstance()
{
    static SmbPrinterStateMonitor instance;
    return instance;
}

void SmbPrinterStateMonitor::StartSmbPrinterStatusMonitor(std::function<void(const PrinterInfo& printerInfo)> notify)
{
    if (!notify) {
        PRINT_HILOGE("notify is nullptr");
        return;
    }
    bool expected = false;
    if (!isMonitoring_.compare_exchange_strong(expected, true)) {
        PRINT_HILOGI("The monitoring thread is running");
        return;
    }
    PRINT_HILOGI("start monitor caller apps");
    std::thread(&SmbPrinterStateMonitor::MonitorSmbPrinters, this, notify).detach();
}

void SmbPrinterStateMonitor::MonitorSmbPrinters(std::function<void(const PrinterInfo& printerInfo)> notify)
{
    threadRunning_.store(true);
    do {
        std::unordered_map<std::string, std::pair<PrinterInfo, HostStatus>> localCopy;
        {
            std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
            if (monitorSmbPrinters_.empty()) {
                PRINT_HILOGI("monitorSmbPrinters_ is empty, stop monitoring");
                isMonitoring_.store(false);
                break;
            }
            localCopy = monitorSmbPrinters_;
        }
        auto hostStatusMap = GetHostStatusMap(localCopy);
        auto notifyPrinters = BuildNotifyPrintersList(localCopy, hostStatusMap);
        UpdateAndNotifyPrinters(notifyPrinters, notify);
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_HOST_ALIVE_INTERVAL));
    } while (isMonitoring_.load());
    threadRunning_.store(false);
}

std::unordered_map<std::string, SmbPrinterStateMonitor::HostStatus> SmbPrinterStateMonitor::GetHostStatusMap(
    const std::unordered_map<std::string, std::pair<PrinterInfo, HostStatus>>& localCopy)
{
    std::unordered_set<std::string> uniqueIps;
    for (const auto& [id, localSmbPrinterPair] : localCopy) {
        std::string ip = SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(localSmbPrinterPair.first.GetPrinterId());
        uniqueIps.insert(ip);
    }
    SmbHostSearchHelper helper;
    std::unordered_map<std::string, HostStatus> hostStatusMap;
    // TestSmbHostAlive has a default timeout of 1 second per IP
    for (const auto& ip : uniqueIps) {
        hostStatusMap[ip] = helper.TestSmbHostAlive(ip) ? HostStatus::ALIVE : HostStatus::DEAD;
    }
    return hostStatusMap;
}

std::vector<std::pair<PrinterInfo, SmbPrinterStateMonitor::HostStatus>> SmbPrinterStateMonitor::BuildNotifyPrintersList(
    const std::unordered_map<std::string, std::pair<PrinterInfo, HostStatus>>& localCopy,
    const std::unordered_map<std::string, HostStatus>& hostStatusMap)
{
    std::vector<std::pair<PrinterInfo, HostStatus>> notifyPrinters;
    for (const auto& [id, localSmbPrinterPair] : localCopy) {
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
        PrinterInfo newInfo = localSmbPrinterPair.first;
        newInfo.SetPrinterStatus(newPrinterStatus);
        notifyPrinters.push_back({newInfo, testHostStatusResult->second});
    }
    return notifyPrinters;
}

void SmbPrinterStateMonitor::UpdateAndNotifyPrinters(
    const std::vector<std::pair<PrinterInfo, HostStatus>>& notifyPrinters,
    std::function<void(const PrinterInfo& printerInfo)> notify)
{
    {
        std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
        for (const auto& notifyPrinterPair : notifyPrinters) {
            monitorSmbPrinters_[notifyPrinterPair.first.GetPrinterId()] = notifyPrinterPair;
        }
    }
    for (const auto& notifyPrinterPair : notifyPrinters) {
        notify(notifyPrinterPair.first);
    }
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

bool SmbPrinterStateMonitor::IsSmbPrinterOnline(const std::string& printerId)
{
    std::lock_guard<std::mutex> lock(monitorSmbPrintersLock_);
    auto it = monitorSmbPrinters_.find(printerId);
    if (it == monitorSmbPrinters_.end()) {
        PRINT_HILOGW("Smb printer not found in monitor list");
        return false;
    }
    bool isOnline = it->second.second == HostStatus::ALIVE;
    return isOnline;
}
} // namespace OHOS::Print
