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

#ifndef PRINT_SMB_PRINTER_STATE_MONITOR
#define PRINT_SMB_PRINTER_STATE_MONITOR

#include <string>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <future>
#include "app_mgr_interface.h"
#include "printer_info.h"

namespace OHOS::Print {
class SmbPrinterStateMonitor {
public:
    static SmbPrinterStateMonitor& GetInstance();
    void StartSmbPrinterStatusMonitor(std::function<void(const PrinterInfo& printerInfo)> notify);
    void StopSmbPrinterStatusMonitor();
    void SetSmbPrinterInMonitorList(const PrinterInfo& info);
    void EraseSmbPrinterInMonitorListById(const std::string& printerId);

private:
    enum class HostStatus;

    SmbPrinterStateMonitor() = default;
    ~SmbPrinterStateMonitor();
    void MonitorSmbPrinters(std::function<void(const PrinterInfo& printerInfo)> notify);

    std::unordered_map<std::string, PrinterInfo> monitorSmbPrinters_;
    std::mutex monitorSmbPrintersLock_;
    std::atomic<bool> isMonitoring_{false};
    std::thread monitorThread_;
    std::mutex threadMutex_;
};

} // namespace OHOS::Print
#endif // PRINT_SMB_PRINTER_STATE_MONITOR