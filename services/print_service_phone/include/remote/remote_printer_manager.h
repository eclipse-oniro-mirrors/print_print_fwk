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

#ifndef REMOTE_PRINTER_MANAGER_H
#define REMOTE_PRINTER_MANAGER_H

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <memory>
#include <thread>
#include "printer_info.h"
#include "printer_capability.h"
#include "print_constant.h"
#include "json/json.h"
#include "refbase.h"
#include "remote_service_adapter.h"

namespace OHOS::Print {

class PrintServiceAbility;

class RemotePrinterManager {
public:
    RemotePrinterManager();
    ~RemotePrinterManager();
    
    bool Destroy();
    
    bool StartPrinterDiscovery();
    bool StopPrinterDiscovery();
    
    std::shared_ptr<PrinterInfo> GetPrinterInfo(const std::string &printerId);
    
    bool UpdatePrinterStatus(const std::string &printerId, PrinterStatus status);
    
    bool OnPrinterListReceived(const Json::Value &jsonArray);
    bool OnPrinterStatusReceived(const Json::Value &jsonArray);
    void ClearAllPrinters();
    
    static PrinterStatus ConvertStatusToPrinterStatus(const std::string &statusStr);

private:
    void DiscoveryLoop();
    static void SetDefaultCapability(PrinterCapability &capability);
    static bool BuildPrinterInfo(const Json::Value &item, PrinterInfo &printerInfo);
    void RemoveDeprecatedPrinters(const std::vector<std::string> &currentDevIds);
    
    std::map<std::string, std::shared_ptr<PrinterInfo>> printerMap_;
    std::mutex printerMapLock_;
    std::mutex controlMutex_;
    RemoteServiceAdapter& serviceAdapter_;
    std::thread discoveryThread_;
    std::once_flag initFlag_;
    
    std::atomic<bool> isDiscoveryRunning_{false};
};

} // namespace OHOS::Print

#endif // REMOTE_PRINTER_MANAGER_H