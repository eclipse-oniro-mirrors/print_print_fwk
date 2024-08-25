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

#ifndef VENDOR_MANAGER_H
#define VENDOR_MANAGER_H

#include <map>
#include <string>
#include <mutex>
#include <thread>
#include "vendor_driver_base.h"

namespace OHOS {
namespace Print {

class IPrintServiceAbility {
public:
    virtual bool AddVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) = 0;
    virtual bool UpdateVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) = 0;
    virtual bool RemoveVendorPrinterFromDiscovery(const std::string &globalVendorName,
                                                  const std::string &printerId) = 0;
    virtual bool AddVendorPrinterToCupsWithPpd(const std::string &globalVendorName, const std::string &printerId,
                                               const std::string &ppdData) = 0;
    virtual bool RemoveVendorPrinterFromCups(const std::string &vendorName, const std::string &printerId) = 0;
    virtual bool OnVendorStatusUpdate(const std::string &globalVendorName, const std::string &printerId,
                                      const PrinterVendorStatus &status) = 0;
    virtual bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) = 0;
    virtual bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) = 0;
};

class VendorManager : public IPrinterVendorManager {
public:
    static std::string GetGlobalVendorName(const std::string &vendorName);
    static std::string GetGlobalPrinterId(const std::string &globalVendorName, const std::string &printerId);
    static std::string ExtractVendorName(const std::string &globalVendorName);
    static std::string ExtractGlobalVendorName(const std::string &globalPrinterId);
    static std::string ExtractPrinterId(const std::string &globalPrinterId);
    VendorManager();
    ~VendorManager();
    bool Init(IPrintServiceAbility *sa, bool loadDefault = true);
    void UnInit();
    void StartDiscovery();
    void StopDiscovery();
    bool LoadVendorDriver(std::shared_ptr<VendorDriverBase> vendorDriver);
    bool UnloadVendorDriver(const std::string &vendorName);
    bool ConnectPrinter(const std::string &globalPrinterId);
    bool ConnectPrinterByIp(const std::string &globalPrinterIp, const std::string &protocol);
    bool QueryPrinterInfo(const std::string &globalPrinterId, int timeout);
    int32_t AddPrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    int32_t UpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    int32_t RemovePrinterFromDiscovery(const std::string &vendorName, const std::string &printerId) override;
    int32_t AddPrinterToCupsWithPpd(const std::string &vendorName, const std::string &printerId,
                                    const std::string &ppdData) override;
    int32_t RemovePrinterFromCups(const std::string &vendorName, const std::string &printerId) override;
    bool OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                const PrinterVendorStatus &status) override;
    bool OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                             const std::string &ppdData) override;
    bool MonitorPrinterStatus(const std::string &globalPrinterId, bool on);
    void StartStatusMonitor();
    void StopStatusMonitor();
    bool IsConnectingPrinter(const std::string &id, const std::string &uri) override;
    void SetConnectingPrinter(ConnectMethod method, const std::string &printer) override;
    void ClearConnectingPrinter() override;
    bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) override;
    bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) override;

private:
    std::shared_ptr<VendorDriverBase> FindDriverByPrinterId(const std::string &globalPrinterId);
    std::shared_ptr<VendorDriverBase> FindDriverByVendorName(const std::string &vendorName);
    void StatusMonitorProcess();
    void UpdateAllPrinterStatus();

private:
    std::atomic<bool> defaultLoaded{false};
    IPrintServiceAbility *printServiceAbility = nullptr;
    std::map<std::string, std::shared_ptr<VendorDriverBase>> vendorMap;
    std::mutex vendorMapMutex;
    std::thread statusMonitorThread;
    bool statusMonitorOn = false;
    std::mutex statusMonitorMutex;
    std::condition_variable statusMonitorCondition;
    std::string connectingPrinterId;
    bool isConnecting = false;
    ConnectMethod connectingMethod = ID_AUTO;
    std::string connectingPrinter;
    std::mutex simpleObjectMutex;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_MANAGER_H
