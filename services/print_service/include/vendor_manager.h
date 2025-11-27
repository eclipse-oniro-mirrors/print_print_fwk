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
#include "vendor_driver_group.h"

namespace OHOS {
namespace Print {

class IPrintServiceAbility {
public:
    virtual bool AddVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) = 0;
    virtual bool UpdateVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) = 0;
    virtual bool RemoveVendorPrinterFromDiscovery(const std::string &globalVendorName,
                                                  const std::string &printerId) = 0;
    virtual bool AddVendorPrinterToCupsWithPpd(const std::string &globalVendorName, const std::string &printerId,
                                               const std::string &ppdName, const std::string &ppdData) = 0;
    virtual bool RemoveVendorPrinterFromCups(const std::string &vendorName, const std::string &printerId) = 0;
    virtual bool OnVendorStatusUpdate(const std::string &globalVendorName, const std::string &printerId,
                                      const PrinterVendorStatus &status) = 0;
    virtual bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) = 0;
    virtual bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) = 0;
    virtual std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &printerId) = 0;
    virtual std::shared_ptr<PrinterInfo> QueryConnectingPrinterInfoById(const std::string &printerId) = 0;
    virtual int32_t QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info) = 0;
    virtual std::vector<std::string> QueryAddedPrintersByIp(const std::string &printerIp) = 0;
    virtual bool QueryPPDInformation(const std::string &makeModel, std::string &ppdName) = 0;
    virtual bool AddIpPrinterToSystemData(const std::string &globalVendorName, const PrinterInfo &info) = 0;
    virtual bool AddIpPrinterToCupsWithPpd(const std::string &globalVendorName, const std::string &printerId,
                                           const std::string &ppdName, const std::string &ppdData) = 0;
    virtual int32_t DiscoverBackendPrinters(std::vector<PrinterInfo> &printers) = 0;
    virtual void AddPrintEvent(const std::string &printerId, const std::string &eventType, int32_t eventCode) = 0;
};

class PrintServiceAbility;

class VendorManager : public IPrinterVendorManager {
public:
    static std::string GetGlobalVendorName(const std::string &vendorName);
    static std::string GetGlobalPrinterId(const std::string &globalVendorName, const std::string &printerId);
    static std::string ExtractVendorName(const std::string &globalVendorName);
    static std::string ExtractGlobalVendorName(const std::string &globalPrinterId);
    static std::string ExtractPrinterId(const std::string &globalPrinterId);
    VendorManager();
    ~VendorManager();
    bool Init(sptr<PrintServiceAbility> sa, bool loadDefault = true);
    void UnInit();
    void StartDiscovery();
    void StopDiscovery();
    bool LoadVendorDriver(std::shared_ptr<VendorDriverBase> vendorDriver);
    bool UnloadVendorDriver(const std::string &vendorName);
    bool ConnectPrinterByIp(const std::string &globalPrinterIp, const std::string &protocol);
    bool QueryPrinterInfo(const std::string &globalPrinterId, int timeout);
    int32_t AddPrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    int32_t UpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    int32_t RemovePrinterFromDiscovery(const std::string &vendorName, const std::string &printerId) override;
    int32_t AddPrinterToCupsWithPpd(const std::string &vendorName, const std::string &printerId,
                                    const std::string &ppdName, const std::string &ppdData) override;
    int32_t RemovePrinterFromCups(const std::string &vendorName, const std::string &printerId) override;
    bool OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                const PrinterVendorStatus &status) override;
    bool OnPrinterCapabilityQueried(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    bool OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                             const std::string &ppdName, const std::string &ppdData) override;
    bool MonitorPrinterStatus(const std::string &globalPrinterId, bool on);
    void StartStatusMonitor();
    void StopStatusMonitor();
    bool IsConnectingPrinter(const std::string &globalPrinterIdOrIP, const std::string &uri) override;
    ConnectMethod GetConnectingMethod(const std::string &globalPrinterIdOrIp) override;
    void SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIP) override;
    void ClearConnectingPrinter() override;
    bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) override;
    std::string GetConnectingPrinter() override;
    std::string GetConnectingPpdName() override;
    std::string GetConnectingProtocol() override;
    void ClearConnectingPpdName() override;
    void ClearConnectingProtocol() override;
    bool IsQueryingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri) override;
    void SetQueryPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp) override;
    bool OnQueryCallBackEvent(const PrinterInfo &info) override;
    bool ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
        const std::string &ppdName) override;
    bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) override;
    std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &vendorName,
        const std::string &printerId) override;
    int32_t QueryPrinterInfoByPrinterId(const std::string &vendorName, const std::string &printerId,
        PrinterInfo &info) override;
    std::vector<std::string> QueryAddedPrintersByIp(const std::string &printerIp) override;
    bool QueryPPDInformation(const std::string &makeModel, std::string &ppdName) override;
    bool ConnectPrinterByIdAndPpd(const std::string &printerId, const std::string &protocol,
        const std::string &ppdName) override;
    std::shared_ptr<VendorDriverBase> FindDriverByPrinterId(const std::string &globalPrinterId);
    std::shared_ptr<VendorDriverBase> FindDriverByVendorName(const std::string &vendorName);
    int32_t DiscoverBackendPrinters(const std::string &vendorName, std::vector<PrinterInfo> &printers) override;
    void AddPrintEvent(const std::string &vendorName, const std::string &printerId,
        const std::string &eventType, int32_t eventCode) override;
    bool IsBsunidriverSupport(const PrinterInfo &printerInfo) override;
#ifdef ENTERPRISE_ENABLE
    bool IsEnterprise() override;
    void SwitchSpace();
    void UpdateIsEnterprise(bool isEnterprise);
#endif  // ENTERPRISE_ENABLE

private:
    void StatusMonitorProcess();
    void UpdateAllPrinterStatus();
    bool WaitNext();
    bool IsPrivatePpdDriver(const std::string &vendorName);
    bool IsWlanGroupDriver(const std::string &bothPrinterId);

private:
    std::atomic<bool> defaultLoaded{false};
    sptr<PrintServiceAbility> printServiceAbility;
    std::map<std::string, std::shared_ptr<VendorDriverBase>> vendorMap;
    std::mutex vendorMapMutex;
    std::shared_ptr<VendorDriverGroup> wlanGroupDriver = nullptr;
    std::thread statusMonitorThread;
    bool statusMonitorOn = false;
    std::mutex statusMonitorMutex;
    std::condition_variable statusMonitorCondition;
    ConnectState connectingState = ConnectState::STATE_NONE;
    std::string connectingPrinterId;
    bool isConnecting = false;
    ConnectMethod connectingMethod = ID_AUTO;
    std::string connectingPrinter;
    std::string connectingProtocol;
    std::string connectingPpdName;
    std::mutex simpleObjectMutex;
#ifdef ENTERPRISE_ENABLE
    bool isEnterprise_ = false;
#endif  // ENTERPRISE_ENABLE
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_MANAGER_H
