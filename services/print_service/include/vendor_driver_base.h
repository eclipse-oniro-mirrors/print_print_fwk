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

#ifndef VENDOR_DRIVER_BASE_H
#define VENDOR_DRIVER_BASE_H

#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include "vendor_extension.h"
#include "printer_info.h"
#include "print_constant.h"
#include "thread_sync_wait.h"

namespace OHOS {
namespace Print {

static inline uint64_t GetNowTime();

struct PrinterVendorStatus {
    Print_PrinterState state;
    uint64_t lastUpdateTime;
    uint64_t lastCheckTime;
    PrinterVendorStatus() : state(PRINTER_UNAVAILABLE), lastUpdateTime(GetNowTime()), lastCheckTime(0) {}
};

static inline uint64_t GetNowTime()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

enum ConnectMethod { ID_AUTO = 0, IP_AUTO };
enum ConnectState { STATE_NONE = 0, STATE_CONNECTING, STATE_QUERYING };

class IPrinterVendorManager {
public:
    virtual int32_t AddPrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) = 0;
    virtual int32_t UpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) = 0;
    virtual int32_t RemovePrinterFromDiscovery(const std::string &vendorName, const std::string &printerId) = 0;
    virtual int32_t AddPrinterToCupsWithPpd(const std::string &vendorName, const std::string &printerId,
                                            const std::string &ppdName, const std::string &ppdData) = 0;
    virtual int32_t RemovePrinterFromCups(const std::string &vendorName, const std::string &printerId) = 0;
    virtual bool OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                        const PrinterVendorStatus &status) = 0;
    virtual bool OnPrinterCapabilityQueried(const std::string &vendorName, const PrinterInfo &printerInfo) = 0;
    virtual bool OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                                     const std::string &ppdName, const std::string &ppdData) = 0;
    virtual bool IsConnectingPrinter(const std::string &id, const std::string &uri) = 0;
    virtual void SetConnectingPrinter(ConnectMethod method, const std::string &printer) = 0;
    virtual void ClearConnectingPrinter() = 0;
    virtual bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) = 0;
    virtual std::string GetConnectingPpdName() = 0;
    virtual std::string GetConnectingProtocol() = 0;
    virtual void ClearConnectingPpdName() = 0;
    virtual void ClearConnectingProtocol() = 0;
    virtual bool IsQueryingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri) = 0;
    virtual bool SetQueryingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp) = 0;
    virtual bool OnQueryCallBackEvent(const PrinterInfo &info) = 0;
    virtual bool ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
        const std::string &ppdName) = 0;
    virtual bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) = 0;
    virtual std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &vendorName,
        const std::string &printerId) = 0;
    virtual int32_t QueryPrinterInfoByPrinterId(const std::string &vendorName, const std::string &printerId,
        PrinterInfo &info) = 0;
    virtual std::vector<std::string> QueryAddedPrintersByIp(const std::string &printerIp) = 0;
    virtual bool QueryPPDInformation(const std::string &makeModel, std::string &ppdName) = 0;
    virtual ConnectMethod GetConnectingMethod(const std::string &id) = 0;
    virtual int32_t DiscoverBackendPrinters(const std::string &vendorName, std::vector<PrinterInfo> &printers) = 0;
    virtual void AddPrintEvent(const std::string &vendorName, const std::string &printerId,
        const std::string &eventType, int32_t eventCode) = 0;
    virtual bool IsBsunidriverSupport(const PrinterInfo &printerInfo) = 0;
};

class VendorDriverBase {
public:
    VendorDriverBase();
    virtual ~VendorDriverBase();
    virtual bool Init(IPrinterVendorManager *manager);
    virtual void UnInit();
    virtual void OnCreate();
    virtual void OnDestroy();
    virtual void OnStartDiscovery();
    virtual void OnStopDiscovery();
    virtual bool OnQueryCapability(const std::string &printerId, int timeout);
    virtual bool OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol);
    virtual bool OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys);
    virtual std::string GetVendorName() = 0;
    virtual int32_t OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo);
    virtual bool MonitorPrinterStatus(const std::string &printerId, bool on);
    virtual bool IsStatusMonitoring(const std::string &printerId);
    virtual bool QueryProperty(const std::string &printerId, const std::string &key, std::string &value);
    virtual void UpdateAllPrinterStatus();
    
    std::shared_ptr<PrinterVendorStatus> GetMonitorVendorStatus(const std::string &printerId);
    std::string GetGlobalVendorName();
    std::string GetGlobalPrinterId(const std::string &printerId);
    void OnPrinterStateQueried(const std::string &printerId, Print_PrinterState state);

protected:
    IPrinterVendorManager *vendorManager = nullptr;
    std::mutex statusMapMutex;
    std::map<std::string, std::shared_ptr<PrinterVendorStatus>> vendorStatusMap;
    ThreadSyncWait syncWait;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_DRIVER_BASE_H
