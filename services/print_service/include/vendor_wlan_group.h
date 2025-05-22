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

#ifndef VENDOR_WLAN_GROUP_H
#define VENDOR_WLAN_GROUP_H

#include "vendor_manager.h"
#include "vendor_driver_group.h"

namespace OHOS {
namespace Print {

class VendorWlanGroup : public VendorDriverGroup {
public:
    explicit VendorWlanGroup(VendorManager *vendorManager);
    std::string GetVendorName() override;
    bool OnQueryCapability(const std::string &printerId, int timeout) override;
    bool OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol) override;
    int32_t OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    int32_t OnPrinterRemoved(const std::string &vendorName, const std::string &printerId) override;
    bool IsGroupDriver(const std::string &bothPrinterId) override;
    bool ConvertGroupDriver(std::string &printerId, std::string &vendorName) override;
    std::string ConvertGroupGlobalPrinterId(const std::string &bothPrinterId) override;
    int32_t OnUpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    bool IsConnectingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri) override;
    ConnectMethod GetConnectingMethod(const std::string &globalPrinterIdOrIp) override;
    void SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp) override;
    bool OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                             const std::string &ppdName, const std::string &ppdData) override;
    bool MonitorPrinterStatus(const std::string &groupPrinterId, bool on) override;
    bool OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                const PrinterVendorStatus &status) override;

private:
    bool IsBsunidriverSupport(const std::string &groupPrinterId);
    void RemoveGroupPrinterFromVendorGroupList(const std::string &groupPrinterId);
    std::string ExtractPrinterIdByPrinterInfo(const PrinterInfo &printerInfo);
    std::string GetGroupPrinterId(const std::string &printerId);
    void UpdateGroupPrinter(const std::string &printerId, const std::string &groupPrinterId);
    bool HasGroupPrinter(const std::string &printerId);
    void RemovedGroupPrinter(const std::string &printerId);
    PrinterInfo ConvertPrinterInfoId(const PrinterInfo &priterInfo);
    bool CheckPrinterAddedByIp(const std::string &printerId);
    PrinterInfo ConvertIpPrinterName(const PrinterInfo &printerInfo);
    std::string QueryVendorDriverByGroupPrinterId(const std::string &groupPrinterId);

private:
    VendorManager* parentVendorManager = nullptr;
    std::map<std::string, std::string> printerVendorGroupList_;
    std::map<std::string, std::string> groupPrinterIdMap_;
    std::mutex groupPrinterIdMapMutex;
    bool hasGs = false;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_WLAN_GROUP_H