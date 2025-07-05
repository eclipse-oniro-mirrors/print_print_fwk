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

#ifndef VENDOR_PPD_DRIVER_H
#define VENDOR_PPD_DRIVER_H

#include <vector>
#include <mutex>
#include "vendor_driver_base.h"
#include "vendor_manager.h"

namespace OHOS {
namespace Print {

class VendorPpdDriver : public VendorDriverBase {
public:
    VendorPpdDriver();
    ~VendorPpdDriver();
    std::string GetVendorName() override;
    int32_t OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo) override;
    bool QueryProperty(const std::string &printerId, const std::string &key, std::string &value) override;
    void OnStartDiscovery() override;
    void OnStopDiscovery() override;
    bool OnQueryCapability(const std::string &printerId, int timeout) override;
    void UpdateAllPrinterStatus() override;

private:
    std::string QueryPpdName(const std::string &makeAndModel);
    void DiscoverBackendPrinters();
    void DiscoveryProcess();
    bool WaitNext();
    bool TryConnectByPpdDriver(const PrinterInfo &printerInfo);

private:
    std::string connectingVendorGroup;
    std::shared_ptr<PrinterInfo> connectingPrinterInfo;
    std::map<std::string, std::vector<std::string>> privatePrinterPpdMap;
    std::mutex updateDiscoveryMutex_;
    std::map<std::string, bool> discoveredPrinters_;
    bool startDiscovery_ = false;
    std::thread discoveryThread_;
    std::mutex startDiscoveryMutex_;
    std::condition_variable startDiscoveryCondition_;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_PPD_DRIVER_H