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

#ifndef VENDOR_BSUNI_DRIVER_H
#define VENDOR_BSUNI_DRIVER_H

#include "vendor_driver_base.h"
#include "operation_queue.h"

namespace OHOS {
namespace Print {
class VendorBsuniDriver : public VendorDriverBase {
public:
    static void SetDriverWrapper(VendorBsuniDriver *driver);
    static bool CheckVendorExtension(Print_VendorExtension *extension);
    static int32_t AddPrinterToDiscovery(const Print_DiscoveryItem *discoveryItem);
    static int32_t RemovePrinterFromDiscovery(const char *printerId);
    static int32_t AddPrinterToCups(const Print_DiscoveryItem *printer, const Print_PrinterCapability *capability,
                                    const Print_DefaultValue *defaultValue, const char *ppdData);
    static int32_t RemovePrinterFromCups(const char *printerId);
    static int32_t OnCapabilityQueried(const Print_DiscoveryItem *printer, const Print_PrinterCapability *capability,
                                       const Print_DefaultValue *defaultValue);
    static int32_t OnPropertiesQueried(const char *printerId, const Print_PropertyList *propertyList);
    VendorBsuniDriver();
    ~VendorBsuniDriver();
    bool Init(IPrinterVendorManager *manager) override;
    void UnInit() override;
    void OnCreate() override;
    void OnDestroy() override;
    void OnStartDiscovery() override;
    void OnStopDiscovery() override;
    std::string GetVendorName() override;
    bool OnQueryCapability(const std::string &printerId, int timeout) override;
    bool OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol) override;
    bool OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys) override;

private:
    bool LoadDriverExtension();
    void OnDiscoveredPrinterAdd(std::shared_ptr<PrinterInfo> printerInfo);
    void OnDiscoveredPrinterRemove(std::shared_ptr<std::string> printerId);
    void OnCupsPrinterAdd(std::shared_ptr<PrinterInfo> printerInfo, std::shared_ptr<std::string> ppdData);
    void OnCupsPrinterRemove(std::shared_ptr<std::string> printerId);
    void OnPpdQueried(std::shared_ptr<std::string> printerId, std::shared_ptr<std::string> ppdData);
    void OnStateQueried(std::shared_ptr<std::string> printerId, std::shared_ptr<std::string> stateData);
    void OnPrinterCapabilityQueried(std::shared_ptr<PrinterInfo> printerInfo);
private:
    void *bsUniDriverHandler = nullptr;
    Print_VendorExtension *vendorExtension = nullptr;
    Print_ServiceAbility printServiceAbility = { 0 };
    OperationQueue opQueue;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_BSUNI_DRIVER_H
