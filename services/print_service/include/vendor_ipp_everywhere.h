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

#ifndef VENDOR_IPP_EVERYWHERE_H
#define VENDOR_IPP_EVERYWHERE_H

#include "vendor_driver_base.h"
#include "operation_queue.h"

namespace OHOS {
namespace Print {
class VendorIppEveryWhere : public VendorDriverBase {
public:
    VendorIppEveryWhere();
    ~VendorIppEveryWhere();
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
    void QueryCapabilityByUri(const std::string &uri);
    void ConnectPrinterByUri(const std::string &uri);
    void ConnectPrinterByPrinterIdAndUri(const std::string &printerId, const std::string &uri);
    std::shared_ptr<PrinterInfo> QueryPrinterInfoByUri(const std::string &uri);
    std::shared_ptr<PrinterInfo> ConvertCapabilityToInfo(const PrinterCapability &printerCap,
        const std::string &printerUri);
    void QueryPrinterStatusByUri(const std::string &uri);
    bool UpdateCapability(std::shared_ptr<PrinterInfo> printerInfo);
    bool ConnectPrinter(std::shared_ptr<PrinterInfo> printerInfo);
    bool ConvertPrinterIdByUri(std::string &uri);

private:
    OperationQueue opQueue;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_IPP_EVERYWHERE_H
