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
#include "vendor_driver_base.h"

namespace OHOS {
namespace Print {

class VendorPpdDriver : public VendorDriverBase {
public:
    VendorPpdDriver();
    ~VendorPpdDriver();
    bool OnQueryCapability(const std::string &printerId, int timeout) override;
    bool OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys) override;
    std::string GetVendorName() override;

private:
    bool QueryPpdByPrinterId(const std::string &printerId, std::vector<std::string> &ppds);
    bool AddPrinterToCups(const std::string &printerId, const std::string &ppdData);
    std::shared_ptr<PrinterInfo> QueryPrinterCapabilityFromPpd(const std::string &printerId,
        const std::string &ppdData);
    bool UpdateCapability(std::shared_ptr<PrinterInfo> printerInfo);

private:
    std::map<std::string, std::vector<std::string>> privatePrinterPpdMap;
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_PPD_DRIVER_H