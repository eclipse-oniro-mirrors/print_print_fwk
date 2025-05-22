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

#ifndef VENDOR_DRIVER_GROUP_H
#define VENDOR_DRIVER_GROUP_H

#include "vendor_driver_base.h"

namespace OHOS {
namespace Print {

class VendorDriverGroup : public VendorDriverBase {
public:
    virtual int32_t OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo);
    virtual int32_t OnPrinterRemoved(const std::string &vendorName, const std::string &printerId);
    virtual bool IsGroupDriver(const std::string &bothPrinterId);
    virtual std::string ConvertGroupGlobalPrinterId(const std::string &bothPrinterId);
    virtual bool ConvertGroupDriver(std::string &printerId, std::string &vendorName) = 0;
    virtual int32_t OnUpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo) = 0;
    virtual bool IsConnectingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri) = 0;
    virtual ConnectMethod GetConnectingMethod(const std::string &globalPrinterIdOrIp) = 0;
    virtual void SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp) = 0;
    virtual bool OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                                     const std::string &ppdName, const std::string &ppdData) = 0;
    virtual bool MonitorPrinterStatus(const std::string &printerId, bool on) = 0;
    virtual bool OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                        const PrinterVendorStatus &status) = 0;
private:
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_DRIVER_GROUP_H
