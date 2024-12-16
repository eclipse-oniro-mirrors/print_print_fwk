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
private:
};
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_DRIVER_GROUP_H