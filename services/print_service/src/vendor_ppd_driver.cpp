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

#include "vendor_ppd_driver.h"
#include "print_log.h"

using namespace OHOS::Print;

VendorPpdDriver::VendorPpdDriver() {}

VendorPpdDriver::~VendorPpdDriver() {}

std::string VendorPpdDriver::GetVendorName()
{
    return VENDOR_PPD_DRIVER;
}

int32_t VendorPpdDriver::OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    connectingVendorGroup = vendorName;
    connectingPrinterInfo = std::make_shared<PrinterInfo>(printerInfo);
    return 0;
}

bool VendorPpdDriver::QueryProperty(const std::string &printerId, const std::string &key, std::string &value)
{
    if (connectingPrinterInfo == nullptr) {
        PRINT_HILOGW("connectingPrinterInfo is null");
        return false;
    }
    if (connectingPrinterInfo->GetPrinterId() != printerId) {
        PRINT_HILOGW("not connecting printer");
        return false;
    }
    if (key == PRINTER_PROPERTY_KEY_CUPS_PPD_NAME) {
        auto makeAndModel = connectingPrinterInfo->GetPrinterMake();
        value = QueryPpdName(makeAndModel);
        return !value.empty();
    }
    return false;
}

std::string VendorPpdDriver::QueryPpdName(const std::string &makeAndModel)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return std::string();
    }
    std::string ppdName;
    if (!vendorManager->QueryPPDInformation(makeAndModel, ppdName)) {
        PRINT_HILOGW("QueryPPDInformation fail. printerMake = %{public}s", makeAndModel.c_str());
        return std::string();
    }
    return ppdName;
}
