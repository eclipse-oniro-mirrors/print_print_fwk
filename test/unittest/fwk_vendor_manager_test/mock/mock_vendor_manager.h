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

#ifndef MOCK_VENDOR_MANAGER_H
#define MOCK_VENDOR_MANAGER_H

#include <gmock/gmock.h>
#include "vendor_driver_base.h"

namespace OHOS {
namespace Print {
class MockVendorManager final : public IPrinterVendorManager {
public:
    MOCK_METHOD2(AddPrinterToDiscovery, int32_t (const std::string &, const PrinterInfo &));
    MOCK_METHOD2(UpdatePrinterToDiscovery, int32_t (const std::string &, const PrinterInfo &));
    MOCK_METHOD2(RemovePrinterFromDiscovery, int32_t (const std::string &, const std::string &));
    MOCK_METHOD3(AddPrinterToCupsWithPpd, int32_t (const std::string &, const std::string &, const std::string &));
    MOCK_METHOD2(RemovePrinterFromCups, int32_t (const std::string &, const std::string &));
    MOCK_METHOD3(OnPrinterStatusChanged, bool (const std::string &, const std::string &, const PrinterVendorStatus &));
    MOCK_METHOD3(OnPrinterPpdQueried, bool (const std::string &, const std::string &, const std::string &));
    MOCK_METHOD2(IsConnectingPrinter, bool (const std::string &, const std::string &));
    MOCK_METHOD2(SetConnectingPrinter, void (ConnectMethod, const std::string &));
    MOCK_METHOD0(ClearConnectingPrinter, void ());
    MOCK_METHOD2(QueryPrinterCapabilityByUri, bool (const std::string &, PrinterCapability &));
    MOCK_METHOD2(QueryPrinterStatusByUri, bool (const std::string &, PrinterStatus &));
    MOCK_METHOD2(QueryDiscoveredPrinterInfoById, std::shared_ptr<PrinterInfo> (const std::string &,
        const std::string &));
    MOCK_METHOD3(QueryPrinterInfoByPrinterId, int32_t (const std::string &, const std::string &, PrinterInfo &));
    MOCK_METHOD2(QueryPPDInformation, bool (const char *, std::vector<std::string> &));
    MOCK_METHOD1(GetConnectingMethod, ConnectMethod (const std::string &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_VENDOR_MANAGER_H
