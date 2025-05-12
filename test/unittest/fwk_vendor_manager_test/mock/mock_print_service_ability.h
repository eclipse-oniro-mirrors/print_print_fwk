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

#ifndef MOCK_PRINT_SERVICE_ABILITY_H
#define MOCK_PRINT_SERVICE_ABILITY_H

#include <gmock/gmock.h>
#include "print_service_ability.h"

namespace OHOS {
namespace Print {
class MockPrintServiceAbility final : public PrintServiceAbility {
public:
    MOCK_METHOD2(AddVendorPrinterToDiscovery, bool (const std::string &, const PrinterInfo &));
    MOCK_METHOD2(UpdateVendorPrinterToDiscovery, bool (const std::string &, const PrinterInfo &));
    MOCK_METHOD2(RemoveVendorPrinterFromDiscovery, bool (const std::string &, const std::string &));
    MOCK_METHOD3(AddVendorPrinterToCupsWithPpd, bool (const std::string &, const std::string &, const std::string &));
    MOCK_METHOD3(AddVendorPrinterToCupsWithSpecificPpd, bool (const std::string &, const std::string &,
        const std::string &));
    MOCK_METHOD2(RemoveVendorPrinterFromCups, bool (const std::string &, const std::string &));
    MOCK_METHOD3(OnVendorStatusUpdate, bool (const std::string &, const std::string &, const PrinterVendorStatus &));
    MOCK_METHOD2(QueryPrinterCapabilityByUri, bool (const std::string &, PrinterCapability &));
    MOCK_METHOD2(QueryPrinterStatusByUri, bool (const std::string &, PrinterStatus &));
    MOCK_METHOD1(QueryDiscoveredPrinterInfoById, std::shared_ptr<PrinterInfo> (const std::string &));
    MOCK_METHOD2(QueryPrinterInfoByPrinterId, int32_t (const std::string &, PrinterInfo &));
    MOCK_METHOD2(QueryPPDInformation, bool (const char *, std::vector<std::string> &));
    MOCK_METHOD2(AddIpPrinterToSystemData, bool (const std::string &, const PrinterInfo &));
    MOCK_METHOD3(AddIpPrinterToCupsWithPpd, bool (const std::string &, const std::string &, const std::string &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_SERVICE_ABILITY_H
