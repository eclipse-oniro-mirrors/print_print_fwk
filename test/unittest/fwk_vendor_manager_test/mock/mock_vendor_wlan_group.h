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

#ifndef MOCK_VENDOR_PPD_DRIVER_H
#define MOCK_VENDOR_PPD_DRIVER_H

#include <gmock/gmock.h>
#include "vendor_ppd_driver.h"

namespace OHOS {
namespace Print {
class MockWlanGroup {
public:
    MOCK_METHOD2(OnQueryCapability, bool(const std::string &, int));
    MOCK_METHOD2(OnQueryProperties, bool(const std::string &, const std::vector<std::string> &));
    MOCK_METHOD0(GetVendorName, std::string());
    MOCK_METHOD1(OnQueryCapability, bool(const std::string &, int));
    MOCK_METHOD2(OnQueryCapabilityByIp, bool(const std::string &, const std::string &));
    MOCK_METHOD2(OnPrinterDiscovered, int32_t(const std::string &, const PrinterInfo &));
    MOCK_METHOD2(OnPrinterRemoved, int32_t(const std::string &, const std::string &));
    MOCK_METHOD1(IsGroupDriver, bool(const std::string &));
    MOCK_METHOD2(ConvertGroupDriver, bool(std::string &, std::string &));
    MOCK_METHOD1(ConvertGroupGlobalPrinterId, std::string(const std::string &));
    MOCK_METHOD2(OnUpdatePrinterToDiscovery, int32_t(const std::string &, const PrinterInfo &));
    MOCK_METHOD2(IsConnectingPrinter, bool(const std::string &, const std::string &));
    MOCK_METHOD1(GetConnectingMethod, ConnectMethod(const std::string &));
    MOCK_METHOD2(SetConnectingPrinter, void(ConnectMethod, const std::string &));
    MOCK_METHOD2(IsQueryingPrinter, bool(const std::string &, const std::string &));
    MOCK_METHOD2(SetQueryPrinter, void(ConnectMethod, const std::string &));
    MOCK_METHOD3(ConnectPrinterByIpAndPpd, bool(const std::string &, const std::string &, const std::string &));
    MOCK_METHOD4(
        OnPrinterPpdQueried, bool(const std::string &, const std::string &, const std::string &, const std::string &));
    MOCK_METHOD1(MonitorPrinterStatus, bool(const std::string &, bool));
    MOCK_METHOD3(OnPrinterStatusChanged, bool(const std::string &, const std::string &, const PrinterVendorStatus &));
    MOCK_METHOD1(IsBsunidriverSupport, bool(const PrinterInfo &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_VENDOR_PPD_DRIVER_H