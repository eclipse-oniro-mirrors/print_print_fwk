/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SCAN_SERVICE_PROXY_H
#define SCAN_SERVICE_PROXY_H

#include "iscan_service.h"
#include "iremote_proxy.h"
#include "scanner_info.h"
#define TDD_ENABLE 1

namespace OHOS::Scan {
class ScanServiceProxy : public IRemoteProxy<IScanService> {
public:
    explicit ScanServiceProxy(const sptr<IRemoteObject> &object);
    ~ScanServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(ScanServiceProxy);

    int32_t InitScan() override;
    int32_t ExitScan() override;
    int32_t GetScannerList() override;
    int32_t OpenScanner(const std::string scannerId) override;
    int32_t CloseScanner(const std::string scannerId) override;
    int32_t GetScanOptionDesc(const std::string scannerId,
        const int32_t optionIndex, ScanOptionDescriptor &desc) override;
    int32_t OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value) override;
    int32_t GetScanParameters(const std::string scannerId, ScanParameters &para) override;
    int32_t StartScan(const std::string scannerId, const bool &batchMode) override;
    int32_t CancelScan(const std::string scannerId) override;
    int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog) override;
    int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner) override;
    int32_t On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener) override;
    int32_t Off(const std::string taskId, const std::string &type) override;

#ifndef TDD_ENABLE
private:
#endif
    int32_t GetResult(int32_t retCode, MessageParcel &reply);
    static inline BrokerDelegator<ScanServiceProxy> delegator_;
};
} // namespace OHOS::Scan
#endif // SCAN_SERVICE_PROXY_H
