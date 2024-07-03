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

#ifndef SCAN_NOTIFY_PROXY_H
#define SCAN_NOTIFY_PROXY_H

#include "iscan_callback.h"
#include "iremote_proxy.h"

namespace OHOS::Scan {
class ScanCallbackProxy : public IRemoteProxy<IScanCallback> {
public:
    explicit ScanCallbackProxy(const sptr<IRemoteObject> &impl);
    ~ScanCallbackProxy() = default;

    bool OnCallback(uint32_t state, const ScanDeviceInfoTCP &info) override;
    bool OnCallback(uint32_t state, const ScanDeviceInfo &info) override;
    bool OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info) override;
    bool OnGetFrameResCallback(bool isGetSucc, int32_t sizeRead) override;
    bool OnScanInitCallback(int32_t &scanVersion) override;
    bool OnSendSearchMessage(std::string &message) override;
    bool OnGetDevicesList(std::vector<ScanDeviceInfo> &info) override;

private:
    static inline BrokerDelegator<ScanCallbackProxy> delegator_;
};
} // namespace OHOS::Scan

#endif // SCAN_NOTIFY_PROXY_H
