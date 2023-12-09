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

#ifndef PRINT_CALLBACK_PROXY_H
#define PRINT_CALLBACK_PROXY_H

#include "iprint_callback.h"
#include "iremote_proxy.h"

namespace OHOS::Print {
class PrintCallbackProxy : public IRemoteProxy<IPrintCallback> {
public:
    explicit PrintCallbackProxy(const sptr<IRemoteObject> &impl);
    ~PrintCallbackProxy() = default;
    bool OnCallback() override;
    bool OnCallback(uint32_t state, const PrinterInfo &info) override;
    bool OnCallback(uint32_t state, const PrintJob &info) override;
    bool OnCallback(const std::string &extensionId, const std::string &info) override;
    bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) override;
    bool onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) override;
    bool OnCallbackAdapterGetFile(uint32_t state) override;

private:
    static inline BrokerDelegator<PrintCallbackProxy> delegator_;
};
}  // namespace OHOS::Print
#endif  // PRINT_CALLBACK_PROXY_H
