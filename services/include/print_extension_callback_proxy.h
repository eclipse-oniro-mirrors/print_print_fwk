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

#ifndef PRINT_EXTENSION_CALLBACK_PROXY_H
#define PRINT_EXTENSION_CALLBACK_PROXY_H

#include "iprint_extension_callback.h"
#include "iremote_proxy.h"

namespace OHOS::Print {
class PrintExtensionCallbackProxy : public IRemoteProxy<IPrintExtensionCallback> {
public:
    explicit PrintExtensionCallbackProxy(const sptr<IRemoteObject> &impl);
    ~PrintExtensionCallbackProxy() = default;
    bool OnCallback() override;
    bool OnCallback(const std::string &printerId) override;
    bool OnCallback(const PrintJob &job) override;
    bool OnCallback(const std::string &printerId, PrinterCapability &cap) override;

private:
    static inline BrokerDelegator<PrintExtensionCallbackProxy> delegator_;
};
} // namespace OHOS::Print

#endif // PRINT_EXTENSION_CALLBACK_PROXY_H