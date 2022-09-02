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

#ifndef PRINT_EXTCB_PROXY_H
#define PRINT_EXTCB_PROXY_H

#include "iremote_proxy.h"
#include "print_extcb_interface.h"

namespace OHOS::Print {
class PrintExtcbProxy : public IRemoteProxy<PrintExtcbInterface> {
public:
    explicit PrintExtcbProxy(const sptr<IRemoteObject> &impl);
    ~PrintExtcbProxy() = default;
    bool OnCallback() override;
    bool OnCallback(uint32_t printerId) override;
    bool OnCallback(const PrintJob &job) override;

private:
    static inline BrokerDelegator<PrintExtcbProxy> delegator_;
};
} // namespace OHOS::Print

#endif // PRINT_EXTCB_PROXY_H