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

#ifndef PRINT_NOTIFY_PROXY_H
#define PRINT_NOTIFY_PROXY_H

#include "iremote_proxy.h"
#include "print_notify_interface.h"

namespace OHOS::Print {
class PrintNotifyProxy : public IRemoteProxy<PrintNotifyInterface> {
public:
    explicit PrintNotifyProxy(const sptr<IRemoteObject> &impl);
    ~PrintNotifyProxy() = default;
    void OnCallBack(MessageParcel &data) override;

private:
    static inline BrokerDelegator<PrintNotifyProxy> delegator_;
};
} // namespace OHOS::Print

#endif // PRINT_NOTIFY_PROXY_H