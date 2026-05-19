/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOCK_KIA_INTERCEPTOR_CALLBACK_H
#define MOCK_KIA_INTERCEPTOR_CALLBACK_H

#include <gmock/gmock.h>
#include "ikia_interceptor_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Print {

class MockKiaInterceptorCallback : public IRemoteStub<IKiaInterceptorCallback> {
public:
    MockKiaInterceptorCallback() = default;
    virtual ~MockKiaInterceptorCallback() = default;

    MOCK_METHOD2(OnCheckPrintJobNeedReject, bool(const int32_t &pid, const std::string &callerAppId));

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data,
                            MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return this;
    }

    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient) override
    {
        deathRecipient_ = recipient;
        return true;
    }

    bool RemoveDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient) override
    {
        if (deathRecipient_ == recipient) {
            deathRecipient_ = nullptr;
        }
        return true;
    }

private:
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};

}  // namespace Print
}  // namespace OHOS

#endif  // MOCK_KIA_INTERCEPTOR_CALLBACK_H
