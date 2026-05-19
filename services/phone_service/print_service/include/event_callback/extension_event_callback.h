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

#ifndef PRINT_EXTENSION_EVENT_CALLBACK_H
#define PRINT_EXTENSION_EVENT_CALLBACK_H

#include <memory>
#include "base_event_callback.h"
#include "iprint_extension_callback.h"

namespace OHOS {
namespace Print {

class ExtensionEventCallback : public BaseEventCallback {
public:
    ExtensionEventCallback(int32_t userId, pid_t pid, CallbackEventType eventType,
        const sptr<IPrintExtensionCallback> &listener, sptr<IRemoteObject::DeathRecipient> deathRecipient)
        : BaseEventCallback(userId, pid, eventType, deathRecipient), listener_(listener)
    {}

    virtual ExecuteResult Execute(const CallbackInfo &info) override;
    virtual bool IsRemoteDied(const sptr<IRemoteObject> &listener) override;
    virtual uint32_t Clear() override;
    void SetListener(const sptr<IPrintExtensionCallback> &listener);
    void SetExtensionId(const std::string &extensionId);
    const std::string &GetExtensionId();

private:
    sptr<IPrintExtensionCallback> listener_ = nullptr;
    std::string extensionId_;
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_EXTENSION_EVENT_CALLBACK_H