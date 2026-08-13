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

#ifndef PRINT_PRINTER_EVENT_CALLBACK_H
#define PRINT_PRINTER_EVENT_CALLBACK_H

#include <memory>
#include "base_event_callback.h"
#include "iprint_callback.h"

namespace OHOS {
namespace Print {

class PrinterEventCallback : public BaseEventCallback {
public:
    PrinterEventCallback(int32_t userId, pid_t pid, CallbackEventType eventType, const sptr<IPrintCallback> &listener,
        sptr<IRemoteObject::DeathRecipient> deathRecipient)
        : BaseEventCallback(userId, pid, eventType, deathRecipient), listener_(listener)
    {}

    virtual ExecuteResult Execute(const CallbackInfo &info) override;
    virtual bool IsRemoteDied(const sptr<IRemoteObject> &listener) override;
    virtual uint32_t Clear() override;
    void SetListener(const sptr<IPrintCallback> &listener);

private:
    bool HandleJobStateChange(const CallbackInfo &info);
    bool HandlePrinterChange(const CallbackInfo &info);
    bool HandlePrinterStateChange(const CallbackInfo &info);
    bool HandlePrinterInfoQuery(const CallbackInfo &info);
    bool HandleExtInfoChange(const CallbackInfo &info);
    bool HandleSharedHostDiscover(const CallbackInfo &info);
    
    sptr<IPrintCallback> listener_ = nullptr;
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_PRINTER_EVENT_CALLBACK_H