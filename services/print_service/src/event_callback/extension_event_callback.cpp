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

#include "extension_event_callback.h"
#include "ipc_skeleton.h"
#include "print_log.h"
#include "print_common_death_recipient.h"

namespace OHOS {
namespace Print {

bool ExtensionEventCallback::Execute(const CallbackInfo &info)
{
    if (listener_ == nullptr) {
        return false;
    }
    if (info.extensionId != extensionId_) {
        return true;
    }
    PRINT_HILOGI("ExtensionEventCallback Execute, type=%{public}d, pid=%{public}d", info.cbEventType, GetPid());

    switch (info.cbEventType) {
        case EXTCB_START_DISCOVERY:
        case EXTCB_STOP_DISCOVERY:
        case EXTCB_DESTROY_EXTENSION: {
            return listener_->OnCallback();
        }
        case EXTCB_CONNECT_PRINTER:
        case EXTCB_DISCONNECT_PRINTER:
        case EXTCB_REQUEST_CAP: {
            return listener_->OnCallback(info.printerId);
        }
        case EXTCB_START_PRINT:
        case EXTCB_CANCEL_PRINT: {
            if (!info.printJobInfo) {
                return false;
            }
            return listener_->OnCallback(*info.printJobInfo);
        }
        case EXTCB_REQUEST_PREVIEW:
            return true;
        default:
            return false;
    }
}

bool ExtensionEventCallback::IsRemoteDied(const sptr<IRemoteObject> &listener)
{
    if (listener_ == nullptr) {
        PRINT_HILOGW("listener is null");
        return false;
    }
    auto remoteObject = listener_->AsObject();
    return remoteObject == listener;
}

uint32_t ExtensionEventCallback::Clear()
{
    if (listener_) {
        RemoveDeathRecipient(listener_->AsObject());
        listener_ = nullptr;
    }
    return 1;
}

void ExtensionEventCallback::SetListener(const sptr<IPrintExtensionCallback> &listener)
{
    Clear();
    listener_ = listener;
    if (listener_) {
        AddDeathRecipient(listener_->AsObject());
    }
}

void ExtensionEventCallback::SetExtensionId(const std::string &extensionId)
{
    extensionId_ = extensionId;
}

const std::string &ExtensionEventCallback::GetExtensionId()
{
    return extensionId_;
}

}  // namespace Print
}  // namespace OHOS