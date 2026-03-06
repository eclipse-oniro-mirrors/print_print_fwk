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

#include "printer_event_callback.h"
#include "ipc_skeleton.h"
#include "print_log.h"
#include "print_common_death_recipient.h"

namespace OHOS {
namespace Print {

bool PrinterEventCallback::Execute(const CallbackInfo &info)
{
    if (listener_ == nullptr) {
        PRINT_HILOGW("listener is null");
        return false;
    }
    PRINT_HILOGI("PrinterEventCallback Execute, type=%{public}d, pid=%{public}d", info.cbEventType, GetPid());

    switch (info.cbEventType) {
        case PRINTER_JOB_STATE_CHANGE: {
            auto jobInfo = info.printJobInfo;
            if (!jobInfo) {
                PRINT_HILOGE("jobInfo is nullptr");
                return false;
            }
            return listener_->OnCallback(jobInfo->GetJobState(), *jobInfo);
        }
        case PRINTER_CHANGE:
        case PRINTER_DISCOVER: {
            if (!info.printerInfo) {
                PRINT_HILOGE("printerInfo is nullptr");
                return false;
            }
            return listener_->OnCallback(info.printerEvent, *info.printerInfo);
        }
        case PRINTER_STATE_CHANGE: {
            if (!info.printerInfo) {
                PRINT_HILOGE("printerInfo is nullptr");
                return false;
            }
            return listener_->OnCallback(info.printerInfo->GetPrinterState(), *info.printerInfo);
        }
        case PRINTER_INFO_QUERY: {
            if (!info.printerInfo) {
                PRINT_HILOGE("printerInfo is nullptr");
                return false;
            }
            return listener_->OnCallback(*info.printerInfo, info.ppdInfos);
        }
        case PRINTER_EXT_INFO_CHANGE: {
            return listener_->OnCallback(info.extensionId, info.extInfo);
        }
        default:
            return false;
    }
}

bool PrinterEventCallback::IsRemoteDied(const sptr<IRemoteObject> &listener)
{
    if (listener_ == nullptr) {
        PRINT_HILOGW("listener is null");
        return false;
    }
    auto remoteObject = listener_->AsObject();
    return remoteObject == listener;
}

uint32_t PrinterEventCallback::Clear()
{
    if (listener_) {
        RemoveDeathRecipient(listener_->AsObject());
        listener_ = nullptr;
    }
    return 1;
}

void PrinterEventCallback::SetListener(const sptr<IPrintCallback> &listener)
{
    Clear();
    listener_ = listener;
    if (listener_) {
        AddDeathRecipient(listener_->AsObject());
    }
}

}  // namespace Print
}  // namespace OHOS