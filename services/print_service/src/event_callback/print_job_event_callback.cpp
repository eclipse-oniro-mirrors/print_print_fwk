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

#include "print_job_event_callback.h"
#include "ipc_skeleton.h"
#include "print_log.h"
#include "print_common_death_recipient.h"

namespace OHOS {
namespace Print {

bool PrintJobEventCallback::Execute(const CallbackInfo &info)
{
    auto it = listeners_.find(info.jobId);
    if (it == listeners_.end()) {
        PRINT_HILOGW("listener not exist for jobId=%{public}s", info.jobId.c_str());
        return true;
    }
    auto listener = it->second;
    PRINT_HILOGI("PrintJobEventCallback Execute, type=%{public}d, pid=%{public}d", info.cbEventType, GetPid());

    switch (info.cbEventType) {
        case PRINT_JOB_BLOCK:
        case PRINT_JOB_SUCCESS:
        case PRINT_JOB_FAIL:
        case PRINT_JOB_CANCEL: {
            return listener->OnCallback();
        }
        case PRINT_JOB_STATE_CALLBACK: {
            if (!info.printJobInfo) {
                return false;
            }
            return listener->OnCallback(info.printJobInfo->GetJobState(), *(info.printJobInfo));
        }
        case PRINT_JOB_CALLBACK_ADAPTER: {
            if (info.fd == 0) {
                return listener->OnCallbackAdapterJobStateChanged(info.jobId, info.jobState, info.adapterState);
            } else if (info.newAttrs && info.oldAttrs) {
                return listener->OnCallbackAdapterLayout(info.jobId, *(info.oldAttrs), *(info.newAttrs), info.fd);
            }
            return false;
        }
        case PRINT_JOB_FILE_GET_ADAPTER: {
            return listener->OnCallbackAdapterGetFile(info.fileCompletedState);
        }
        default:
            return false;
    }
}

bool PrintJobEventCallback::IsRemoteDied(const sptr<IRemoteObject> &listener)
{
    for (const auto &[_, listener_] : listeners_) {
        if (!listener_) {
            continue;
        }
        if (listener_->AsObject() == listener) {
            return true;
        }
    }
    return false;
}

uint32_t PrintJobEventCallback::Clear()
{
    for (auto &[_, listener_] : listeners_) {
        if (listener_) {
            RemoveDeathRecipient(listener_->AsObject());
        }
    }
    uint32_t count = listeners_.size();
    listeners_.clear();
    return count;
}

uint32_t PrintJobEventCallback::SetListener(const sptr<IPrintCallback> &listener, const std::string &jobId)
{
    uint32_t count = 0;
    auto it = listeners_.find(jobId);
    if (it != listeners_.end() && it->second) {
        RemoveDeathRecipient(it->second->AsObject());
        count = 1;
    }
    listeners_[jobId] = listener;
    if (listener) {
        AddDeathRecipient(listener->AsObject());
    }
    return count;
}

bool PrintJobEventCallback::DeleteListener(const std::string &jobId)
{
    auto it = listeners_.find(jobId);
    if (it != listeners_.end()) {
        if (it->second) {
            RemoveDeathRecipient(it->second->AsObject());
        }
        listeners_.erase(it);
        return true;
    }
    return false;
}

bool PrintJobEventCallback::HasJobId(const std::string &jobId)
{
    return listeners_.count(jobId) != 0;
}

}  // namespace Print
}  // namespace OHOS