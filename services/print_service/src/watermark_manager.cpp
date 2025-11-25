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

#include "watermark_manager.h"
#include "watermark_death_recipient.h"
#include "print_log.h"
#include "print_constant.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include <unistd.h>

namespace OHOS::Print {

// System parameter key for watermark enable
static const std::string WATERMARK_PARAM_KEY = "persist.pc_service_file_guard_waterprint";

WatermarkManager& WatermarkManager::GetInstance()
{
    static WatermarkManager instance;
    return instance;
}

int32_t WatermarkManager::FindCallbackIndexByPid(int32_t pid) const
{
    for (size_t i = 0; i < callbacks_.size(); ++i) {
        if (callbacks_[i].pid == pid) {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

int32_t WatermarkManager::UpdateExistingCallback(int32_t index, const sptr<IWatermarkCallback> &callback,
    const sptr<IRemoteObject> &remoteObject, int32_t callerPid)
{
    auto& info = callbacks_[index];
    sptr<WatermarkDeathRecipient> newDeathRecipient = new (std::nothrow) WatermarkDeathRecipient(callerPid);
    if (newDeathRecipient == nullptr) {
        PRINT_HILOGE("Failed to create death recipient for PID: %{public}d", callerPid);
        return E_PRINT_SERVER_FAILURE;
    }
    if (!remoteObject->AddDeathRecipient(newDeathRecipient)) {
        PRINT_HILOGE("Failed to add death recipient for PID: %{public}d", callerPid);
        return E_PRINT_SERVER_FAILURE;
    }

    // Remove old, update new
    if (info.callback != nullptr && info.deathRecipient != nullptr) {
        info.callback->AsObject()->RemoveDeathRecipient(info.deathRecipient);
    }
    info.callback = callback;
    info.deathRecipient = newDeathRecipient;

    PRINT_HILOGI("Update existing callback for PID: %{public}d", callerPid);
    return E_PRINT_NONE;
}

int32_t WatermarkManager::AddNewCallback(const sptr<IWatermarkCallback> &callback,
    const sptr<IRemoteObject> &remoteObject, int32_t callerPid)
{
    WatermarkCallbackInfo info;
    info.pid = callerPid;
    info.callback = callback;
    info.deathRecipient = new (std::nothrow) WatermarkDeathRecipient(callerPid);

    if (info.deathRecipient != nullptr) {
        if (!remoteObject->AddDeathRecipient(info.deathRecipient)) {
            PRINT_HILOGE("Failed to add death recipient for PID: %{public}d", callerPid);
            info.deathRecipient = nullptr;
        }
    }

    callbacks_.push_back(info);
    PRINT_HILOGI("Added new callback for PID: %{public}d, total callbacks: %{public}zu",
                 callerPid, callbacks_.size());
    return E_PRINT_NONE;
}

int32_t WatermarkManager::RegisterCallback(const sptr<IWatermarkCallback> &callback)
{
    PRINT_HILOGD("WatermarkManager::RegisterCallback start");
    if (callback == nullptr) {
        PRINT_HILOGE("callback is null");
        return E_PRINT_INVALID_PARAMETER;
    }

    auto remoteObject = callback->AsObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGE("callback AsObject is null");
        return E_PRINT_INVALID_PARAMETER;
    }

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    PRINT_HILOGI("RegisterCallback from PID: %{public}d", callerPid);

    std::lock_guard<std::mutex> lock(mutex_);

    int32_t index = FindCallbackIndexByPid(callerPid);
    int32_t result = (index >= 0) ?
        UpdateExistingCallback(index, callback, remoteObject, callerPid) :
        AddNewCallback(callback, remoteObject, callerPid);
    if (result == E_PRINT_NONE) {
        PRINT_HILOGD("RegisterCallback success");
    }
    return result;
}

int32_t WatermarkManager::UnregisterCallback()
{
    PRINT_HILOGD("WatermarkManager::UnregisterCallback start");

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    PRINT_HILOGI("UnregisterCallback from PID: %{public}d", callerPid);

    std::lock_guard<std::mutex> lock(mutex_);

    int32_t index = FindCallbackIndexByPid(callerPid);
    if (index < 0) {
        PRINT_HILOGW("No callback found for PID: %{public}d", callerPid);
        return E_PRINT_INVALID_PARAMETER;
    }

    // Remove death recipient before erasing callback
    auto remoteObject = callbacks_[index].callback->AsObject();
    if (remoteObject != nullptr && callbacks_[index].deathRecipient != nullptr) {
        remoteObject->RemoveDeathRecipient(callbacks_[index].deathRecipient);
    }

    // Remove callback at index
    callbacks_.erase(callbacks_.begin() + index);
    PRINT_HILOGI("Removed callback for PID: %{public}d, remaining callbacks: %{public}zu",
                 callerPid, callbacks_.size());

    // Clear status map if no callbacks left
    if (callbacks_.empty()) {
        statusMap_.clear();
    }

    PRINT_HILOGD("UnregisterCallback success");
    return E_PRINT_NONE;
}

bool WatermarkManager::IsCallbackRegistered()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return !callbacks_.empty();
}

int32_t WatermarkManager::ProcessWatermark(const std::string &jobId, uint32_t fd)
{
    PRINT_HILOGD("WatermarkManager::ProcessWatermark jobId=%{public}s, fd=%{public}u",
                 jobId.c_str(), fd);

    std::unique_lock<std::mutex> lock(mutex_);

    if (callbacks_.empty()) {
        PRINT_HILOGD("No watermark callback registered, skip watermark");
        return E_PRINT_NONE;
    }

    // Copy callbacks to avoid iterator invalidation during unlock
    std::vector<WatermarkCallbackInfo> callbacksCopy = callbacks_;
    lock.unlock();

    // Process watermark with each callback in registration order
    for (size_t i = 0; i < callbacksCopy.size(); ++i) {
        const auto& callbackInfo = callbacksCopy[i];
        PRINT_HILOGI("Processing watermark with callback %{public}zu (PID: %{public}d)",
                     i, callbackInfo.pid);

        int32_t ret = TriggerWatermarkProcess(jobId, fd, callbackInfo.callback);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("TriggerWatermarkProcess failed for callback %{public}zu, ret=%{public}d",
                         i, ret);
            return ret;
        }
        
        ret = WaitWatermarkComplete(jobId);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("WaitWatermarkComplete failed for callback %{public}zu, ret=%{public}d",
                         i, ret);
            return ret;
        }

        PRINT_HILOGI("Watermark callback %{public}zu (PID: %{public}d) completed successfully",
                     i, callbackInfo.pid);
    }

    return E_PRINT_NONE;
}

int32_t WatermarkManager::ProcessWatermarkForFiles(const std::string &jobId,
    const std::vector<uint32_t> &fdList)
{
    PRINT_HILOGD("WatermarkManager::ProcessWatermarkForFiles jobId=%{public}s, files=%{public}zu",
                 jobId.c_str(), fdList.size());

    if (!IsWatermarkEnabled()) {
        PRINT_HILOGD("Watermark is disabled by system parameter, skip watermark");
        return E_PRINT_NONE;
    }

    // When watermark is enabled but no callback registered, fail the job for security
    if (!IsCallbackRegistered()) {
        PRINT_HILOGE("Security policy violation: watermark is enabled but no callback registered, "
                     "jobId=%{public}s", jobId.c_str());
        return E_PRINT_SERVER_FAILURE;
    }

    if (fdList.empty()) {
        PRINT_HILOGW("fdList is empty");
        return E_PRINT_NONE;
    }

    for (uint32_t fd : fdList) {
        // Duplicate file descriptor to avoid consumption
        int32_t dupFd = dup(fd);
        if (dupFd < 0) {
            PRINT_HILOGE("dup fd failed");
            return E_PRINT_SERVER_FAILURE;
        }

        // Process watermark for this file
        int32_t ret = ProcessWatermark(jobId, static_cast<uint32_t>(dupFd));
        close(dupFd);

        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("ProcessWatermark failed, ret=%{public}d", ret);
            return ret;
        }
    }

    PRINT_HILOGI("All files watermark added successfully");
    return E_PRINT_NONE;
}

int32_t WatermarkManager::NotifyComplete(const std::string &jobId, int32_t result)
{
    PRINT_HILOGD("WatermarkManager::NotifyComplete jobId=%{public}s, result=%{public}d",
                 jobId.c_str(), result);

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statusMap_.find(jobId);
    if (it == statusMap_.end()) {
        PRINT_HILOGE("jobId not found in statusMap");
        return E_PRINT_INVALID_PARAMETER;
    }

    // Update status
    it->second.first = true;    // completed
    it->second.second = result; // result code

    // Notify waiting thread
    cv_.notify_all();

    PRINT_HILOGD("NotifyComplete success");
    return E_PRINT_NONE;
}

int32_t WatermarkManager::TriggerWatermarkProcess(const std::string &jobId, int32_t fd,
    const sptr<IWatermarkCallback> &callback)
{
    PRINT_HILOGD("TriggerWatermarkProcess jobId=%{public}s, fd=%{public}d", jobId.c_str(), fd);

    if (callback == nullptr) {
        PRINT_HILOGE("callback is null");
        return E_PRINT_INVALID_PARAMETER;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Initialize watermark status
        statusMap_[jobId] = {false, E_PRINT_NONE};
    }

    // Call MDM callback (outside lock to avoid blocking)
    // Callback is async, result will be notified via NotifyComplete
    callback->OnCallback(jobId, static_cast<uint32_t>(fd));

    return E_PRINT_NONE;
}

int32_t WatermarkManager::WaitWatermarkComplete(const std::string &jobId)
{
    PRINT_HILOGD("WaitWatermarkComplete jobId=%{public}s", jobId.c_str());

    std::unique_lock<std::mutex> lock(mutex_);

    int32_t completionResult = E_PRINT_NONE;
    const bool success = cv_.wait_for(lock, std::chrono::milliseconds(WATERMARK_TIMEOUT_MS),
        [this, &jobId, &completionResult]() {
            auto it = statusMap_.find(jobId);
            if (it != statusMap_.end() && it->second.first) {
                completionResult = it->second.second;
                return true;
            }
            return false;
        });

    statusMap_.erase(jobId);

    if (!success) {
        PRINT_HILOGE("Security policy violation: watermark processing timeout, jobId=%{public}s",
                     jobId.c_str());
        return E_PRINT_SERVER_FAILURE;
    }

    if (completionResult != E_PRINT_NONE) {
        PRINT_HILOGE("Security policy violation: watermark processing failed, "
                     "jobId=%{public}s, result=%{public}d", jobId.c_str(), completionResult);
        return E_PRINT_SERVER_FAILURE;
    }

    PRINT_HILOGD("Watermark process success");
    return E_PRINT_NONE;
}

bool WatermarkManager::IsWatermarkEnabled()
{
    std::string paramValue = OHOS::system::GetParameter(WATERMARK_PARAM_KEY, "false");
    bool enabled = (paramValue == "true" || paramValue == "1");
    PRINT_HILOGD("IsWatermarkEnabled: param=%{public}s, enabled=%{public}d",
                 paramValue.c_str(), enabled);
    return enabled;
}

void WatermarkManager::OnCallbackDied(int32_t pid)
{
    PRINT_HILOGI("WatermarkManager::OnCallbackDied pid=%{public}d", pid);

    std::lock_guard<std::mutex> lock(mutex_);

    int32_t index = FindCallbackIndexByPid(pid);
    if (index < 0) {
        PRINT_HILOGW("No callback found for dead PID: %{public}d", pid);
        return;
    }

    // Remove callback at index (death recipient already triggered, no need to remove it)
    callbacks_.erase(callbacks_.begin() + index);
    PRINT_HILOGI("Removed dead callback for PID: %{public}d, remaining callbacks: %{public}zu",
                 pid, callbacks_.size());

    // Clear status map if no callbacks left
    if (callbacks_.empty()) {
        statusMap_.clear();
    }
}

} // namespace OHOS::Print