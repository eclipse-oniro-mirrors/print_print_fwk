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

#ifndef WATERMARK_MANAGER_H
#define WATERMARK_MANAGER_H

#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "iwatermark_callback.h"
#include "noncopyable.h"

namespace OHOS::Print {

/**
 * @brief Structure to store callback information with PID
 */
struct WatermarkCallbackInfo {
    int32_t pid;                                        // Process ID of the registrant
    sptr<IWatermarkCallback> callback;                  // The callback interface
    sptr<IRemoteObject::DeathRecipient> deathRecipient; // Death recipient for cleanup
};

class WatermarkManager : public NoCopyable {
public:
    static WatermarkManager& GetInstance();

    /**
     * @brief Register watermark callback from MDM
     * @param callback The watermark callback interface
     * @return E_PRINT_NONE if success, error code otherwise
     * @note Callbacks are stored in registration order and processed sequentially
     */
    int32_t RegisterCallback(const sptr<IWatermarkCallback> &callback);

    /**
     * @brief Unregister watermark callback for current caller
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t UnregisterCallback();

    /**
     * @brief Process watermark for a single file descriptor (synchronous blocking)
     * @param jobId The print job ID
     * @param fd The file descriptor to process
     * @return E_PRINT_NONE if success, error code otherwise
     * @note All registered callbacks are called in registration order
     */
    int32_t ProcessWatermark(const std::string &jobId, uint32_t fd);

    /**
     * @brief Process watermark for multiple file descriptors
     * @param jobId The print job ID
     * @param fdList The list of file descriptors to process
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t ProcessWatermarkForFiles(const std::string &jobId, const std::vector<uint32_t> &fdList);

    /**
     * @brief Notify watermark processing complete (called by MDM)
     * @param jobId The print job ID
     * @param result The processing result code
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t NotifyComplete(const std::string &jobId, int32_t result);

    /**
     * @brief Check if any watermark callback is registered
     * @return true if at least one callback is registered, false otherwise
     */
    bool IsCallbackRegistered();

    /**
     * @brief Check if watermark is enabled via system parameter
     * @return true if watermark is enabled, false otherwise
     * @note Checks system parameter: persist.pc_service_file_guard_watermarkprint
     */
    bool IsWatermarkEnabled();

    /**
     * @brief Handle callback death notification (called by WatermarkDeathRecipient)
     * @param pid The PID of the dead process
     */
    void OnCallbackDied(int32_t pid);

private:
    WatermarkManager() = default;
    ~WatermarkManager() override = default;

    /**
     * @brief Trigger watermark processing by calling a single MDM callback
     * @param jobId The print job ID
     * @param fd The file descriptor
     * @param callback The callback to invoke
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t TriggerWatermarkProcess(const std::string &jobId, int32_t fd,
                                     const sptr<IWatermarkCallback> &callback);

    /**
     * @brief Wait for watermark processing to complete
     * @param jobId The print job ID
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t WaitWatermarkComplete(const std::string &jobId);

    /**
     * @brief Find callback index by PID
     * @param pid The process ID to find
     * @return Index of the callback, or -1 if not found
     */
    int32_t FindCallbackIndexByPid(int32_t pid) const;

    /**
     * @brief Update existing callback for a PID
     * @param index The index of existing callback in callbacks_ vector
     * @param callback The new callback interface
     * @param remoteObject The remote object of the new callback
     * @param callerPid The caller process ID
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t UpdateExistingCallback(int32_t index, const sptr<IWatermarkCallback> &callback,
                                   const sptr<IRemoteObject> &remoteObject, int32_t callerPid);

    /**
     * @brief Add new callback for a PID
     * @param callback The callback interface to add
     * @param remoteObject The remote object of the callback
     * @param callerPid The caller process ID
     * @return E_PRINT_NONE if success, error code otherwise
     */
    int32_t AddNewCallback(const sptr<IWatermarkCallback> &callback,
                          const sptr<IRemoteObject> &remoteObject, int32_t callerPid);

    // Watermark processing timeout: 30 seconds
    static constexpr uint32_t WATERMARK_TIMEOUT_MS = 30000;

    // MDM watermark callbacks list (ordered by registration time)
    std::vector<WatermarkCallbackInfo> callbacks_;

    // Watermark status map: jobId -> (completed, result)
    std::map<std::string, std::pair<bool, int32_t>> statusMap_;

    // Condition variable for synchronous waiting
    std::condition_variable cv_;

    // Mutex for thread safety
    std::mutex mutex_;
};

} // namespace OHOS::Print

#endif // WATERMARK_MANAGER_H
