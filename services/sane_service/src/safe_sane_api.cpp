/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <chrono>
#include <thread>
#include "safe_sane_api.h"
#include "sane/sane.h"
#include "sane/saneopts.h"
#include "scan_log.h"

namespace OHOS {
namespace Scan {

namespace {
// Timeout for waiting cancel to take effect before closing handles.
// Some backends (e.g. pixma) close pipes and terminate reader threads in cancel,
// which needs time to complete before safe close.
constexpr int32_t CANCEL_WAIT_TIMEOUT_MS = 100;
} // namespace

SafeSANEAPI& SafeSANEAPI::GetInstance()
{
    static SafeSANEAPI instance;
    return instance;
}

std::shared_ptr<std::mutex> SafeSANEAPI::GetHandleMutex(SANE_Handle handle)
{
    if (handle == nullptr) {
        SCAN_HILOGE("GetHandleMutex: handle is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(handleMutexesLock_);
    auto it = handleMutexes_.find(handle);
    if (it == handleMutexes_.end() || !it->second) {
        SCAN_HILOGE("GetHandleMutex: handle not registered");
        return nullptr;
    }
    return it->second;
}

void SafeSANEAPI::AddHandleMutex(SANE_Handle handle)
{
    if (handle == nullptr) {
        SCAN_HILOGE("AddHandleMutex: handle is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(handleMutexesLock_);
    handleMutexes_[handle] = std::make_shared<std::mutex>();
    SCAN_HILOGI("AddHandleMutex: handle added");
}

std::shared_ptr<std::mutex> SafeSANEAPI::RemoveHandleMutex(SANE_Handle handle)
{
    if (handle == nullptr) {
        SCAN_HILOGE("RemoveHandleMutex: handle is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(handleMutexesLock_);
    auto it = handleMutexes_.find(handle);
    if (it == handleMutexes_.end() || !it->second) {
        SCAN_HILOGE("RemoveHandleMutex: handle not found");
        return nullptr;
    }
    auto mutexPtr = it->second;
    handleMutexes_.erase(it);
    SCAN_HILOGI("RemoveHandleMutex: handle removed");
    return mutexPtr;
}

SANE_Status SafeSANEAPI::SaneInit(SANE_Int* version, SANE_Auth_Callback authorize)
{
    std::lock_guard<std::mutex> lock(globalLock_);
    return sane_init(version, authorize);
}

void SafeSANEAPI::SaneExit()
{
    std::lock_guard<std::mutex> lock(globalLock_);
    sane_exit();
}

SANE_Status SafeSANEAPI::SaneGetDevices(const SANE_Device*** deviceList, SANE_Bool localOnly)
{
    std::lock_guard<std::mutex> lock(globalLock_);
    return sane_get_devices(deviceList, localOnly);
}

SANE_Status SafeSANEAPI::SaneOpen(const char* device_name, SANE_Handle* handle)
{
    std::lock_guard<std::mutex> lock(globalLock_);
    SANE_Status status = sane_open(device_name, handle);
    if (status == SANE_STATUS_GOOD && handle != nullptr && *handle != nullptr) {
        AddHandleMutex(*handle);
    }
    return status;
}

void SafeSANEAPI::SaneClose(SANE_Handle handle)
{
    std::shared_ptr<std::mutex> mutexPtr = RemoveHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneClose: handle not registered or already closed");
        return;
    }
    std::lock_guard<std::mutex> handleLock(*mutexPtr);
    sane_close(handle);
}

SANE_Status SafeSANEAPI::SaneStart(SANE_Handle handle)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneStart: handle not registered or already closed");
        return SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    return sane_start(handle);
}

void SafeSANEAPI::SaneCancel(SANE_Handle handle)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneCancel: handle not registered or already closed");
        return;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    sane_cancel(handle);
}

const SANE_Option_Descriptor* SafeSANEAPI::SaneGetOptionDescriptor(SANE_Handle handle, SANE_Int option)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneGetOptionDescriptor: handle not registered or already closed");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    return sane_get_option_descriptor(handle, option);
}

SANE_Status SafeSANEAPI::SaneGetParameters(SANE_Handle handle, SANE_Parameters* params)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneGetParameters: handle not registered or already closed");
        return SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    return sane_get_parameters(handle, params);
}

SANE_Status SafeSANEAPI::SaneControlOption(SANE_Handle handle, SANE_Int option,
    SANE_Action action, void* value, SANE_Int* info)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneControlOption: handle not registered or already closed");
        return SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    return sane_control_option(handle, option, action, value, info);
}

SANE_Status SafeSANEAPI::SaneRead(SANE_Handle handle, SANE_Byte* data,
    SANE_Int maxLength, SANE_Int* length)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneRead: handle not registered or already closed");
        return SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    return sane_read(handle, data, maxLength, length);
}

void SafeSANEAPI::SaneCloseAllHandles()
{
    std::vector<SANE_Handle> handles;
    {
        std::lock_guard<std::mutex> lock(handleMutexesLock_);
        for (auto it = handleMutexes_.begin(); it != handleMutexes_.end(); ++it) {
            handles.emplace_back(it->first);
        }
    }
    
    if (handles.empty()) {
        SCAN_HILOGI("SaneCloseAllHandles: no handles to close");
        return;
    }
    
    SCAN_HILOGI("SaneCloseAllHandles: cancelling %{public}zu handles", handles.size());
    for (auto handle : handles) {
        SaneCancel(handle);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(CANCEL_WAIT_TIMEOUT_MS));
    
    SCAN_HILOGI("SaneCloseAllHandles: closing %{public}zu handles", handles.size());
    for (auto handle : handles) {
        SaneClose(handle);
    }
    SCAN_HILOGI("SaneCloseAllHandles: all handles closed");
}

} // namespace Scan
} // namespace OHOS