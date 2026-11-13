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
#include <utility>
#include "safe_sane_api.h"
#include "sane/sane.h"
#include "sane/saneopts.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS {
namespace Scan {

namespace {
// Timeout for waiting cancel to take effect before closing handles.
// Some backends (e.g. pixma) close pipes and terminate reader threads in cancel,
// which needs time to complete before safe close.
constexpr int32_t CANCEL_WAIT_TIMEOUT_MS = 100;
constexpr int32_t MAX_WORD_LIST_SIZE = 1000;

void ConvertSaneWordList(const SANE_Word *wordList, SaneOptionDescriptor &saneOptDes)
{
    if (wordList != nullptr) {
        int32_t sizeNumber = wordList[0];
        if (sizeNumber < 0 || sizeNumber > MAX_WORD_LIST_SIZE) {
            SCAN_HILOGE("Invalid word_list size: %{public}d", sizeNumber);
            return;
        }
        saneOptDes.optionConstraintNumber_.assign(wordList + 1, wordList + 1 + sizeNumber);
    }
}

void ConvertSaneStringList(const SANE_String_Const *stringList, SaneOptionDescriptor &saneOptDes)
{
    if (stringList != nullptr) {
        for (int32_t i = 0; i < MAX_WORD_LIST_SIZE && stringList[i] != nullptr; i++) {
            saneOptDes.optionConstraintString_.emplace_back(stringList[i]);
        }
    }
}

void ConvertSaneConstraint(const SANE_Option_Descriptor &saneDesc, SaneOptionDescriptor &saneOptDes)
{
    if (saneDesc.constraint_type == ::SANE_CONSTRAINT_RANGE && saneDesc.constraint.range != nullptr) {
        saneOptDes.minValue_ = saneDesc.constraint.range->min;
        saneOptDes.maxValue_ = saneDesc.constraint.range->max;
        saneOptDes.quantValue_ = saneDesc.constraint.range->quant;
    } else if (saneDesc.constraint_type == ::SANE_CONSTRAINT_WORD_LIST) {
        ConvertSaneWordList(saneDesc.constraint.word_list, saneOptDes);
    } else if (saneDesc.constraint_type == ::SANE_CONSTRAINT_STRING_LIST) {
        ConvertSaneStringList(saneDesc.constraint.string_list, saneOptDes);
    }
}

void ConvertSaneDescriptor(const SANE_Option_Descriptor &saneDesc, SaneOptionDescriptor &saneOptDes)
{
    if (saneDesc.name != nullptr) {
        saneOptDes.optionName_ = saneDesc.name;
    }
    if (saneDesc.title != nullptr) {
        saneOptDes.optionTitle_ = saneDesc.title;
    }
    if (saneDesc.desc != nullptr) {
        saneOptDes.optionDesc_ = saneDesc.desc;
    }
    saneOptDes.optionType_ = static_cast<int32_t>(saneDesc.type);
    saneOptDes.optionUnit_ = static_cast<int32_t>(saneDesc.unit);
    saneOptDes.optionSize_ = saneDesc.size;
    saneOptDes.optionCap_ = saneDesc.cap;
    saneOptDes.optionConstraintType_ = static_cast<int32_t>(saneDesc.constraint_type);
    ConvertSaneConstraint(saneDesc, saneOptDes);
}
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
    if (status == ::SANE_STATUS_GOOD && handle != nullptr && *handle != nullptr) {
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
        return ::SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(GetHandleMutex(handle), ::SANE_STATUS_INVAL, __func__);
    return sane_start(handle);
}

void SafeSANEAPI::SaneCancel(SANE_Handle handle)
{
    if (handle == nullptr) {
        SCAN_HILOGE("SaneCancel: handle is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(handleMutexesLock_);
    auto it = handleMutexes_.find(handle);
    if (it == handleMutexes_.end() || !it->second) {
        SCAN_HILOGE("SaneCancel: handle not registered or already closed");
        return;
    }
    sane_cancel(handle);
}

std::optional<SaneOptionDescriptor> SafeSANEAPI::SaneGetOptionDescriptor(SANE_Handle handle, SANE_Int option)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneGetOptionDescriptor: handle not registered or already closed");
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(GetHandleMutex(handle), std::nullopt, __func__);
    const SANE_Option_Descriptor* saneDesc = sane_get_option_descriptor(handle, option);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(saneDesc, std::nullopt, __func__);
    std::optional<SaneOptionDescriptor> saneOptDes(std::in_place);
    ConvertSaneDescriptor(*saneDesc, *saneOptDes);
    return saneOptDes;
}

SANE_Status SafeSANEAPI::SaneGetParameters(SANE_Handle handle, SANE_Parameters* params)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneGetParameters: handle not registered or already closed");
        return ::SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(GetHandleMutex(handle), ::SANE_STATUS_INVAL, __func__);
    return sane_get_parameters(handle, params);
}

SANE_Status SafeSANEAPI::SaneControlOption(SANE_Handle handle, SANE_Int option,
    SANE_Action action, void* value, SANE_Int* info)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneControlOption: handle not registered or already closed");
        return ::SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(GetHandleMutex(handle), ::SANE_STATUS_INVAL, __func__);
    return sane_control_option(handle, option, action, value, info);
}

SANE_Status SafeSANEAPI::SaneRead(SANE_Handle handle, SANE_Byte* data,
    SANE_Int maxLength, SANE_Int* length)
{
    std::shared_ptr<std::mutex> mutexPtr = GetHandleMutex(handle);
    if (!mutexPtr) {
        SCAN_HILOGE("SaneRead: handle not registered or already closed");
        return ::SANE_STATUS_INVAL;
    }
    std::lock_guard<std::mutex> lock(*mutexPtr);
    SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(GetHandleMutex(handle), ::SANE_STATUS_INVAL, __func__);
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