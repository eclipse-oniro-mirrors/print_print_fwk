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

#include "remote_callback_stub.h"

#include <chrono>

#include "remote_constants.h"
#include "remote_printer_manager_impl.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_utils.h"
#include "ipc_skeleton.h"
#include "singleton.h"

namespace OHOS::Print {

namespace {

class PendingRequestGuard {
public:
    PendingRequestGuard(std::atomic<int32_t> &counter, std::mutex &mutex, std::condition_variable &cv)
        : counter_(counter), mutex_(mutex), cv_(cv)
    {
        counter_.fetch_add(1, std::memory_order_relaxed);
    }
    ~PendingRequestGuard()
    {
        if (counter_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            std::lock_guard<std::mutex> lock(mutex_);
            cv_.notify_all();
        }
    }
private:
    std::atomic<int32_t> &counter_;
    std::mutex &mutex_;
    std::condition_variable &cv_;
};

bool ReadRemoteRequestPayload(MessageParcel &data, int32_t &errorCode, std::string &msg)
{
    if (!data.ReadInt32(errorCode)) {
        PRINT_HILOGE("RemoteCallbackStub ReadInt32 errorCode failed");
        errorCode = E_PRINT_RPC_FAILURE;
        return false;
    }
    if (errorCode == E_PRINT_NETWORK_ERROR || errorCode == E_PRINT_ACCOUNT_ERROR ||
        errorCode == E_PRINT_INVALID_PARAMETER) {
        PRINT_HILOGE("RemoteCallbackStub error: %{public}d, clear printers", errorCode);
        RemotePrinterManagerImpl::GetInstance().ClearAllPrinters();
        return false;
    }
    if (errorCode != E_PRINT_NONE) {
        PRINT_HILOGE("RemoteCallbackStub read errorCode failed: %{public}d, remote unreachable", errorCode);
        return false;
    }

    int64_t rawDataSize = 0;
    if (!data.ReadInt64(rawDataSize)) {
        PRINT_HILOGE("RemoteCallbackStub ReadInt64 rawDataSize failed");
        errorCode = E_PRINT_RPC_FAILURE;
        return false;
    }
    if (rawDataSize < 0 || rawDataSize > REMOTE_MAX_RAW_DATA_SIZE) {
        PRINT_HILOGE("RemoteCallbackStub read rawDataSize invalid: %{public}lld",
            static_cast<long long>(rawDataSize));
        errorCode = E_PRINT_SERVER_FAILURE;
        return false;
    }

    if (rawDataSize > 0) {
        const char* rawData = static_cast<const char*>(data.ReadRawData(static_cast<size_t>(rawDataSize)));
        if (rawData == nullptr) {
            PRINT_HILOGE("RemoteCallbackStub read rawData failed");
            errorCode = E_PRINT_SERVER_FAILURE;
            return false;
        }
        msg.assign(rawData, static_cast<size_t>(rawDataSize));
    }
    return true;
}

} // namespace

RemoteCallbackStub::RemoteCallbackStub()
{
    cmdMap_[static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS)] =
        &RemoteCallbackStub::HandleGetPrinterStatus;
    cmdMap_[static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST)] =
        &RemoteCallbackStub::HandleGetPrinterList;
}

int32_t RemoteCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PendingRequestGuard guard(pendingRequests_, idleMutex_, idleCv_);
    PRINT_HILOGI("RemoteCallbackStub::OnRemoteRequest started, code = %{public}u", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    int32_t callerUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName = PrintUtils::GetBundleNameForUid(callerUid);
    if (callerBundleName != REMOTE_SERVICE_BUNDLE_NAME) {
        PRINT_HILOGE("RemoteCallbackStub rejected caller uid=%{public}d bundle=%{public}s",
            callerUid, callerBundleName.c_str());
        return E_PRINT_RPC_FAILURE;
    }

    int32_t errorCode = 0;
    std::string msg;
    if (!ReadRemoteRequestPayload(data, errorCode, msg)) {
        return errorCode;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(msg);
            return result ? E_PRINT_NONE : E_PRINT_SERVER_FAILURE;
        }
    }
    PRINT_HILOGW("RemoteCallbackStub default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool RemoteCallbackStub::HandleGetPrinterStatus(const std::string &msg)
{
    PRINT_HILOGI("RemoteCallbackStub HandleGetPrinterStatus");

    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(msg, jsonObject)) {
        PRINT_HILOGE("Failed to parse printer status response");
        return false;
    }

    if (!jsonObject.isArray()) {
        PRINT_HILOGE("Printer status response is not an array");
        return false;
    }

    return RemotePrinterManagerImpl::GetInstance().OnPrinterStatusReceived(jsonObject);
}

bool RemoteCallbackStub::HandleGetPrinterList(const std::string &msg)
{
    PRINT_HILOGI("RemoteCallbackStub HandleGetPrinterList");

    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(msg, jsonObject)) {
        PRINT_HILOGE("Failed to parse printer list response");
        return false;
    }

    if (!jsonObject.isArray()) {
        PRINT_HILOGE("Printer list response is not an array");
        return false;
    }

    return RemotePrinterManagerImpl::GetInstance().OnPrinterListReceived(jsonObject);
}

bool RemoteCallbackStub::WaitForIdle(int32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(idleMutex_);
    return idleCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [this] { return pendingRequests_.load(std::memory_order_acquire) == 0; });
}

} // namespace OHOS::Print
