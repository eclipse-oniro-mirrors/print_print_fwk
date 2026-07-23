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

#include "print_ipc_connection.h"
#include "print_constant.h"
#include "refbase.h"
#include "ipc_object_stub.h"
#include "print_common_death_recipient.h"
#include "remote_service_adapter.h"

namespace OHOS::Print {

void PrintIpcConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject,
    int32_t resultCode)
{
    PRINT_HILOGI("PrintIpcConnection::OnAbilityConnectDone resultCode = %{public}d", resultCode);
    if (resultCode == ERR_OK && remoteObject != nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (remoteObject_ != nullptr && deathRecipient_ != nullptr) {
            if (!remoteObject_->RemoveDeathRecipient(deathRecipient_)) {
                PRINT_HILOGW("RemoveDeathRecipient failed during connect");
            }
        }
        
        remoteObject_ = remoteObject;
        wptr<PrintIpcConnection> weakThis = this;
        deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
            new (std::nothrow) PrintCommonDeathRecipient([weakThis](const sptr<IRemoteObject> &remote) {
                sptr<PrintIpcConnection> connection = weakThis.promote();
                PRINT_CHECK_NULL_RETURN_VOID(connection);
                PRINT_HILOGI("Remote service died, attempting reconnect");
                std::lock_guard<std::mutex> lock(connection->mutex_);
                connection->remoteObject_ = nullptr;
                connection->deathRecipient_ = nullptr;
                
                RemoteServiceAdapter::GetInstance().OnRemoteServiceDied();
            }));
        
        PRINT_CHECK_NULL_RETURN_VOID(deathRecipient_);
        if (!remoteObject_->AddDeathRecipient(deathRecipient_)) {
            PRINT_HILOGW("AddDeathRecipient failed during connect");
        }
        
        cv_.notify_one();
        PRINT_HILOGI("ipc service connected successfully with death recipient");
    } else {
        PRINT_HILOGE("ipc service connect failed, resultCode = %{public}d", resultCode);
    }
}

void PrintIpcConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    PRINT_HILOGI("PrintIpcConnection::OnAbilityDisconnectDone resultCode = %{public}d", resultCode);
    if (resultCode == ERR_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (remoteObject_ != nullptr && deathRecipient_ != nullptr) {
            if (!remoteObject_->RemoveDeathRecipient(deathRecipient_)) {
                PRINT_HILOGW("RemoveDeathRecipient failed during disconnect");
            }
        }
        
        remoteObject_ = nullptr;
        deathRecipient_ = nullptr;
        PRINT_HILOGI("ipc service disconnected successfully");
    } else {
        PRINT_HILOGE("ipc service disconnect failed, resultCode = %{public}d", resultCode);
    }
}

void PrintIpcConnection::ClearConnection()
{
    PRINT_HILOGI("PrintIpcConnection::ClearConnection");
    std::lock_guard<std::mutex> lock(mutex_);
    if (remoteObject_ != nullptr && deathRecipient_ != nullptr) {
        if (!remoteObject_->RemoveDeathRecipient(deathRecipient_)) {
            PRINT_HILOGW("RemoveDeathRecipient failed during clear");
        }
    }
    remoteObject_ = nullptr;
    deathRecipient_ = nullptr;
}

bool PrintIpcConnection::IsConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return remoteObject_ != nullptr;
}

sptr<IRemoteObject> PrintIpcConnection::GetRemoteObject()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return remoteObject_;
}

bool PrintIpcConnection::WaitForConnection(int32_t timeoutMs)
{
    PRINT_HILOGI("PrintIpcConnection::WaitForConnection timeout = %{public}d ms", timeoutMs);
    std::unique_lock<std::mutex> lock(mutex_);
    bool result = cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [this] { return remoteObject_ != nullptr; });
    PRINT_HILOGI("WaitForConnection result = %{public}d", result);
    return result;
}

int32_t PrintIpcConnection::SendData(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("PrintIpcConnection::SendData code = %{public}d", code);
    sptr<IRemoteObject> remoteObject;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        remoteObject = remoteObject_;
    }
    if (remoteObject == nullptr) {
        PRINT_HILOGE("connection is not established");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t result = remoteObject->SendRequest(code, data, reply, option);
    if (result != ERR_OK) {
        PRINT_HILOGE("SendRequest failed, result = %{public}d, clearing remoteObject", result);
        std::lock_guard<std::mutex> lock(mutex_);
        remoteObject_ = nullptr;
    }
    return result;
}

} // namespace OHOS::Print