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

#include "remote_service_adapter.h"
#include "remote_constants.h"
#include "extension_manager_client.h"
#include "want.h"
#include "print_constant.h"
#include "refbase.h"
#include "os_account_manager.h"
#include "iremote_callback.h"
#include "print_json_util.h"
#include "print_utils.h"
#include <mutex>

namespace OHOS::Print {

RemoteServiceAdapter& RemoteServiceAdapter::GetInstance()
{
    static RemoteServiceAdapter instance;
    return instance;
}

RemoteServiceAdapter::RemoteServiceAdapter()
{
    PRINT_HILOGI("RemoteServiceAdapter constructor");
    connection_ = sptr<PrintIpcConnection>::MakeSptr();
    callbackStub_ = sptr<RemoteCallbackStub>::MakeSptr();
}

RemoteServiceAdapter::~RemoteServiceAdapter()
{
    PRINT_HILOGI("RemoteServiceAdapter destructor");
}

bool RemoteServiceAdapter::BindService()
{
    PRINT_HILOGI("RemoteServiceAdapter::BindService");
    
    PRINT_CHECK_NULL_AND_RETURN(connection_, false);
    
    std::lock_guard<std::mutex> lock(bindMutex_);
    if (IsConnected()) {
        PRINT_HILOGI("RemoteServiceAdapter already connected");
        return true;
    }
    
    std::vector<int32_t> userIds;
    if (AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds) != ERR_OK) {
        PRINT_HILOGE("failed to QueryActiveOsAccountIds");
        return false;
    }
    if (userIds.empty()) {
        PRINT_HILOGE("no active user id");
        return false;
    }
    int32_t userId = userIds[0];
    PRINT_HILOGI("active userId = %{public}d", userId);
    
    AAFwk::Want want;
    want.SetElementName(REMOTE_SERVICE_BUNDLE_NAME, REMOTE_ABILITY_NAME);
    
    AAFwk::ExtensionManagerClient extensionManager;
    int32_t result = extensionManager.ConnectServiceExtensionAbility(
        want, connection_->AsObject(), userId);
    PRINT_HILOGI("ConnectServiceExtensionAbility result = %{public}d", result);
    
    if (result != ERR_OK) {
        PRINT_HILOGE("ConnectServiceExtensionAbility failed");
        return false;
    }

    return true;
}

bool RemoteServiceAdapter::IsConnected()
{
    PRINT_CHECK_NULL_AND_RETURN(connection_, false);
    return connection_->GetRemoteObject() != nullptr;
}

void RemoteServiceAdapter::OnRemoteServiceDied()
{
    PRINT_HILOGI("RemoteServiceAdapter::OnRemoteServiceDied");
    
    PRINT_CHECK_NULL_RETURN_VOID(onServiceDiedCb_);
    PRINT_HILOGI("Calling onServiceDiedCallback to clear printers");
    onServiceDiedCb_();
}

int32_t RemoteServiceAdapter::SendData(uint32_t code, const std::string &msg)
{
    PRINT_HILOGI("RemoteServiceAdapter::SendData code = %{public}d, msg = %{public}s", code, msg.c_str());
    
    PRINT_CHECK_NULL_AND_RETURN(connection_, E_PRINT_RPC_FAILURE);
    auto remoteObject = connection_->GetRemoteObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGW("remoteObject is null, attempting reconnect");
        if (!BindService()) {
            PRINT_HILOGE("reconnect failed");
            return E_PRINT_RPC_FAILURE;
        }
        remoteObject = connection_->GetRemoteObject();
        PRINT_CHECK_NULL_AND_RETURN(remoteObject, E_PRINT_RPC_FAILURE);
    }

    PRINT_CHECK_NULL_AND_RETURN(callbackStub_, E_PRINT_RPC_FAILURE);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(
        data.WriteInterfaceToken(remoteObject->GetInterfaceDescriptor()), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteRemoteObject(callbackStub_->AsObject()), E_PRINT_RPC_FAILURE);
    
    const char* buffer = msg.c_str();
    size_t size = msg.size();
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt64(static_cast<int64_t>(size)), E_PRINT_RPC_FAILURE);
    if (size > 0 && buffer != nullptr) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteRawData(buffer, size), E_PRINT_RPC_FAILURE);
    }
    
    int32_t result = connection_->SendData(code, data, reply, option);
    PRINT_HILOGI("SendData result = %{public}d", result);
    return result;
}

int32_t RemoteServiceAdapter::RequestPrinterStatus(const std::string &devId)
{
    PRINT_HILOGI("RemoteServiceAdapter::RequestPrinterStatus devId: %{public}s", devId.c_str());
    
    Json::Value jsonArray(Json::arrayValue);
    jsonArray.append(devId);
    
    std::string msg = PrintJsonUtil::WriteString(jsonArray);
    PRINT_HILOGD("RequestPrinterStatus request: %{public}s", msg.c_str());
    return SendData(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS), msg);
}

int32_t RemoteServiceAdapter::RequestPrinterList()
{
    PRINT_HILOGI("RemoteServiceAdapter::RequestPrinterList");
    
    Json::Value jsonArray(Json::arrayValue);
    jsonArray.append(REMOTE_DEVICE_TYPE_PRINTER);
    
    std::string msg = PrintJsonUtil::WriteString(jsonArray);
    PRINT_HILOGD("RequestPrinterList request: %{public}s", msg.c_str());
    return SendData(static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST), msg);
}

void RemoteServiceAdapter::SetOnServiceDiedCallback(std::function<void()> cb)
{
    PRINT_HILOGI("RemoteServiceAdapter::SetOnServiceDiedCallback");
    onServiceDiedCb_ = cb;
}

} // namespace OHOS::Print