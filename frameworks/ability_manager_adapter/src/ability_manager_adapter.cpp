/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ability_manager_adapter.h"
#include "ability_manager_ipc_interface_code.h"
#include "print_constant.h"
#include "print_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Print {
namespace {
const std::u16string ABILITY_MGR_DESCRIPTOR = u"ohos.aafwk.AbilityManager";
}

AbilityManagerAdapter &AbilityManagerAdapter::GetInstance()
{
    static AbilityManagerAdapter instance;

    return instance;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

ErrCode AbilityManagerAdapter::Connect()
{
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    if (proxy_ != nullptr) {
        PRINT_HILOGI("[AbilityManagerAdapter] Connect exit, proxy already exists, return ERR_OK");
        return ERR_OK;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    PRINT_CHECK_NULL_AND_RETURN(systemManager, E_PRINT_GENERIC_FAILURE);
    sptr<IRemoteObject> remoteObj = systemManager->CheckSystemAbility(ABILITY_MGR_SERVICE_ID);
    PRINT_CHECK_NULL_AND_RETURN(remoteObj, E_PRINT_GENERIC_FAILURE);
    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AbilityMgrDeathRecipient());
    PRINT_CHECK_NULL_AND_RETURN(deathRecipient_, E_PRINT_GENERIC_FAILURE);
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        PRINT_HILOGE("[AbilityManagerAdapter] Add death recipient to AbilityManagerService failed");
        return E_PRINT_GENERIC_FAILURE;
    }
    proxy_ = remoteObj;
    PRINT_HILOGI("[AbilityManagerAdapter] Connect success");
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StartAbility(
    const Want &want, int requestCode, int32_t userId, uint64_t specifiedFullTokenId)
{
    auto abms = GetAbilityManagerProxy();
    PRINT_CHECK_NULL_AND_RETURN(abms, E_PRINT_GENERIC_FAILURE);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteParcelable(&want), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt32(userId), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt32(requestCode), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint64(specifiedFullTokenId), E_PRINT_RPC_FAILURE);

    ErrCode error =
        abms->SendRequest(static_cast<uint32_t>(AbilityManagerInterfaceCode::START_ABILITY), data, reply, option);
    if (error != NO_ERROR) {
        PRINT_HILOGE("[AbilityManagerAdapter] StartAbility send request error: %{public}d", error);
        return error;
    }
    ErrCode result;
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.ReadInt32(result), E_PRINT_RPC_FAILURE);
    PRINT_HILOGI("[AbilityManagerAdapter] StartAbility exit, result=%{public}d", result);
    return result;
}

ErrCode AbilityManagerAdapter::ConnectAbility(const Want &want, sptr<IAbilityConnection> connect, int32_t userId)
{
    return ConnectAbilityCommon(want, connect, nullptr, AppExecFwk::ExtensionAbilityType::SERVICE, userId, false, 0, 0);
}

ErrCode AbilityManagerAdapter::ConnectAbilityWithExtensionType(const Want &want, sptr<IAbilityConnection> connect,
    sptr<IRemoteObject> callerToken, int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    return ConnectAbilityCommon(want, connect, callerToken, extensionType, userId);
}

ErrCode AbilityManagerAdapter::ConnectAbilityCommon(const Want &want, const sptr<IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken, AppExecFwk::ExtensionAbilityType extensionType, int32_t userId,
    bool isQueryExtensionOnly, uint64_t specifiedFullTokenId, int32_t loadTimeout)
{
    auto abms = GetAbilityManagerProxy();
    PRINT_CHECK_NULL_AND_RETURN(abms, E_PRINT_GENERIC_FAILURE);
    PRINT_CHECK_NULL_AND_RETURN(connect, E_PRINT_INVALID_PARAMETER);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteParcelable(&want), E_PRINT_RPC_FAILURE);
    auto connectObject = connect->AsObject();
    if (connectObject) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteBool(true), E_PRINT_RPC_FAILURE);
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteRemoteObject(connectObject), E_PRINT_RPC_FAILURE);
    } else {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteBool(false), E_PRINT_RPC_FAILURE);
    }
    if (callerToken) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteBool(true), E_PRINT_RPC_FAILURE);
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteRemoteObject(callerToken), E_PRINT_RPC_FAILURE);
    } else {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteBool(false), E_PRINT_RPC_FAILURE);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt32(userId), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt32(static_cast<int32_t>(extensionType)), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteBool(isQueryExtensionOnly), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint64(specifiedFullTokenId), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInt32(loadTimeout), E_PRINT_RPC_FAILURE);
    // 这里为了做兼容，原有的序列化逻辑这里需要传入IndirectCallerInfo, 基本都不传，默认为nullptr
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteParcelable(nullptr), E_PRINT_RPC_FAILURE);
    ErrCode error = abms->SendRequest(
        static_cast<uint32_t>(AbilityManagerInterfaceCode::CONNECT_ABILITY_WITH_TYPE), data, reply, option);
    if (error != NO_ERROR) {
        PRINT_HILOGE("[AbilityManagerAdapter] ConnectAbilityCommon send request error: %{public}d", error);
        return error;
    }
    ErrCode result;
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.ReadInt32(result), E_PRINT_RPC_FAILURE);
    PRINT_HILOGI("[AbilityManagerAdapter] ConnectAbilityCommon exit, result=%{public}d", result);
    return result;
}

ErrCode AbilityManagerAdapter::DisconnectAbility(sptr<IAbilityConnection> connect)
{
    auto abms = GetAbilityManagerProxy();
    PRINT_CHECK_NULL_AND_RETURN(abms, E_PRINT_GENERIC_FAILURE);
    PRINT_CHECK_NULL_AND_RETURN(connect, E_PRINT_INVALID_PARAMETER);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR), E_PRINT_RPC_FAILURE);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteRemoteObject(connect->AsObject()), E_PRINT_RPC_FAILURE);

    ErrCode error =
        abms->SendRequest(static_cast<uint32_t>(AbilityManagerInterfaceCode::DISCONNECT_ABILITY), data, reply, option);
    if (error != NO_ERROR) {
        PRINT_HILOGE("[AbilityManagerAdapter] DisconnectAbility send request error: %{public}d", error);
        return error;
    }
    ErrCode result;
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.ReadInt32(result), E_PRINT_RPC_FAILURE);
    PRINT_HILOGI("[AbilityManagerAdapter] DisconnectAbility exit, result=%{public}d", result);
    return result;
}

sptr<IRemoteObject> AbilityManagerAdapter::GetAbilityManagerProxy()
{
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    if (!proxy_) {
        PRINT_HILOGI("[AbilityManagerAdapter] GetAbilityManagerProxy proxy is nullptr, calling Connect()");
        Connect();
    }
    return proxy_;
}

void AbilityManagerAdapter::ResetProxy(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    if ((proxy_ != nullptr) && (proxy_ == remote.promote())) {
        PRINT_HILOGI("[AbilityManagerAdapter] ResetProxy removing death recipient and clearing proxy");
        proxy_->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void AbilityManagerAdapter::AbilityMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    PRINT_HILOGI("[AbilityManagerAdapter] AbilityMgrDeathRecipient OnRemoteDied");
    AbilityManagerAdapter::GetInstance().ResetProxy(remote);
}
}  // namespace Print
}  // namespace OHOS