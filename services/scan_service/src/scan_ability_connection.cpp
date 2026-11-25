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

#include "scan_ability_connection.h"

#include "scan_log.h"
#include "string_ex.h"

namespace OHOS::Scan {
void ScanAbilityConnection::ScanConnectCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SCAN_HILOGI("cert dialog ability died");
    if (func_) {
        func_();
    }
}

ScanAbilityConnection::ScanAbilityConnection(std::function<void(const std::string &)> onConnected,
    std::function<void(const std::string &)> onClosed)
    : onConnected_(std::move(onConnected)), onClosed_(std::move(onClosed))
{}

void ScanAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    if (resultCode != ERR_OK) {
        SCAN_HILOGE("connect cert dialog ability failed, ret: %{public}d", resultCode);
        // A failed connect has no disconnect callback; release the dialog slot here.
        if (onClosed_) {
            onClosed_(sessionId_);
        }
        return;
    }
    SCAN_HILOGI("connect cert dialog ability done");
    isConnected_ = true;
    if (remoteObject == nullptr || deathRecipient_ == nullptr) {
        SCAN_HILOGE("fail to add death recipient for cert dialog ability");
        if (onClosed_) {
            onClosed_(sessionId_);
        }
        return;
    }
    dialogRemote_ = remoteObject;
    remoteObject->AddDeathRecipient(deathRecipient_);
    if (decisionCallback_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option(MessageOption::TF_ASYNC);
        if (data.WriteInterfaceToken(IScanCertDialogCallback::GetDescriptor()) &&
            data.WriteRemoteObject(decisionCallback_->AsObject())) {
            dialogRemote_->SendRequest(static_cast<uint32_t>(ScanCertDialogCode::REGISTER_CALLBACK),
                data, reply, option);
        } else {
            SCAN_HILOGE("write cert dialog callback failed");
        }
    }
    if (onConnected_) {
        onConnected_(sessionId_);
    }
}

void ScanAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    SCAN_HILOGI("cert dialog ability disconnected, ret: %{public}d", resultCode);
    isConnected_ = false;
    if (onClosed_) {
        onClosed_(sessionId_);
    }
}

bool ScanAbilityConnection::IsConnected() const
{
    return isConnected_.load();
}

void ScanAbilityConnection::SetDecisionCallback(const sptr<ScanCertDecisionCallback> &callback,
    const std::string &sessionId)
{
    decisionCallback_ = callback;
    sessionId_ = sessionId;
    // Capture the callback and session by value so a death notification that
    // arrives after this connection is released cannot dangle on `this`.
    deathRecipient_ = new ScanConnectCallbackRecipient(
        [onClosed = onClosed_, sessionId = sessionId]() {
            if (onClosed) {
                onClosed(sessionId);
            }
        });
}

bool ScanAbilityConnection::SendDismiss(const std::string &sessionId)
{
    if (dialogRemote_ == nullptr) {
        SCAN_HILOGE("dismiss cert dialog: remote is null");
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    // The dialog is an ArkTS RemoteObject: ArkTS MessageSequence.readString
    // expects String16, so the native side must write String16 here.
    if (!data.WriteInterfaceToken(IScanCertDialogCallback::GetDescriptor()) ||
        !data.WriteString16(Str8ToStr16(sessionId))) {
        SCAN_HILOGE("write dismiss session failed");
        return false;
    }
    return dialogRemote_->SendRequest(static_cast<uint32_t>(ScanCertDialogCode::DISMISS),
        data, reply, option) == ERR_NONE;
}

sptr<IRemoteObject> ScanAbilityConnection::GetRemote() const
{
    return dialogRemote_;
}
} // namespace OHOS::Scan
