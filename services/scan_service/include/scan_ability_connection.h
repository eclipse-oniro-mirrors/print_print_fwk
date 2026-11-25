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

#ifndef SCAN_ABILITY_CONNECTION_H
#define SCAN_ABILITY_CONNECTION_H

#include <atomic>
#include <functional>
#include <string>

#include "ability_connect_callback_stub.h"
#include "iremote_object.h"
#include "scan_cert_dialog_callback.h"

namespace OHOS::Scan {
// Connection object for the framework-hosted scanner dialog ability.
// The connection lifecycle is the dialog's close notification (connected
// service-extension ability). Mirrors PrintServiceHelper::PrintAbilityConnection.
class ScanAbilityConnection : public AAFwk::AbilityConnectionStub {
public:
    ScanAbilityConnection(std::function<void(const std::string &)> onConnected,
        std::function<void(const std::string &)> onClosed);
    ~ScanAbilityConnection() override = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

    bool IsConnected() const;
    // Register the decision callback with the dialog; sends the session id.
    void SetDecisionCallback(const sptr<ScanCertDecisionCallback> &callback, const std::string &sessionId);
    // Ask the dialog to close itself (session invalidated).
    bool SendDismiss(const std::string &sessionId);
    sptr<IRemoteObject> GetRemote() const;

private:
    class ScanConnectCallbackRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ScanConnectCallbackRecipient(std::function<void()> func) : func_(std::move(func))
        {}
        ~ScanConnectCallbackRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        std::function<void()> func_ = nullptr;
    };

    std::atomic<bool> isConnected_ = false;
    std::function<void(const std::string &)> onConnected_ = nullptr;
    std::function<void(const std::string &)> onClosed_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    sptr<IRemoteObject> dialogRemote_ = nullptr;
    sptr<ScanCertDecisionCallback> decisionCallback_ = nullptr;
    std::string sessionId_;
};
} // namespace OHOS::Scan
#endif // SCAN_ABILITY_CONNECTION_H
