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

#ifndef SCAN_CERT_DIALOG_CALLBACK_H
#define SCAN_CERT_DIALOG_CALLBACK_H

#include <functional>
#include <string>

#include "iremote_broker.h"
#include "iremote_stub.h"
#include "message_parcel.h"

namespace OHOS::Scan {
// Framework -> dialog transaction codes.
enum class ScanCertDialogCode : uint32_t {
    REGISTER_CALLBACK = 1,
    DISMISS = 2,
};

// Dialog -> framework transaction codes.
enum class ScanCertDecisionCode : uint32_t {
    ON_DECISION = 1,
};

enum class ScanCertDecision : int32_t {
    TRUST = 0,
    REJECT = 1,
};

// Internal callback used by the framework-hosted cert dialog. This is not a
// public SDK interface: the dialog calls it over the existing ConnectAbility
// connection to report the user's decision.
class IScanCertDialogCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Scan.IScanCertDialogCallback");
    virtual void OnDecision(const std::string &sessionId, const std::string &scannerId,
        const std::string &fingerprint, int32_t decision) = 0;
};

class ScanCertDecisionCallback : public IRemoteStub<IScanCertDialogCallback> {
public:
    using DecisionHandler = std::function<void(const std::string &sessionId, const std::string &scannerId,
        const std::string &fingerprint, int32_t decision)>;

    explicit ScanCertDecisionCallback(DecisionHandler handler);
    ~ScanCertDecisionCallback() override = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
    void OnDecision(const std::string &sessionId, const std::string &scannerId,
        const std::string &fingerprint, int32_t decision) override;

private:
    DecisionHandler handler_;
};
} // namespace OHOS::Scan
#endif // SCAN_CERT_DIALOG_CALLBACK_H
