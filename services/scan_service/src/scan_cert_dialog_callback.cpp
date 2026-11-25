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

#include "scan_cert_dialog_callback.h"

#include "scan_constant.h"
#include "scan_log.h"
#include "string_ex.h"

namespace OHOS::Scan {
ScanCertDecisionCallback::ScanCertDecisionCallback(DecisionHandler handler) : handler_(std::move(handler))
{}

int ScanCertDecisionCallback::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        SCAN_HILOGE("cert dialog callback descriptor mismatch");
        return E_SCAN_RPC_FAILURE;
    }
    if (code != static_cast<uint32_t>(ScanCertDecisionCode::ON_DECISION)) {
        SCAN_HILOGE("unknown cert dialog callback code: %{public}u", code);
        return E_SCAN_RPC_FAILURE;
    }
    // The dialog is an ArkTS RemoteObject: ArkTS MessageSequence.writeString
    // serializes as String16, so the native side must read String16 here.
    std::u16string sessionId;
    std::u16string scannerId;
    std::u16string fingerprint;
    int32_t decision = 0;
    if (!data.ReadString16(sessionId) || !data.ReadString16(scannerId) ||
        !data.ReadString16(fingerprint) || !data.ReadInt32(decision)) {
        SCAN_HILOGE("read cert dialog decision failed");
        return E_SCAN_RPC_FAILURE;
    }
    OnDecision(Str16ToStr8(sessionId), Str16ToStr8(scannerId), Str16ToStr8(fingerprint), decision);
    return E_SCAN_NONE;
}

void ScanCertDecisionCallback::OnDecision(const std::string &sessionId, const std::string &scannerId,
    const std::string &fingerprint, int32_t decision)
{
    if (handler_) {
        handler_(sessionId, scannerId, fingerprint, decision);
    }
}
} // namespace OHOS::Scan
