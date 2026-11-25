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

#ifndef TOFU_CERT_STORE_H
#define TOFU_CERT_STORE_H

#include <mutex>
#include <string>

namespace OHOS {
namespace Scan {

// Owns the TOFU certificate files shared with sane-airscan:
//   <ip>.crt          trusted baseline
//   <ip>.crt.pending  new cert awaiting user confirmation
// All file operations are serialized by a private leaf lock: never acquire
// lock_ or addedScannerMapLock_ while holding it, and never do IPC
// (SaneClose/SaneOpen, ability calls) inside these methods.
class TofuCertStore {
public:
    static TofuCertStore &GetInstance()
    {
        static TofuCertStore instance;
        return instance;
    }

    static std::string CertPath(const std::string &ipAddress);
    static std::string PendingPath(const std::string &ipAddress);

    // SHA-256 hex fingerprint of the pending cert. false = missing/unreadable.
    bool ReadPendingFingerprint(const std::string &ipAddress, std::string &fingerprint);

    enum class PromoteResult {
        OK,
        MISSING,        // pending absent or unreadable
        MISMATCH,       // pending bytes differ from the confirmed fingerprint
        RENAME_FAILED   // promote syscall failed
    };
    // Verify the pending cert against expectedFingerprint, then atomically
    // promote it to the baseline. On MISMATCH the pending file is dropped.
    PromoteResult PromotePending(const std::string &ipAddress, const std::string &expectedFingerprint);

    void DropPending(const std::string &ipAddress);
    // Remove baseline and pending for a deleted scanner.
    void RemoveCert(const std::string &ipAddress);
    // IP changed: drop the old pending and move the baseline to the new IP.
    void Migrate(const std::string &oldIpAddress, const std::string &newIpAddress);

private:
    TofuCertStore() = default;
    ~TofuCertStore() = default;
    TofuCertStore(const TofuCertStore &) = delete;
    TofuCertStore &operator=(const TofuCertStore &) = delete;

    std::mutex mutex_;
};

} // namespace Scan
} // namespace OHOS

#endif // TOFU_CERT_STORE_H
