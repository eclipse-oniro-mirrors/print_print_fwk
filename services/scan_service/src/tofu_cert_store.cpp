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

#include "tofu_cert_store.h"

#include <cerrno>
#include <cstdio>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "scan_constant.h"
#include "scan_log.h"
#include "securec.h"

namespace OHOS {
namespace Scan {
namespace {
// One byte renders as 2 hex chars in the fingerprint string.
constexpr unsigned int HEX_CHARS_PER_BYTE = 2;

// SHA-256 over the DER encoding, lower-case hex. Caller holds mutex_.
bool ReadFingerprintLocked(const std::string &path, std::string &fingerprint)
{
    FILE *fp = fopen(path.c_str(), "r");
    if (fp == nullptr) {
        return false;
    }
    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    if (fclose(fp) != 0) {
        SCAN_HILOGE("close cert file failed");
        X509_free(cert);
        return false;
    }
    if (cert == nullptr) {
        return false;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    bool ok = X509_digest(cert, EVP_sha256(), digest, &len) == 1;
    X509_free(cert);
    if (!ok || len == 0) {
        return false;
    }
    fingerprint.clear();
    fingerprint.reserve(len * HEX_CHARS_PER_BYTE);
    char hex[HEX_CHARS_PER_BYTE + 1] = {0};
    for (unsigned int i = 0; i < len; i++) {
        if (sprintf_s(hex, sizeof(hex), "%02x", digest[i]) < 0) {
            SCAN_HILOGE("sprintf_s hex fail");
            return false;
        }
        fingerprint += hex;
    }
    return true;
}
} // namespace

std::string TofuCertStore::CertPath(const std::string &ipAddress)
{
    return SCANNER_SANE_CERT_DIR + "/" + ipAddress + SCANNER_SANE_CERT_SUFFIX;
}

std::string TofuCertStore::PendingPath(const std::string &ipAddress)
{
    return SCANNER_SANE_CERT_DIR + "/" + ipAddress + SCANNER_SANE_CERT_PENDING_SUFFIX;
}

bool TofuCertStore::ReadPendingFingerprint(const std::string &ipAddress, std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return ReadFingerprintLocked(PendingPath(ipAddress), fingerprint);
}

TofuCertStore::PromoteResult TofuCertStore::PromotePending(const std::string &ipAddress,
    const std::string &expectedFingerprint)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string pendingPath = PendingPath(ipAddress);
    std::string actualFingerprint;
    if (!ReadFingerprintLocked(pendingPath, actualFingerprint)) {
        SCAN_HILOGE("pending cert missing/unreadable, refuse trust");
        return PromoteResult::MISSING;
    }
    if (actualFingerprint != expectedFingerprint) {
        SCAN_HILOGE("pending cert fingerprint mismatch, refuse trust");
        unlink(pendingPath.c_str());
        return PromoteResult::MISMATCH;
    }
    // Atomic promote: the confirmed bytes become the new baseline.
    if (rename(pendingPath.c_str(), CertPath(ipAddress).c_str()) != 0) {
        SCAN_HILOGE("promote pending cert failed, errno=%{public}d", errno);
        return PromoteResult::RENAME_FAILED;
    }
    return PromoteResult::OK;
}

void TofuCertStore::DropPending(const std::string &ipAddress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    unlink(PendingPath(ipAddress).c_str());
}

void TofuCertStore::RemoveCert(const std::string &ipAddress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string certPath = CertPath(ipAddress);
    if (unlink(certPath.c_str()) == 0) {
        SCAN_HILOGI("TOFU cert removed: %{private}s", certPath.c_str());
    } else if (errno != ENOENT) {
        SCAN_HILOGW("TOFU cert remove failed: %{private}s, errno=%{public}d", certPath.c_str(), errno);
    }
    unlink(PendingPath(ipAddress).c_str());
}

void TofuCertStore::Migrate(const std::string &oldIpAddress, const std::string &newIpAddress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string oldPath = CertPath(oldIpAddress);
    const std::string newPath = CertPath(newIpAddress);
    // The pending cert belongs to the old address/session; drop it.
    unlink(PendingPath(oldIpAddress).c_str());

    // rename() atomically replaces any stale cert left at the new IP.
    if (rename(oldPath.c_str(), newPath.c_str()) == 0) {
        SCAN_HILOGI("RenameTofuCert: %{private}s -> %{private}s", oldPath.c_str(), newPath.c_str());
    } else if (errno != ENOENT) {
        SCAN_HILOGW("RenameTofuCert failed: errno=%{public}d", errno);
    }
}

} // namespace Scan
} // namespace OHOS
