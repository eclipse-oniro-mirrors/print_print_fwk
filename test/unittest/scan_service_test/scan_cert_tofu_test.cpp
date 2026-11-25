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

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "escl_driver_manager.h"
#include "tofu_cert_store.h"
#include "scan_constant.h"

using namespace testing::ext;

namespace OHOS {
namespace Scan {

namespace {
// eSCL scanner ids carry the address as "scheme://ip:port/...".
constexpr const char* OLD_DEVICE_ID = "airscan:eSCL:scanner:https://10.11.12.13:443/eSCL/";
constexpr const char* NEW_DEVICE_ID = "airscan:eSCL:scanner:https://10.11.12.14:443/eSCL/";
constexpr const char* OLD_IP = "10.11.12.13";
constexpr const char* NEW_IP = "10.11.12.14";

// Self-signed certificate used to exercise the fingerprint/promote path.
constexpr const char* TEST_CERT_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDCzCCAfOgAwIBAgIUZttoF8vN2uaWgSyhzCJnYL+J9sUwDQYJKoZIhvcNAQEL\n"
    "BQAwFDESMBAGA1UEAwwJdG9mdS10ZXN0MCAXDTI2MTEyMzAyMzAwM1oYDzIxMjYx\n"
    "MDMwMDIzMDAzWjAUMRIwEAYDVQQDDAl0b2Z1LXRlc3QwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQDGE0tBU626lGXHYveDl2x5CapNGcnx2ziYJutfAA5Z\n"
    "40XyQkDlhaMzAWBbNQBlmKhVxk2g8/shM3D7TSbk+bp6N2yPoezZ9xh5tI35I51B\n"
    "yS0I+oBhrRmzjlZzKONON+40wnpsmFcG/Jtq2NZk6A51MDwvf3XlQHYZB/0VAs87\n"
    "WpjhEscElp8a2WVfGMT95Gc6NKMTx9YdcaH9RjJo/7+ZNwiKIFAK9pSq4jGF1cr9\n"
    "Grdmxs11Yo0GNBdGUXAB85FXwH3fzGxi7HDUw9zWDOs4B6IvbnuGsFQBeeLS5z82\n"
    "dM7lWQr17PnZYlMwb1VN3VaodOtQFwV5ukoWDSk3/wH3AgMBAAGjUzBRMB0GA1Ud\n"
    "DgQWBBRK9YlMbpWmkYTLIjpDLEnT7qKbNDAfBgNVHSMEGDAWgBRK9YlMbpWmkYTL\n"
    "IjpDLEnT7qKbNDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCE\n"
    "xfOHPgUtRZ7QUXyaHdbpcblJjA50rZHTYsjYhytc3MxopypXIG1K+vfKND/cC27K\n"
    "jXylgbmPBMQf78kPefP6LJ1lN1lf+hL0cfXY1YB++bbplWJDN1mf10GBsQHoC9qV\n"
    "wsK0v24ONTtFlYWAIJ2XbqBr2dP6lgZhdeiH8a2TvKFZGVl4nsVwqM+hTJ91OcYZ\n"
    "Lh54bSCGxdXX4Ybx2rYu58+IpnP/5kdTyH8yBCACVDtm24UDkBAJxzUHH4K7PWoF\n"
    "f93gyzv/Zl863+46eRIzGFVhN9fT9CXK6pCaB/Hm4SGxxFErjnMCNsAPrr1Hx+1F\n"
    "stKmuhcVqmWT+9Jsq+dy\n"
    "-----END CERTIFICATE-----\n";

std::string CertFile(const std::string &ip)
{
    return TofuCertStore::CertPath(ip);
}

std::string PendingFile(const std::string &ip)
{
    return TofuCertStore::PendingPath(ip);
}

bool WriteFile(const std::string &path, const std::string &content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out << content;
    out.close();
    return true;
}

bool ReadFile(const std::string &path, std::string &content)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool FileExists(const std::string &path)
{
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

// The certificate directory is a hardcoded absolute path shared with
// sane-airscan, so the filesystem cases can only run where that directory is
// writable (the device/service environment). When it is not writable the
// cases are disabled via the project DISABLED_CASE mechanism instead of being
// silently skipped.
bool PrepareCertDir()
{
    std::error_code ec;
    std::filesystem::create_directories(SCANNER_SANE_CERT_DIR, ec);
    return access(SCANNER_SANE_CERT_DIR.c_str(), W_OK) == 0;
}

void RemoveCertFiles()
{
    unlink(CertFile(OLD_IP).c_str());
    unlink(CertFile(NEW_IP).c_str());
    unlink(PendingFile(OLD_IP).c_str());
    unlink(PendingFile(NEW_IP).c_str());
}
} // namespace

class ScanCertTofuTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanCertTofuTest::SetUpTestCase(void) {}
void ScanCertTofuTest::TearDownTestCase(void) {}

/**
 * 场景: 合法 https 设备 ID。
 * 预期: 成功解析出 IP 与端口。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_ValidHttps_ReturnsIpAndPort_0001, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_TRUE(EsclDriverManager::ExtractIpAndPort(OLD_DEVICE_ID, ip, port));
    EXPECT_EQ(OLD_IP, ip);
    EXPECT_EQ(443, port);
}

/**
 * 场景: 合法 http 设备 ID（端口 80）。
 * 预期: 成功解析出 IP 与端口。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_ValidHttp_ReturnsIpAndPort_0002, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_TRUE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:http://10.0.0.5:80/eSCL/", ip, port));
    EXPECT_EQ("10.0.0.5", ip);
    EXPECT_EQ(80, port);
}

/**
 * 场景: 设备 ID 缺少 "//" 分隔符。
 * 预期: 解析失败。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_MissingSchemeSeparator_ReturnsFalse_0003, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_FALSE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:10.11.12.13:443/eSCL/", ip, port));
}

/**
 * 场景: 端口段不是数字。
 * 预期: 解析失败。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_NonNumericPort_ReturnsFalse_0004, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_FALSE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:https://10.11.12.13:abc/eSCL/", ip, port));
}

/**
 * 场景: 端口为 0 或超过 65535。
 * 预期: 越界端口解析失败。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_PortOutOfRange_ReturnsFalse_0005, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_FALSE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:https://10.11.12.13:0/eSCL/", ip, port));
    EXPECT_FALSE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:https://10.11.12.13:65536/eSCL/", ip, port));
}

/**
 * 场景: 端口分隔冒号出现在路径斜杠之后。
 * 预期: 解析失败。
 */
HWTEST_F(ScanCertTofuTest, ExtractIpAndPort_ColonAfterSlash_ReturnsFalse_0006, TestSize.Level2)
{
    std::string ip;
    int32_t port = 0;
    EXPECT_FALSE(EsclDriverManager::ExtractIpAndPort(
        "airscan:eSCL:scanner:https://10.11.12.13/eSCL/:443", ip, port));
}

/**
 * 场景: pending 证书不存在。
 * 预期: 信任提升失败，返回 MISSING，不产生基线。
 */
HWTEST_F(ScanCertTofuTest, PromotePending_MissingPending_ReturnsMissing_0007, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();

    EXPECT_EQ(TofuCertStore::PromoteResult::MISSING,
        TofuCertStore::GetInstance().PromotePending(OLD_IP, "deadbeef"));
    EXPECT_FALSE(FileExists(CertFile(OLD_IP)));
    RemoveCertFiles();
}

/**
 * 场景: pending 证书与用户确认的指纹不一致。
 * 预期: 拒绝提升，pending 被删除，基线不变。
 */
HWTEST_F(ScanCertTofuTest, PromotePending_FingerprintMismatch_DropsPending_0012, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "OLD-BASELINE"));
    ASSERT_TRUE(WriteFile(PendingFile(OLD_IP), TEST_CERT_PEM));

    EXPECT_EQ(TofuCertStore::PromoteResult::MISMATCH,
        TofuCertStore::GetInstance().PromotePending(OLD_IP, "deadbeef"));
    EXPECT_FALSE(FileExists(PendingFile(OLD_IP)));
    std::string baseline;
    ASSERT_TRUE(ReadFile(CertFile(OLD_IP), baseline));
    EXPECT_EQ("OLD-BASELINE", baseline);
    RemoveCertFiles();
}

/**
 * 场景: 指纹与 pending 一致。
 * 预期: pending 原子提升为基线，pending 不再存在。
 */
HWTEST_F(ScanCertTofuTest, PromotePending_MatchingFingerprint_Promotes_0013, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(PendingFile(OLD_IP), TEST_CERT_PEM));
    std::string fingerprint;
    ASSERT_TRUE(TofuCertStore::GetInstance().ReadPendingFingerprint(OLD_IP, fingerprint));
    EXPECT_FALSE(fingerprint.empty());

    EXPECT_EQ(TofuCertStore::PromoteResult::OK,
        TofuCertStore::GetInstance().PromotePending(OLD_IP, fingerprint));
    EXPECT_FALSE(FileExists(PendingFile(OLD_IP)));
    std::string baseline;
    ASSERT_TRUE(ReadFile(CertFile(OLD_IP), baseline));
    EXPECT_EQ(TEST_CERT_PEM, baseline);
    RemoveCertFiles();
}

/**
 * 场景: 删除设备时清理证书。
 * 预期: 基线与 pending 都被删除。
 */
HWTEST_F(ScanCertTofuTest, RemoveCert_DropsBaselineAndPending_0014, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "BASELINE"));
    ASSERT_TRUE(WriteFile(PendingFile(OLD_IP), "PENDING"));

    TofuCertStore::GetInstance().RemoveCert(OLD_IP);

    EXPECT_FALSE(FileExists(CertFile(OLD_IP)));
    EXPECT_FALSE(FileExists(PendingFile(OLD_IP)));
    RemoveCertFiles();
}

/**
 * 场景: 旧 IP 的基线证书与 pending 证书存在，新 IP 无证书。
 * 预期: 基线被原子重命名到新 IP，旧 pending 被删除。
 */
HWTEST_F(ScanCertTofuTest, RenameTofuCert_MovesBaselineAndDropsPending_0008, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "OLD-BASELINE"));
    ASSERT_TRUE(WriteFile(PendingFile(OLD_IP), "OLD-PENDING"));

    EsclDriverManager::RenameTofuCert(OLD_DEVICE_ID, NEW_DEVICE_ID);

    std::string moved;
    EXPECT_FALSE(FileExists(CertFile(OLD_IP)));
    EXPECT_FALSE(FileExists(PendingFile(OLD_IP)));
    ASSERT_TRUE(ReadFile(CertFile(NEW_IP), moved));
    EXPECT_EQ("OLD-BASELINE", moved);
    RemoveCertFiles();
}

/**
 * 场景: 新 IP 已存在一份陈旧证书。
 * 预期: 重命名覆盖陈旧证书，新 IP 内容为旧 IP 的基线。
 */
HWTEST_F(ScanCertTofuTest, RenameTofuCert_ReplacesStaleNewIpCert_0009, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "CURRENT-BASELINE"));
    ASSERT_TRUE(WriteFile(CertFile(NEW_IP), "STALE-BASELINE"));

    EsclDriverManager::RenameTofuCert(OLD_DEVICE_ID, NEW_DEVICE_ID);

    std::string replaced;
    ASSERT_TRUE(ReadFile(CertFile(NEW_IP), replaced));
    EXPECT_EQ("CURRENT-BASELINE", replaced);
    EXPECT_FALSE(FileExists(CertFile(OLD_IP)));
    RemoveCertFiles();
}

/**
 * 场景: 新旧设备 ID 指向同一 IP。
 * 预期: 直接返回，基线证书保持不变。
 */
HWTEST_F(ScanCertTofuTest, RenameTofuCert_SameIp_KeepsBaseline_0010, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "SAME-BASELINE"));

    EsclDriverManager::RenameTofuCert(OLD_DEVICE_ID, OLD_DEVICE_ID);

    std::string kept;
    ASSERT_TRUE(ReadFile(CertFile(OLD_IP), kept));
    EXPECT_EQ("SAME-BASELINE", kept);
    RemoveCertFiles();
}

/**
 * 场景: 旧设备 ID 无法解析出 IP。
 * 预期: 不触碰任何证书文件。
 */
HWTEST_F(ScanCertTofuTest, RenameTofuCert_InvalidOldDeviceId_KeepsFiles_0011, TestSize.Level2)
{
    ASSERT_TRUE(PrepareCertDir());
    RemoveCertFiles();
    ASSERT_TRUE(WriteFile(CertFile(OLD_IP), "UNTOUCHED"));

    EsclDriverManager::RenameTofuCert("invalid-device-id", NEW_DEVICE_ID);

    std::string untouched;
    ASSERT_TRUE(ReadFile(CertFile(OLD_IP), untouched));
    EXPECT_EQ("UNTOUCHED", untouched);
    EXPECT_FALSE(FileExists(CertFile(NEW_IP)));
    RemoveCertFiles();
}

} // namespace Scan
} // namespace OHOS
