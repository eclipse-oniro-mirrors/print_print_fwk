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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cups/cups-private.h>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>

#define private public
#include "print_cert_manager.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

namespace {
const std::string TEST_SSL_DIR = "/data/service/el1/public/print_service/cups/ssl";
const std::string TEST_URI = "ipps://192.168.1.1:631/ipp/print";
const std::string TEST_URI_NO_PORT = "foo://192.168.1.1/resource";
const std::string TEST_PRINTER_NAME = "Test Printer";

http_t *const FAKE_HTTP = reinterpret_cast<http_t *>(0x1000);
}  // namespace

class MockPrintCertAbility : public IPrintCertAbility {
public:
    MOCK_METHOD(http_t *, Connect, (const char *host, int port, int timeout), (override));
    MOCK_METHOD(bool, IsEncrypted, (http_t *http), (override));
    MOCK_METHOD(int, CopyCredentials, (http_t *http, cups_array_t **creds), (override));
    MOCK_METHOD(int, SaveCredentials, (const char *path, cups_array_t *creds, const char *commonName), (override));
    MOCK_METHOD(void, Close, (http_t *http), (override));
};

class PrintCertManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        manager_ = DelayedSingleton<PrintCertManager>::GetInstance();
        ASSERT_NE(manager_, nullptr);
        originalAbility_ = manager_->certAbility_;
        manager_->certAbility_ = &certMock_;
        sslDirExistedBefore_ = std::filesystem::exists(TEST_SSL_DIR);
        std::error_code ec;
        std::filesystem::create_directories(TEST_SSL_DIR, ec);
    }

    void TearDown() override
    {
        if (manager_ != nullptr) {
            manager_->certAbility_ = originalAbility_;
        }
        // Only remove artifacts created by these cases. Never remove the real
        // CUPS trust directory or its pre-existing contents.
        std::error_code ec;
        for (const auto &name : {"my_printer_1.crt", "my printer@1.crt", "a-b.c.crt", "dir_printer.crt"}) {
            std::filesystem::remove(TEST_SSL_DIR + "/" + name, ec);
        }
        if (!sslDirExistedBefore_) {
            // remove() only succeeds for an empty directory, which is the case
            // when this test created it and cleaned all its artifacts above.
            std::filesystem::remove(TEST_SSL_DIR, ec);
        }
    }

    static void CreateFile(const std::string &path)
    {
        std::ofstream ofs(path);
        ofs << "cert";
    }

    std::shared_ptr<PrintCertManager> manager_;
    IPrintCertAbility *originalAbility_ = nullptr;
    bool sslDirExistedBefore_ = false;
    NiceMock<MockPrintCertAbility> certMock_;
};

/**
 * @tc.name: SaveCertForPrinter_EmptyHost_001
 * @tc.desc: URI without hostname returns false and never connects.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_EmptyHost_001, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(_, _, _)).Times(0);
    EXPECT_FALSE(manager_->SaveCertForPrinter("", TEST_PRINTER_NAME));
    EXPECT_FALSE(manager_->SaveCertForPrinter("ipp:///resource", TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_ConnectFail_002
 * @tc.desc: TLS connection failure returns false without touching credentials.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_ConnectFail_002, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(StrEq("192.168.1.1"), 631, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(certMock_, IsEncrypted(_)).Times(0);
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_DefaultPort_003
 * @tc.desc: URI without explicit port falls back to IPP_PORT (631).
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_DefaultPort_003, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(StrEq("192.168.1.1"), IPP_PORT, _)).WillOnce(Return(nullptr));
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI_NO_PORT, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_NotEncrypted_004
 * @tc.desc: Plain connection is rejected and closed.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_NotEncrypted_004, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(_, _, _)).WillOnce(Return(FAKE_HTTP));
    EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(false));
    EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    EXPECT_CALL(certMock_, CopyCredentials(_, _)).Times(0);
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_CopyCredFail_005
 * @tc.desc: CopyCredentials non-zero return is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_CopyCredFail_005, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(_, _, _)).WillOnce(Return(FAKE_HTTP));
    EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(true));
    EXPECT_CALL(certMock_, CopyCredentials(FAKE_HTTP, _)).WillOnce(Return(-1));
    EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    EXPECT_CALL(certMock_, SaveCredentials(_, _, _)).Times(0);
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_CopyCredNull_006
 * @tc.desc: CopyCredentials success but null credentials is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_CopyCredNull_006, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(_, _, _)).WillOnce(Return(FAKE_HTTP));
    EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(true));
    EXPECT_CALL(certMock_, CopyCredentials(FAKE_HTTP, _)).WillOnce(Return(0));
    EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    EXPECT_CALL(certMock_, SaveCredentials(_, _, _)).Times(0);
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_SaveFail_007
 * @tc.desc: SaveCredentials failure returns false after releasing resources.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_SaveFail_007, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(_, _, _)).WillOnce(Return(FAKE_HTTP));
    EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(true));
    EXPECT_CALL(certMock_, CopyCredentials(FAKE_HTTP, _)).WillOnce([](http_t *, cups_array_t **creds) {
        *creds = cupsArrayNew(nullptr, nullptr);
        return 0;
    });
    EXPECT_CALL(certMock_, SaveCredentials(nullptr, NotNull(), StrEq(TEST_PRINTER_NAME)))
        .WillOnce(Return(-1));
    EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    EXPECT_FALSE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: SaveCertForPrinter_Success_008
 * @tc.desc: Full success path saves credentials under standardized printer name.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, SaveCertForPrinter_Success_008, TestSize.Level1)
{
    EXPECT_CALL(certMock_, Connect(StrEq("192.168.1.1"), 631, _)).WillOnce(Return(FAKE_HTTP));
    EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(true));
    EXPECT_CALL(certMock_, CopyCredentials(FAKE_HTTP, _)).WillOnce([](http_t *, cups_array_t **creds) {
        *creds = cupsArrayNew(nullptr, nullptr);
        return 0;
    });
    EXPECT_CALL(certMock_, SaveCredentials(nullptr, NotNull(), StrEq(TEST_PRINTER_NAME)))
        .WillOnce(Return(0));
    EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    EXPECT_TRUE(manager_->SaveCertForPrinter(TEST_URI, TEST_PRINTER_NAME));
}

/**
 * @tc.name: DeleteCertForPrinter_Sanitize_001
 * @tc.desc: Illegal characters are replaced with '_' so the sanitized file is removed.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, DeleteCertForPrinter_Sanitize_001, TestSize.Level1)
{
    std::string sanitized = TEST_SSL_DIR + "/my_printer_1.crt";
    std::string raw = TEST_SSL_DIR + "/my printer@1.crt";
    CreateFile(sanitized);
    CreateFile(raw);
    ASSERT_TRUE(std::filesystem::exists(sanitized));
    ASSERT_TRUE(std::filesystem::exists(raw));

    EXPECT_TRUE(manager_->DeleteCertForPrinter("my printer@1"));
    EXPECT_FALSE(std::filesystem::exists(sanitized));
    EXPECT_TRUE(std::filesystem::exists(raw));
}

/**
 * @tc.name: DeleteCertForPrinter_KeepAllowedChars_002
 * @tc.desc: alnum, '-' and '.' are preserved in the certificate file name.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, DeleteCertForPrinter_KeepAllowedChars_002, TestSize.Level1)
{
    std::string path = TEST_SSL_DIR + "/a-b.c.crt";
    CreateFile(path);
    ASSERT_TRUE(std::filesystem::exists(path));

    EXPECT_TRUE(manager_->DeleteCertForPrinter("a-b.c"));
    EXPECT_FALSE(std::filesystem::exists(path));
}

/**
 * @tc.name: DeleteCertForPrinter_NotExist_003
 * @tc.desc: Missing certificate file is treated as success (ENOENT).
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, DeleteCertForPrinter_NotExist_003, TestSize.Level1)
{
    EXPECT_TRUE(manager_->DeleteCertForPrinter("no_such_printer"));
}

/**
 * @tc.name: DeleteCertForPrinter_OtherErrno_004
 * @tc.desc: unlink failure other than ENOENT returns false.
 * @tc.type: FUNC
 */
HWTEST_F(PrintCertManagerTest, DeleteCertForPrinter_OtherErrno_004, TestSize.Level1)
{
    std::string path = TEST_SSL_DIR + "/dir_printer.crt";
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    ASSERT_TRUE(std::filesystem::is_directory(path)) << "cannot create directory " << path;

    EXPECT_FALSE(manager_->DeleteCertForPrinter("dir_printer"));
    EXPECT_TRUE(std::filesystem::is_directory(path));
}

}  // namespace Print
}  // namespace OHOS
