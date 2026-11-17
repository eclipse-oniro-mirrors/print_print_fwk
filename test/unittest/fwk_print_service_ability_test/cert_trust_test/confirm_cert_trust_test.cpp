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
#include <string>

#define private public
#include "print_cert_manager.h"
#include "print_cups_client.h"
#undef private

#include "print_service_ability_test_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

namespace {
const std::string TEST_PRINTER_ID = "com.example.ext:cert_printer";
const std::string TEST_PRINTER_URI = "ipps://192.168.1.1:631/ipp/print";
const std::string TEST_PRINTER_NAME = "Test Printer";
const std::string TEST_PRINTER_NAME_STANDARD = "Test_Printer";
http_t *const FAKE_HTTP = reinterpret_cast<http_t *>(0x2000);
}  // namespace

class MockCertAbility : public IPrintCertAbility {
public:
    MOCK_METHOD(http_t *, Connect, (const char *host, int port, int timeout), (override));
    MOCK_METHOD(bool, IsEncrypted, (http_t *http), (override));
    MOCK_METHOD(int, CopyCredentials, (http_t *http, cups_array_t **creds), (override));
    MOCK_METHOD(int, SaveCredentials, (const char *path, cups_array_t *creds, const char *commonName), (override));
    MOCK_METHOD(void, Close, (http_t *http), (override));
};

class MockCupsAbility : public IPrintAbilityBase {
public:
    MOCK_METHOD(cups_dest_t *, GetNamedDest, (http_t *http, const char *name, const char *instance), (override));
    MOCK_METHOD(void, FreeDests, (int num, cups_dest_t *dests), (override));
    MOCK_METHOD(cups_dinfo_t *, CopyDestInfo, (http_t *http, cups_dest_t *dest), (override));
    MOCK_METHOD(void, FreeDestInfo, (cups_dinfo_t *dinfo), (override));
    MOCK_METHOD(ipp_t *, DoRequest, (http_t *http, ipp_t *request, const char *resource), (override));
    MOCK_METHOD(void, FreeRequest, (ipp_t *response), (override));
};

class ConfirmCertTrustTest : public PrintServiceAbilityTest {
public:
    void SetUp() override
    {
        PrintServiceAbilityTest::SetUp();
        service_ = CreateService();
        ASSERT_NE(service_, nullptr);
        certManager_ = DelayedSingleton<PrintCertManager>::GetInstance();
        ASSERT_NE(certManager_, nullptr);
        originalCertAbility_ = certManager_->certAbility_;
        certManager_->certAbility_ = &certMock_;
        cupsClient_ = DelayedSingleton<PrintCupsClient>::GetInstance();
        ASSERT_NE(cupsClient_, nullptr);
        originalCupsAbility_ = cupsClient_->printAbility_;
        cupsClient_->printAbility_ = &cupsMock_;
    }

    void TearDown() override
    {
        if (certManager_ != nullptr) {
            certManager_->certAbility_ = originalCertAbility_;
        }
        if (cupsClient_ != nullptr) {
            cupsClient_->printAbility_ = originalCupsAbility_;
        }
        PrintDataRepository::GetInstance().DeleteAddedPrinter(TEST_PRINTER_ID, TEST_PRINTER_NAME);
        service_->printerJobMap_.clear();
        PrintServiceAbilityTest::TearDown();
    }

    void AddPrinter(const std::string &uri)
    {
        PrinterInfo info;
        info.SetPrinterId(TEST_PRINTER_ID);
        info.SetUri(uri);
        info.SetPrinterName(TEST_PRINTER_NAME);
        PrintDataRepository::GetInstance().InsertAddedPrinter(TEST_PRINTER_ID, info);
    }

    void ExpectCertSaveSuccess()
    {
        EXPECT_CALL(certMock_, Connect(StrEq("192.168.1.1"), 631, _)).WillOnce(Return(FAKE_HTTP));
        EXPECT_CALL(certMock_, IsEncrypted(FAKE_HTTP)).WillOnce(Return(true));
        EXPECT_CALL(certMock_, CopyCredentials(FAKE_HTTP, _)).WillOnce([](http_t *, cups_array_t **creds) {
            *creds = cupsArrayNew(nullptr, nullptr);
            return 0;
        });
        EXPECT_CALL(certMock_, Close(FAKE_HTTP)).Times(1);
    }

    std::shared_ptr<PrintServiceAbility> service_;
    std::shared_ptr<PrintCertManager> certManager_;
    std::shared_ptr<PrintCupsClient> cupsClient_;
    IPrintCertAbility *originalCertAbility_ = nullptr;
    IPrintAbilityBase *originalCupsAbility_ = nullptr;
    NiceMock<MockCertAbility> certMock_;
    NiceMock<MockCupsAbility> cupsMock_;
};

/**
 * @tc.name: ConfirmCertTrust_NoPermission_001
 * @tc.desc: Missing print permission returns E_PRINT_NO_PERMISSION.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_NoPermission_001, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(false));
    service->SetHelper(helper);
    service->state_ = ServiceRunningState::STATE_RUNNING;

    EXPECT_EQ(service->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_NO_PERMISSION);
}

/**
 * @tc.name: ConfirmCertTrust_PrinterNotFound_002
 * @tc.desc: Unknown printerId returns E_PRINT_INVALID_PRINTER.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_PrinterNotFound_002, TestSize.Level1)
{
    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_INVALID_PRINTER);
}

/**
 * @tc.name: ConfirmCertTrust_UriEmpty_003
 * @tc.desc: Printer exists but URI is empty returns E_PRINT_INVALID_PRINTER.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_UriEmpty_003, TestSize.Level1)
{
    AddPrinter("");
    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_INVALID_PRINTER);
}

/**
 * @tc.name: ConfirmCertTrust_RejectNoJobs_004
 * @tc.desc: trusted=false with no tracked jobs returns E_PRINT_NONE.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_RejectNoJobs_004, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, false), E_PRINT_NONE);
    EXPECT_TRUE(service_->printerJobMap_.find(TEST_PRINTER_ID) == service_->printerJobMap_.end());
}

/**
 * @tc.name: ConfirmCertTrust_RejectEmptyJobs_005
 * @tc.desc: trusted=false with an empty job bucket returns E_PRINT_NONE.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_RejectEmptyJobs_005, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    service_->printerJobMap_[TEST_PRINTER_ID] = {};
    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, false), E_PRINT_NONE);
    EXPECT_TRUE(service_->printerJobMap_[TEST_PRINTER_ID].empty());
}

/**
 * @tc.name: ConfirmCertTrust_RejectCancelJobs_006
 * @tc.desc: trusted=false cancels every tracked job of the printer.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_RejectCancelJobs_006, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    service_->printerJobMap_[TEST_PRINTER_ID]["job1"] = true;
    service_->printerJobMap_[TEST_PRINTER_ID]["job2"] = true;

    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, false), E_PRINT_NONE);
    // CancelPrintJob for unknown jobs keeps the tracking map untouched.
    EXPECT_EQ(service_->printerJobMap_[TEST_PRINTER_ID].size(), 2u);
}

/**
 * @tc.name: ConfirmCertTrust_SaveFail_007
 * @tc.desc: trusted=true but certificate saving fails returns E_PRINT_SERVER_FAILURE.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_SaveFail_007, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    EXPECT_CALL(certMock_, Connect(_, _, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(cupsMock_, DoRequest(_, _, _)).Times(0);

    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: ConfirmCertTrust_ResumeFail_008
 * @tc.desc: Certificate saved but printer resume fails returns E_PRINT_SERVER_FAILURE.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_ResumeFail_008, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    ExpectCertSaveSuccess();
    EXPECT_CALL(certMock_, SaveCredentials(nullptr, NotNull(), StrEq(TEST_PRINTER_NAME_STANDARD)))
        .WillOnce(Return(0));
    cupsClient_->printAbility_ = nullptr;

    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_SERVER_FAILURE);
}

/**
 * @tc.name: ConfirmCertTrust_Success_009
 * @tc.desc: trusted=true saves certificate and resumes printer successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, ConfirmCertTrust_Success_009, TestSize.Level1)
{
    AddPrinter(TEST_PRINTER_URI);
    ExpectCertSaveSuccess();
    EXPECT_CALL(certMock_, SaveCredentials(nullptr, NotNull(), StrEq(TEST_PRINTER_NAME_STANDARD)))
        .WillOnce(Return(0));
    EXPECT_CALL(cupsMock_, DoRequest(_, _, _)).WillOnce([](http_t *, ipp_t *, const char *) {
        // ManualStart() may run a real httpConnect2 which overwrites cupsLastError,
        // so reset the error inside the mock right before ResumePrinter checks it.
        _cupsSetError(IPP_STATUS_OK, nullptr, 0);
        return nullptr;
    });

    EXPECT_EQ(service_->ConfirmCertTrust(TEST_PRINTER_ID, true), E_PRINT_NONE);
}

/**
 * @tc.name: CancelJobsByPrinterId_EmptyMap_010
 * @tc.desc: Cancelling a printer with no jobs is a no-op.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, CancelJobsByPrinterId_EmptyMap_010, TestSize.Level1)
{
    service_->printerJobMap_.clear();
    service_->CancelJobsByPrinterId(TEST_PRINTER_ID);
    EXPECT_TRUE(service_->printerJobMap_.empty());
}

/**
 * @tc.name: CancelJobsByPrinterId_NonEmptyMap_011
 * @tc.desc: Cancelling iterates all tracked jobs without dropping the bucket.
 * @tc.type: FUNC
 */
HWTEST_F(ConfirmCertTrustTest, CancelJobsByPrinterId_NonEmptyMap_011, TestSize.Level1)
{
    service_->printerJobMap_[TEST_PRINTER_ID]["job1"] = true;
    service_->CancelJobsByPrinterId(TEST_PRINTER_ID);
    EXPECT_EQ(service_->printerJobMap_[TEST_PRINTER_ID].size(), 1u);
    EXPECT_TRUE(service_->printerJobMap_[TEST_PRINTER_ID].count("job1") == 1);
}

}  // namespace Print
}  // namespace OHOS
