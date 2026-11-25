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

#include "message_option.h"
#include "message_parcel.h"
#include "scan_cert_dialog_callback.h"
#include "scan_constant.h"
#include "string_ex.h"

using namespace testing::ext;

namespace OHOS {
namespace Scan {

class ScanCertDialogCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanCertDialogCallbackTest::SetUpTestCase(void) {}
void ScanCertDialogCallbackTest::TearDownTestCase(void) {}

/**
 * @tc.name: ScanCertDialogCallbackTest_OnDecision_InvokesHandler_0001
 * @tc.desc: Verify OnDecision forwards all arguments to the registered handler.
 */
HWTEST_F(ScanCertDialogCallbackTest, ScanCertDialogCallbackTest_OnDecision_InvokesHandler_0001, TestSize.Level2)
{
    std::string sessionId;
    std::string scannerId;
    std::string fingerprint;
    int32_t decision = -1;
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [&sessionId, &scannerId, &fingerprint, &decision](const std::string &session,
            const std::string &scanner, const std::string &fp, int32_t value) {
            sessionId = session;
            scannerId = scanner;
            fingerprint = fp;
            decision = value;
        });
    ASSERT_NE(nullptr, callback);

    callback->OnDecision("session-1", "scanner-1", "fp-1", static_cast<int32_t>(ScanCertDecision::TRUST));
    EXPECT_EQ("session-1", sessionId);
    EXPECT_EQ("scanner-1", scannerId);
    EXPECT_EQ("fp-1", fingerprint);
    EXPECT_EQ(static_cast<int32_t>(ScanCertDecision::TRUST), decision);
}

/**
 * @tc.name: ScanCertDialogCallbackTest_OnRemoteRequest_DescriptorMismatch_0002
 * @tc.desc: Verify a mismatched interface token is rejected.
 */
HWTEST_F(ScanCertDialogCallbackTest, ScanCertDialogCallbackTest_OnRemoteRequest_DescriptorMismatch_0002,
    TestSize.Level2)
{
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [](const std::string &, const std::string &, const std::string &, int32_t) {});
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(u"wrong.descriptor"));
    EXPECT_EQ(E_SCAN_RPC_FAILURE, callback->OnRemoteRequest(
        static_cast<uint32_t>(ScanCertDecisionCode::ON_DECISION), data, reply, option));
}

/**
 * @tc.name: ScanCertDialogCallbackTest_OnRemoteRequest_UnknownCode_0003
 * @tc.desc: Verify an unknown transaction code is rejected.
 */
HWTEST_F(ScanCertDialogCallbackTest, ScanCertDialogCallbackTest_OnRemoteRequest_UnknownCode_0003, TestSize.Level2)
{
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [](const std::string &, const std::string &, const std::string &, int32_t) {});
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(IScanCertDialogCallback::GetDescriptor()));
    EXPECT_EQ(E_SCAN_RPC_FAILURE, callback->OnRemoteRequest(9999, data, reply, option));
}

/**
 * @tc.name: ScanCertDialogCallbackTest_OnRemoteRequest_ValidDecision_0004
 * @tc.desc: Verify a well-formed decision request dispatches the handler and returns E_SCAN_NONE.
 */
HWTEST_F(ScanCertDialogCallbackTest, ScanCertDialogCallbackTest_OnRemoteRequest_ValidDecision_0004, TestSize.Level2)
{
    std::string sessionId;
    std::string scannerId;
    std::string fingerprint;
    int32_t decision = -1;
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [&sessionId, &scannerId, &fingerprint, &decision](const std::string &session,
            const std::string &scanner, const std::string &fp, int32_t value) {
            sessionId = session;
            scannerId = scanner;
            fingerprint = fp;
            decision = value;
        });
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(IScanCertDialogCallback::GetDescriptor()));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16("session-1")));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16("scanner-1")));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16("fp-1")));
    ASSERT_TRUE(data.WriteInt32(static_cast<int32_t>(ScanCertDecision::REJECT)));

    EXPECT_EQ(E_SCAN_NONE, callback->OnRemoteRequest(
        static_cast<uint32_t>(ScanCertDecisionCode::ON_DECISION), data, reply, option));
    EXPECT_EQ("session-1", sessionId);
    EXPECT_EQ("scanner-1", scannerId);
    EXPECT_EQ("fp-1", fingerprint);
    EXPECT_EQ(static_cast<int32_t>(ScanCertDecision::REJECT), decision);
}

/**
 * @tc.name: ScanCertDialogCallbackTest_OnRemoteRequest_MissingFields_0005
 * @tc.desc: Verify a truncated payload is rejected without invoking the handler.
 */
HWTEST_F(ScanCertDialogCallbackTest, ScanCertDialogCallbackTest_OnRemoteRequest_MissingFields_0005,
    TestSize.Level2)
{
    bool invoked = false;
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [&invoked](const std::string &, const std::string &, const std::string &, int32_t) {
            invoked = true;
        });
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(IScanCertDialogCallback::GetDescriptor()));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16("session-1")));

    EXPECT_EQ(E_SCAN_RPC_FAILURE, callback->OnRemoteRequest(
        static_cast<uint32_t>(ScanCertDecisionCode::ON_DECISION), data, reply, option));
    EXPECT_FALSE(invoked);
}

}  // namespace Scan
}  // namespace OHOS
