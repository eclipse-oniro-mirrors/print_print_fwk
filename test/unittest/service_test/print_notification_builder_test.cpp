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
#include <string>
#include "notification_normal_content.h"
#include "notification_content.h"
#include "notification_request.h"
#define private public
#include "print_notification_builder.h"
#undef private
#include "print_log.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintNotificationBuilderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintNotificationBuilderTest::SetUpTestCase(void)
{}

void PrintNotificationBuilderTest::TearDownTestCase(void)
{}

void PrintNotificationBuilderTest::SetUp(void)
{}

void PrintNotificationBuilderTest::TearDown(void)
{}

class SubStateToResourceKeyTest : public testing::TestWithParam<std::pair<uint32_t, std::string>> {};

HWTEST_P(SubStateToResourceKeyTest, SubStateToResourceKey_ReturnCorrectKey, TestSize.Level1)
{
    auto [subState, expectedKey] = GetParam();
    std::string result = PrintNotificationBuilder::SubStateToResourceKey(subState);
    EXPECT_EQ(result, expectedKey);
}

INSTANTIATE_TEST_SUITE_P(SubStateToResourceKeyTestCases, SubStateToResourceKeyTest,
    testing::Values(
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_DOOR_OPEN, "printer_door_open"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_PAPER, "printer_out_of_paper"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_INK, "printer_out_of_ink"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_TONER, "printer_out_of_toner"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_JAMMED, "printer_jammed"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_OFFLINE, "printer_offline"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_BUSY, "printer_busy"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_LOW_ON_INK, "printer_low_on_ink"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_LOW_ON_TONER, "printer_low_on_toner"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK, "printer_really_low_on_ink"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_BAD_CERTIFICATE, "printer_bad_certificate"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_DRIVER_EXCEPTION, "printer_driver_exception"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_ACCOUNT_ERROR, "printer_account_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR, "printer_permission_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR,
            "printer_color_permission_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_NETWORK_ERROR, "printer_network_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR, "printer_server_connection_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_LARGE_FILE_ERROR, "printer_large_file_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_FILE_PARSING_ERROR, "printer_file_parsing_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION, "printer_slow_file_conversion"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_DRIVER_MISSING, "printer_driver_missing"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_INTERRUPT, "printer_interrupt"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_AUTHENTICATION, "printer_authentication"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_BANNED, "printer_banned"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_SMB_PRINTER, "printer_smb_error"),
        std::make_pair(PrintJobSubState::PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE, "printer_unavailable"),
        std::make_pair(999, "printer_check"),
        std::make_pair(0, "printer_check")
    ));

HWTEST_F(PrintNotificationBuilderTest, BuildRequest_ValidInput_ReturnRequest, TestSize.Level1)
{
    int32_t notiId = 1;
    auto normalContent = std::make_shared<Notification::NotificationNormalContent>();
    auto content = std::make_shared<Notification::NotificationContent>(normalContent);
    
    Notification::NotificationRequest request = PrintNotificationBuilder::BuildRequest(notiId, content);
    
    EXPECT_EQ(request.GetNotificationId(), notiId);
    EXPECT_EQ(request.GetSlotType(), Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
}

HWTEST_F(PrintNotificationBuilderTest, CreateAiButton_ValidInput_ReturnButton, TestSize.Level1)
{
    int32_t notiId = 1;
    std::string askAiKey = "test_key";
    
    std::shared_ptr<Notification::NotificationActionButton> button =
        PrintNotificationBuilder::CreateAiButton(notiId, askAiKey);
    
    EXPECT_EQ(button, nullptr);
}

HWTEST_F(PrintNotificationBuilderTest, CreateNotification_ValidInput_ReturnSuccess, TestSize.Level1)
{
    uint32_t subState = PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_PAPER;
    std::string printerName = "TestPrinter";
    
    int32_t result = PrintNotificationBuilder::CreateNotification(subState, printerName);
    
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

}  // namespace Print
}  // namespace OHOS