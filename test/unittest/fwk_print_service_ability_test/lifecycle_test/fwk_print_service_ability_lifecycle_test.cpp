/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "print_service_ability_test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace Print {

/**
 * @tc.name: PrintServiceAbilityTest_0001
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC ~PrintServiceAbility()
 * @tc.require:
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001_NeedRename, TestSize.Level0)
{
    PrintServiceAbility *print_service = new PrintServiceAbility(PRINT_SERVICE_ID, true);
    if (print_service != nullptr) {
        delete print_service;
        print_service = nullptr;
    }
    PrintServiceAbility *new_print_service = new PrintServiceAbility(PRINT_SERVICE_ID, false);
    if (new_print_service != nullptr) {
        delete new_print_service;
        new_print_service = nullptr;
    }
    // Reset token to ensure Publish fails, making Init return E_PRINT_SERVER_FAILURE
    SetSelfTokenID(0);
    EXPECT_EQ(PrintServiceAbility::GetInstance()->Init(), E_PRINT_SERVER_FAILURE);
    // Second Init also fails: helper_ exists but Publish still fails (g_publishState=false)
    EXPECT_EQ(PrintServiceAbility::GetInstance()->Init(), E_PRINT_SERVER_FAILURE);
    // Restore MockPermission for subsequent tests
    PrintServiceMockPermission::MockPermission();
}

/**
 * @tc.name: PrintServiceAbilityTest_0002
 * @tc.desc: PrintServiceAbility ctor/dtor
 * @tc.type: FUNC ManualStart()
 * @tc.require:
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002_NeedRename, TestSize.Level0)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    int state = static_cast<int>(service->state_.load());
    service->ManualStart();
    EXPECT_EQ(state, 0);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->OnStop();
    EXPECT_EQ(service->state_.load(), ServiceRunningState::STATE_NOT_START);
    service->OnStop();
    EXPECT_EQ(service->state_.load(), ServiceRunningState::STATE_NOT_START);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0092_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    AAFwk::Want want;
    auto ret = service->StartAbility(want);
    EXPECT_EQ(ret, E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0103_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    AAFwk::Want want;
    EXPECT_FALSE(service->StartExtensionAbility(want));
    service->helper_ = std::make_shared<PrintServiceHelper>();
    service->StartExtensionAbility(want);
}

/**
 * @tc.name: QueryQueuedPrintJobById_WhenInvalidJobId_ShouldF
 * @tc.desc: Verify the QueryQueuedPrintJobById failed case.
 * @tc.type: FUNC ExitLowPowerMode
 * @tc.require: AllreadyEnterLowPower
 */
HWTEST_F(PrintServiceAbilityTest, ExitLowPowerMode_WhenAllreadyEnterLowPowerMode_ShouldExit, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->ManualStart();
    service->DelayEnterLowPowerMode();
    EXPECT_TRUE(service->isLowPowerMode_);
    service->ExitLowPowerMode();
    EXPECT_FALSE(service->isLowPowerMode_);
}

/**
 * @tc.name: QueryQueuedPrintJobById_WhenInvalidJobId_ShouldF
 * @tc.desc: Verify the QueryQueuedPrintJobById failed case.
 * @tc.type: FUNC ExitLowPowerMode
 * @tc.require: ExitedLowPowerMode
 */
HWTEST_F(PrintServiceAbilityTest, ExitLowPowerMode_WhenExitedLowPower_ShouldDoNothing, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->ManualStart();
    EXPECT_FALSE(service->isLowPowerMode_);
    service->ExitLowPowerMode();
    EXPECT_FALSE(service->isLowPowerMode_);
}

/**
 * @tc.name: RefreshPrinterStatusOnSwitchUser_NotEnterpriseEnable
 * @tc.desc: Verify the RefreshPrinterStatusOnSwitchUser failed case.
 * @tc.type: ENTERPRISE_ENABLE is true
 * @tc.require: ENTERPRISE_SPACE_PARAM not 2
 */
HWTEST_F(PrintServiceAbilityTest, RefreshPrinterStatusOnSwitchUser_NotEnterpriseEnable, TestSize.Level1)
{
#ifdef ENTERPRISE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, "");
    bool res = service->RefreshPrinterStatusOnSwitchUser();
    EXPECT_FALSE(res);
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
#endif  // ENTERPRISE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, RefreshPrinterStatusOnSwitchUser_EnterpriseEnable_IsEnterprise, TestSize.Level1)
{
#ifdef ENTERPRISE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, IS_ENTERPRISE_ENABLE);
    service->isEnterprise_ = true;
    bool res = service->RefreshPrinterStatusOnSwitchUser();
    EXPECT_TRUE(res);
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
#endif  // ENTERPRISE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, RefreshPrinterStatusOnSwitchUser_EnterpriseEnable_NotEnterprise, TestSize.Level1)
{
#ifdef ENTERPRISE_ENABLE
    auto service = PrintServiceAbilityTest::CreateService();
    std::string parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, IS_ENTERPRISE_ENABLE);
    service->isEnterprise_ = false;
    bool res = service->RefreshPrinterStatusOnSwitchUser();
    EXPECT_TRUE(res);
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
#endif  // ENTERPRISE_ENABLE
}

HWTEST_F(PrintServiceAbilityTest, OHReleaseTest, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->Release(), E_PRINT_NO_PERMISSION);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    service->ManualStart();
    EXPECT_EQ(service->Release(), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, UnloadSystemAbility_WhenJobQueueNotEmpty_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetJobId("job_001");
    service->queuedJobList_["job_001"] = printJob;
    bool result = service->UnloadSystemAbility();
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, UnloadSystemAbility_NoPermision_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->queuedJobList_.clear();
    auto mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(false));
    service->SetHelper(mockHelper);
    bool result = service->UnloadSystemAbility();
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, RegisterSettingDataObserver_WhenPcModeNotSupported_ShouldReturn, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    OHOS::system::SetParameter(PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH, "true");
    service->RegisterSettingDataObserver();
    std::string paramValue = OHOS::system::GetParameter(PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH, "false");
    EXPECT_EQ(paramValue, "true");
    OHOS::system::SetParameter(PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH, "false");
}

HWTEST_F(PrintServiceAbilityTest, IsModeChangeEnd_WhenValueDefaultAndLastDifferent_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string lastChangeModeValue = "running";
    OHOS::system::SetParameter(PARAMETER_CHANGE_MODE_ANIMATION_READY, CHANGE_MODE_DEFAULT_VALUE);
    bool result = service->IsModeChangeEnd(lastChangeModeValue);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, IsModeChangeEnd_WhenValueDefaultAndLastSame_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string lastChangeModeValue = CHANGE_MODE_DEFAULT_VALUE;
    OHOS::system::SetParameter(PARAMETER_CHANGE_MODE_ANIMATION_READY, CHANGE_MODE_DEFAULT_VALUE);
    bool result = service->IsModeChangeEnd(lastChangeModeValue);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, IsModeChangeEnd_WhenValueNotDefault_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string lastChangeModeValue = CHANGE_MODE_DEFAULT_VALUE;
    OHOS::system::SetParameter(PARAMETER_CHANGE_MODE_ANIMATION_READY, "running");
    bool result = service->IsModeChangeEnd(lastChangeModeValue);
    EXPECT_EQ(result, false);
}

}  // namespace Print
}  // namespace OHOS
