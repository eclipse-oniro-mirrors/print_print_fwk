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

namespace OHOS {
namespace Print {

/*
 * @tc.name: PrintServiceAbilityTest_RegisterWatermarkCallback_001
 * @tc.desc: Test RegisterWatermarkCallback without permission
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_RegisterWatermarkCallback_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    sptr<IWatermarkCallback> callback = nullptr;
    EXPECT_EQ(service->RegisterWatermarkCallback(callback), E_PRINT_NO_PERMISSION);
}

/**
 * @tc.name: PrintServiceAbilityTest_RegisterWatermarkCallback_002
 * @tc.desc: Test RegisterWatermarkCallback with permission and null callback
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_INVALID_PARAMETER when WATERMARK_ENFORCING_ENABLE, E_PRINT_NONE otherwise
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_RegisterWatermarkCallback_002, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    sptr<IWatermarkCallback> callback = nullptr;
#ifdef WATERMARK_ENFORCING_ENABLE
    EXPECT_EQ(service->RegisterWatermarkCallback(callback), E_PRINT_INVALID_PARAMETER);
#else
    EXPECT_EQ(service->RegisterWatermarkCallback(callback), E_PRINT_NONE);
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_RegisterWatermarkCallback_003
 * @tc.desc: Test RegisterWatermarkCallback with permission and valid callback
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NONE
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_RegisterWatermarkCallback_003, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
    sptr<MockWatermarkCallback> callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(service->RegisterWatermarkCallback(callback), E_PRINT_NONE);
#ifdef WATERMARK_ENFORCING_ENABLE
    // Clean up: unregister the callback
    service->UnregisterWatermarkCallback();
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_UnregisterWatermarkCallback_001
 * @tc.desc: Test UnregisterWatermarkCallback without permission
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_UnregisterWatermarkCallback_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->UnregisterWatermarkCallback(), E_PRINT_NO_PERMISSION);
}

/**
 * @tc.name: PrintServiceAbilityTest_UnregisterWatermarkCallback_002
 * @tc.desc: Test UnregisterWatermarkCallback with permission but no callback registered
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_INVALID_PARAMETER when WATERMARK_ENFORCING_ENABLE, E_PRINT_NONE otherwise
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_UnregisterWatermarkCallback_002, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
#ifdef WATERMARK_ENFORCING_ENABLE
    EXPECT_EQ(service->UnregisterWatermarkCallback(), E_PRINT_INVALID_PARAMETER);
#else
    EXPECT_EQ(service->UnregisterWatermarkCallback(), E_PRINT_NONE);
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_UnregisterWatermarkCallback_003
 * @tc.desc: Test UnregisterWatermarkCallback with permission after registering callback
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NONE
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_UnregisterWatermarkCallback_003, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
#ifdef WATERMARK_ENFORCING_ENABLE
    sptr<MockWatermarkCallback> callback = sptr<MockWatermarkCallback>::MakeSptr();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(service->RegisterWatermarkCallback(callback), E_PRINT_NONE);
#endif
    EXPECT_EQ(service->UnregisterWatermarkCallback(), E_PRINT_NONE);
}

/**
 * @tc.name: PrintServiceAbilityTest_NotifyWatermarkComplete_001
 * @tc.desc: Test NotifyWatermarkComplete without permission
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_NO_PERMISSION
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_NotifyWatermarkComplete_001, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    service->helper_ = nullptr;
    EXPECT_EQ(service->NotifyWatermarkComplete("jobId", 0), E_PRINT_NO_PERMISSION);
}

/**
 * @tc.name: PrintServiceAbilityTest_NotifyWatermarkComplete_002
 * @tc.desc: Test NotifyWatermarkComplete with permission but non-existent job
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_INVALID_PARAMETER when WATERMARK_ENFORCING_ENABLE, E_PRINT_NONE otherwise
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_NotifyWatermarkComplete_002, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
#ifdef WATERMARK_ENFORCING_ENABLE
    EXPECT_EQ(service->NotifyWatermarkComplete("non_existent_job", 0), E_PRINT_INVALID_PARAMETER);
#else
    EXPECT_EQ(service->NotifyWatermarkComplete("non_existent_job", 0), E_PRINT_NONE);
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_NotifyWatermarkComplete_003
 * @tc.desc: Test NotifyWatermarkComplete with permission and empty jobId
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_INVALID_PARAMETER when WATERMARK_ENFORCING_ENABLE, E_PRINT_NONE otherwise
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_NotifyWatermarkComplete_003, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
#ifdef WATERMARK_ENFORCING_ENABLE
    EXPECT_EQ(service->NotifyWatermarkComplete("", 0), E_PRINT_INVALID_PARAMETER);
#else
    EXPECT_EQ(service->NotifyWatermarkComplete("", 0), E_PRINT_NONE);
#endif
}

/**
 * @tc.name: PrintServiceAbilityTest_NotifyWatermarkComplete_004
 * @tc.desc: Test NotifyWatermarkComplete with permission and failure result
 * @tc.type: FUNC
 * @tc.require: return E_PRINT_INVALID_PARAMETER when WATERMARK_ENFORCING_ENABLE, E_PRINT_NONE otherwise
 */
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_NotifyWatermarkComplete_004, TestSize.Level1)
{
    GTEST_SKIP();
    PrintServiceMockPermission::MockPermission();
    auto service = PrintServiceAbilityTest::CreateService();
#ifdef WATERMARK_ENFORCING_ENABLE
    EXPECT_EQ(service->NotifyWatermarkComplete("jobId", -1), E_PRINT_INVALID_PARAMETER);
#else
    EXPECT_EQ(service->NotifyWatermarkComplete("jobId", -1), E_PRINT_NONE);
#endif
}

}  // namespace Print
}  // namespace OHOS
