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

#include <gtest/gtest.h>
#include "mock_bundle_mgr.h"
#include "scan_service_ability.h"
#include "scan_constant.h"
#include "system_ability_definition.h"
#include "scan_service_utils.h"
#include "mock_scan_callback_proxy.h"
#include "message_parcel.h"
#include "message_option.h"
#include "iscan_service.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Scan {
class ScanServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    sptr<ScanServiceAbility> scanSa;
};

void ScanServiceStubTest::SetUpTestCase(void)
{}

void ScanServiceStubTest::TearDownTestCase(void)
{}

void ScanServiceStubTest::SetUp(void)
{
    scanSa = ScanServiceAbility::GetInstance();
    EXPECT_TRUE(scanSa != nullptr);
}

/**
 * @tc.name: ScanMdnsServiceTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, VerfifyAppCount_When_CallInitScanOneTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IScanService::GetDescriptor());
    int32_t result = scanSa->OnRemoteRequest(CMD_INIT_SCAN, data, reply, option);
    EXPECT_EQ(result, E_SCAN_NONE);
}

/**
 * @tc.name: ScanMdnsServiceTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, VerfifyAppCount_When_CallEXITScanOneTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IScanService::GetDescriptor());
    int32_t result = scanSa->OnRemoteRequest(CMD_EXIT_SCAN, data, reply, option);
    EXPECT_EQ(result, E_SCAN_NONE);
}

/**
 * @tc.name: ScanMdnsServiceTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, VerfifyAppCount_When_CallInitAndExitBothOneTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IScanService::GetDescriptor());
    int32_t result = scanSa->OnRemoteRequest(CMD_INIT_SCAN, data, reply, option);
    EXPECT_EQ(result, E_SCAN_NONE);

    MessageParcel data2;
    MessageParcel reply2;
    data2.WriteInterfaceToken(IScanService::GetDescriptor());
    result = scanSa->OnRemoteRequest(CMD_EXIT_SCAN, data2, reply2, option);
    EXPECT_EQ(result, E_SCAN_NONE);
}

/**
 * @tc.name: ScanMdnsServiceTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, VerfifyAppCount_When_CallInitFiveTimes, TestSize.Level1)
{
    MessageOption option;
    for (int i = 0; i < 5; i++) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInterfaceToken(IScanService::GetDescriptor());
        int32_t result = scanSa->OnRemoteRequest(CMD_INIT_SCAN, data, reply, option);
        EXPECT_EQ(result, E_SCAN_NONE);
    }
}

/**
 * @tc.name: ScanMdnsServiceTest_0005
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, VerfifyAppCount_When_CallExitFiveTimes, TestSize.Level1)
{
    MessageOption option;
    for (int i = 0; i < 5; i++) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInterfaceToken(IScanService::GetDescriptor());
        int32_t result = scanSa->OnRemoteRequest(CMD_EXIT_SCAN, data, reply, option);
        EXPECT_EQ(result, E_SCAN_NONE);
    }
}
}  // namespace Scan
}  // namespace OHOS
