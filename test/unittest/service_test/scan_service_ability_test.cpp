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
#define private public
#include "scan_service_ability.h"
#undef private
#include "scan_constant.h"
#include "system_ability_definition.h"
#include "scan_service_utils.h"
#include "mock_scan_callback_proxy.h"
#include "scan_task.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Scan {
class ScanServiceAbilityTest : public testing::Test {
public:
    ScanServiceAbilityTest() : deathRecipient(nullptr), obj(nullptr), scanSa(nullptr), testNo(0), scannerId("")
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void SetScannerId(const std::string &scannerId);

    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    sptr<Print::MockBundleMgr> obj;
    sptr<ScanServiceAbility> scanSa;
    int32_t testNo;
    std::string scannerId;
    std::set<ScanErrorCode> allStatus;
};

void ScanServiceAbilityTest::SetUpTestCase(void)
{
    SCAN_HILOGD("ScanServiceAbilityTest SetUpTestCase");
}

void ScanServiceAbilityTest::TearDownTestCase(void)
{
    SCAN_HILOGD("ScanServiceAbilityTest TearDownTestCase");
}

void ScanServiceAbilityTest::SetUp(void)
{
    scanSa = ScanServiceAbility::GetInstance();
    EXPECT_TRUE(scanSa != nullptr);
    allStatus.insert({E_SCAN_NONE,
        E_SCAN_NO_PERMISSION,
        E_SCAN_INVALID_PARAMETER,
        E_SCAN_GENERIC_FAILURE,
        E_SCAN_SERVER_FAILURE,
        E_SCAN_UNSUPPORTED,
        E_SCAN_CANCELLED,
        E_SCAN_DEVICE_BUSY,
        E_SCAN_INVAL,
        E_SCAN_EOF,
        E_SCAN_JAMMED,
        E_SCAN_NO_DOCS,
        E_SCAN_COVER_OPEN,
        E_SCAN_IO_ERROR,
        E_SCAN_NO_MEM,
        E_SCAN_ACCESS_DENIED});
    SCAN_HILOGD("ScanServiceAbilityTest : %{public}d", ++testNo);
}

void ScanServiceAbilityTest::SetScannerId(const std::string &scannerId)
{
    EXPECT_TRUE(!scannerId.empty());
    this->scannerId = scannerId;
}

/**
 * @tc.name: ScanServiceAbilityTest_0001
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_001_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->InitScan();
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0002
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_002_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->ExitScan();
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0003
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_004_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->GetScannerList();
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0005
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_005_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->OpenScanner(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0006
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_006_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->CloseScanner(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0007
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_007_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanOptionDescriptor desc;
    status = scanSa->GetScanOptionDesc(scannerId, 0, desc);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0008
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_008_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanOptionDescriptor desc;
    status = scanSa->GetScanOptionDesc(scannerId, 0, desc);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0009
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_009_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanOptionValue value;
    status = scanSa->OpScanOptionValue(scannerId, 0, SCAN_ACTION_GET_VALUE, value);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0010
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_010_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanParameters para;
    status = scanSa->GetScanParameters(scannerId, para);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0011
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_011_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    bool batchMode = false;
    status = scanSa->StartScan(scannerId, batchMode);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0013
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_013_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->CancelScan(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0016
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_016_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->On(scannerId, "scan", nullptr);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0017
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_017_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->Off(scannerId, "scan");
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0019
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_019_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanProgress prog;
    status = scanSa->GetScanProgress(scannerId, prog);
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0020
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_020_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->StartScanOnce(scannerId);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

/**
 * @tc.name: ScanServiceAbilityTest_0021
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_021_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanTask scanTask(scannerId, 100, false);
    scanSa->StartScanTask(scanTask);
    ScanProgress prog;
    status = scanSa->GetScanProgress(scannerId, prog);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

/**
 * @tc.name: ScanServiceAbilityTest_0022
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_022_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->InitScan();
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0023
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_023_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->ExitScan();
    EXPECT_EQ(status, E_SCAN_NONE);
}

/**
 * @tc.name: ScanServiceAbilityTest_0024
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_024_NeedRename, TestSize.Level1)
{
    SetUp();
    scanSa->UnloadSystemAbility();
}

/**
 * @tc.name: ScanServiceAbilityTest_0025
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_025_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->StartScanOnce(scannerId);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

/**
 * @tc.name: ScanServiceAbilityTest_0026
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_026_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanTask scanTask(scannerId, 100, false);
    scanSa->StartScanTask(scanTask);
    ScanProgress prog;
    status = scanSa->GetScanProgress(scannerId, prog);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

/**
 * @tc.name: ScanServiceAbilityTest_0027
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_027_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    ScanTask scanTask(scannerId, 100, false);
    scanSa->StartScanTask(scanTask);
    ScanProgress prog;
    status = scanSa->GetScanProgress(scannerId, prog);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

/**
 * @tc.name: ScanServiceAbilityTest_0028
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_028_NeedRename, TestSize.Level1)
{
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->StartScanOnce(scannerId);
    EXPECT_TRUE(allStatus.count(static_cast<ScanErrorCode>(status)));
}

}  // namespace Scan

}  // namespace OHOS
