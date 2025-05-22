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
#include "scan_utils.h"
#include "mock_scan_callback_proxy.h"

using namespace testing;
using namespace testing::ext;


namespace OHOS {
namespace Scan {
class ScanServiceAbilityTest : public testing::Test {
public:
    ScanServiceAbilityTest() : deathRecipient(nullptr), obj(nullptr), scanSa(nullptr), testNo(0), scannerId(nullptr) {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:

    constexpr int32_t DEFAULT_NUMBER = 0;

    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    sptr<MockBundleMgr> obj;
    sptr<ScanServiceAbility> scanSa;
    int32_t testNo;
    std::string scannerId;
    std::set<ScanErrorCode> allStatus;
};

void ScanServiceAbilityTest::SetUpTestCase(void)
{
    SCAN_HILOGD("ScanServiceAbilityTest SetUpTestCase");
    testNo = 0;
}

void ScanServiceAbilityTest::TearDownTestCase(void)
{
    SCAN_HILOGD("ScanServiceAbilityTest TearDownTestCase");
}

void ScanServiceAbilityTest::SetUp(void)
{
    scanSa = ScanServiceAbility::GetInstance();
    EXPECT_TRUE(scanSa != nullptr);
    EXPECT_TRUE(scannerId != nullptr && scannerId != "")
    allStatus.insert({E_SCAN_NONE, E_SCAN_NO_PERMISSION, E_SCAN_INVALID_PARAMETER,
        E_SCAN_GENERIC_FAILURE, E_SCAN_SERVER_FAILURE, E_SCAN_GOOD, E_SCAN_UNSUPPORTED,
        E_SCAN_CANCELLED, E_SCAN_DEVICE_BUSY, E_SCAN_INVAL, E_SCAN_EOF, E_SCAN_JAMMED,
        E_SCAN_NO_DOCS, E_SCAN_COVER_OPEN, E_SCAN_IO_ERROR, E_SCAN_NO_MEM,
        E_SCAN_ACCESS_DENIED})
    SCAN_HILOGD("ScanServiceAbilityTest : %{public}d", ++testNo);
}

void ScanServiceAbilityTest::TearDown(void) {}

void ScanServiceAbilityTest::SetScannerId(const std::string& scannerId)
{
    EXPECT_TRUE(scannerId != nullptr && scannerId != "")
    this->scannerId = scannerId;
}

/**
 * @tc.name: ScanServiceAbilityTest_0001
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_001_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t scanVersion = DEFAULT_NUMBER;
    int32_t status = E_SCAN_NONE;
    status = InitScan(scanVersion);
    EXPECT_EQ(status, E_SCAN_NONE)
    EXPECT_NE(scanVersion, DEFAULT_NUMBER);
}

/**
 * @tc.name: ScanServiceAbilityTest_0002
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_002_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = ExitScan();
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0003
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_004_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScannerList();
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0004
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_004_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = StopDiscover();
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0005
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_005_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = OpenScanner(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0006
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_006_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = CloseScanner(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0007
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_007_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScanOptionDesc(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}
--
/**
 * @tc.name: ScanServiceAbilityTest_0008
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_008_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScanOptionDesc(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0009
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_009_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = OpScanOptionValue(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0010
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_010_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScanParameters(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0011
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_011_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = StartScan(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0012
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_012_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetSingleFrameFD(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0013
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_013_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = CancelScan(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0014
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_014_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = SetScanIOMode(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0015
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_015_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScanSelectFd(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0016
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_016_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = On(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0017
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_017_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = Off(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0018
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

HWTEST_F(ScanServiceAbilityTest, integer_sub_018_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScannerState(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0019
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_019_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = GetScanProgress(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0020
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_020_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = OnStartScan(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0021
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_021_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    StartScanTask(scannerId);
    status = GetScanProgress(scannerId);
    EXPECT_EQ(status, E_SCAN_NONE)
}

/**
 * @tc.name: ScanServiceAbilityTest_0022
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_022_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    int32_t scanVersion = 0;
    status= scanSa->InitScan(scanVersion);
    EXPECT_EQ(scanSa->appCount_, 0);
}

/**
 * @tc.name: ScanServiceAbilityTest_0023
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_023_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status= scanSa->ExitScan();
    EXPECT_EQ(scanSa->appCount_, 0);
}

/**
 * @tc.name: ScanServiceAbilityTest_0024
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_023_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    scanSa->UnloadSystemAbility();
    EXPECT_EQ(scanSa, nullptr);
}

/**
 * @tc.name: ScanServiceAbilityTest_0025
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_025_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->OnStartScan(scannerId);
    EXPECT_TRUE(ScanErrorCode.count(status))
}

/**
 * @tc.name: ScanServiceAbilityTest_0026
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_026_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    scanSa->StartScanTask(scannerId);
    status = scanSa->GetScanProgress(scannerId);
    EXPECT_TRUE(ScanErrorCode.count(status))
}

/**
 * @tc.name: ScanServiceAbilityTest_0027
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_027_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    scanSa->StartScanTask(scannerId);
    status = scanSa->GetScanProgress(scannerId);
    EXPECT_TRUE(ScanErrorCode.count(status))
}

/**
 * @tc.name: ScanServiceAbilityTest_0028
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanServiceAbilityTest, integer_sub_028_NeedRename, TestSize.Level1) {
    SetUp();
    int32_t status = E_SCAN_NONE;
    status = scanSa->OnStartScan(scannerId);
    EXPECT_TRUE(ScanErrorCode.count(status))
}

}

}
