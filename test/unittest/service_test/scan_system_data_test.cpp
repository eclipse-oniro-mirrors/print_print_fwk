/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <memory>
#include <string>
#define private public
#include "scan_system_data.h"
#undef private
#include "scanner_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Scan {

class ScanSystemDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ScanSystemDataTest::SetUpTestCase(void) {}

void ScanSystemDataTest::TearDownTestCase(void) {}

void ScanSystemDataTest::SetUp(void)
{
    static int32_t testNo = 0;
    SCAN_HILOGI("ScanSystemDataTest_%{public}d", ++testNo);
}

void ScanSystemDataTest::TearDown(void) {}

/**
 * @tc.name: ScanSystemDataTest_UpdateScannerInfoByUniqueId_0001
 * @tc.desc: UpdateScannerInfoByUniqueId returns false (not crash) when map value is null.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanSystemDataTest, ScanSystemDataTest_UpdateScannerInfoByUniqueId_0001, TestSize.Level1)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    const std::string uniqueId = "null_entry_test";
    scanData.addedScannerMap_[uniqueId] = nullptr;
    ScanDeviceInfo scannerInfo;
    scannerInfo.uniqueId = "dummy";
    bool ret = scanData.UpdateScannerInfoByUniqueId(uniqueId, scannerInfo);
    EXPECT_FALSE(ret);
    scanData.addedScannerMap_.erase(uniqueId);
}

/**
 * @tc.name: ScanSystemDataTest_UpdateScannerInfoByUniqueId_0002
 * @tc.desc: UpdateScannerInfoByUniqueId returns true when entry exists and is non-null.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanSystemDataTest, ScanSystemDataTest_UpdateScannerInfoByUniqueId_0002, TestSize.Level1)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    const std::string uniqueId = "valid_entry_test";
    scanData.addedScannerMap_[uniqueId] = std::make_shared<ScanDeviceInfo>();
    ScanDeviceInfo scannerInfo;
    scannerInfo.uniqueId = "updated";
    bool ret = scanData.UpdateScannerInfoByUniqueId(uniqueId, scannerInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(scanData.addedScannerMap_[uniqueId]->uniqueId, "updated");
    scanData.addedScannerMap_.erase(uniqueId);
}

/**
 * @tc.name: ScanSystemDataTest_UpdateScannerInfoByUniqueId_0003
 * @tc.desc: UpdateScannerInfoByUniqueId returns false when uniqueId not in map.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ScanSystemDataTest, ScanSystemDataTest_UpdateScannerInfoByUniqueId_0003, TestSize.Level1)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    ScanDeviceInfo scannerInfo;
    bool ret = scanData.UpdateScannerInfoByUniqueId("not_exist_unique_id", scannerInfo);
    EXPECT_FALSE(ret);
}
}  // namespace Scan
}  // namespace OHOS
