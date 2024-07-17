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
#include "scan_mdns_service.h"

namespace OHOS {
namespace Scan {
class ScanMdnsServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<ScanMdnsService> scanMdnsPtr;
    std::shared_ptr<ScanServiceAbility> scanServicePtr;
};

void ScanMdnsServiceTest::SetUpTestCase(void) {}

void ScanMdnsServiceTest::TearDownTestCase(void) {}

void ScanMdnsServiceTest::SetUp(void)
{
    scanMdnsPtr = ScanMdnsService::GetInstance();
    scanServicePtr = ScanServiceAbility::GetInstance();
    EXPECT_NE(scanMdnsPtr, nullptr);
    EXPECT_NE(scanServicePtr, nullptr);
}

void ScanMdnsServiceTest::TearDown(void) {}

/**
 * @tc.name: ScanMdnsServiceTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanMdnsServiceTest, ScanMdnsServiceTest_0001, TestSize.Level1)
{
    scanMdnsPtr->SetServiceType("_scanner._tcp");
    scanMdnsPtr->onStartDiscoverService();
    EXPECT_NE(scanServicePtr->scanDeviceInfoTCPMap_.size(), 0);
}

/**
 * @tc.name: ScanMdnsServiceTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanMdnsServiceTest, ScanMdnsServiceTest_0002, TestSize.Level1)
{
    scanMdnsPtr->SetServiceType("_scanner._tcp");
    scanMdnsPtr->onStartDiscoverService();
    EXPECT_NE(scanServicePtr->_scanMDnsDiscoveryCallBack, nullptr);
}

/**
 * @tc.name: ScanMdnsServiceTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanMdnsServiceTest, ScanMdnsServiceTest_0003, TestSize.Level1)
{
    scanMdnsPtr->SetServiceType("_scanner._tcp");
    scanMdnsPtr->onStartDiscoverService();
    EXPECT_NE(scanServicePtr->_scanMDnsResolveCallBack, nullptr);
}

} // namespace Scan
} // namespace OHOS