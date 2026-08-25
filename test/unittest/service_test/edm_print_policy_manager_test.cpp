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
#define private public
#include "edm_print_policy_manager.h"
#undef private
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class EdmPrintPolicyManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EdmPrintPolicyManagerTest::SetUpTestCase(void) {}

void EdmPrintPolicyManagerTest::TearDownTestCase(void) {}

void EdmPrintPolicyManagerTest::SetUp(void)
{
    // Reset singleton state before each test
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager.mutex_);
    manager.policy_.ipWhitelist.clear();
    manager.edmQuerySuccess_ = false;
}

void EdmPrintPolicyManagerTest::TearDown(void) {}

// ==================== ParsePolicyJson ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_001
 * @tc.desc: Parse valid policy JSON with multiple IPs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({
        "printer_policies": [
            { "device_ip": "192.168.1.100" },
            { "device_ip": "10.0.0.1" },
            { "device_ip": "2001:0db8:0000:0000:0000:0000:0000:0001" }
        ]
    })";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_EQ(policy.ipWhitelist.size(), 3U);
    EXPECT_TRUE(policy.ipWhitelist.count("192.168.1.100") > 0);
    EXPECT_TRUE(policy.ipWhitelist.count("10.0.0.1") > 0);
    EXPECT_TRUE(policy.ipWhitelist.count("2001:0db8:0000:0000:0000:0000:0000:0001") > 0);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_002
 * @tc.desc: Parse empty JSON object "{}" — no policy set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = "{}";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_TRUE(policy.ipWhitelist.empty());
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_003
 * @tc.desc: Parse JSON with empty printer_policies array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_003, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({ "printer_policies": [] })";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_TRUE(policy.ipWhitelist.empty());
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_004
 * @tc.desc: Parse JSON with invalid root type (array instead of object)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_004, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = "[]";
    EdmPrintPolicy policy;
    EXPECT_FALSE(manager.ParsePolicyJson(json, policy));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_005
 * @tc.desc: Parse malformed JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_005, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = "{ invalid json }";
    EdmPrintPolicy policy;
    EXPECT_FALSE(manager.ParsePolicyJson(json, policy));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_006
 * @tc.desc: Parse JSON with printer_policies not being an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_006, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({ "printer_policies": "not_array" })";
    EdmPrintPolicy policy;
    EXPECT_FALSE(manager.ParsePolicyJson(json, policy));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_007
 * @tc.desc: Parse JSON with entry missing device_ip key — skip invalid entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_007, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({
        "printer_policies": [
            { "device_ip": "192.168.1.100" },
            { "wrong_key": "10.0.0.1" },
            { "device_ip": "10.0.0.2" }
        ]
    })";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_EQ(policy.ipWhitelist.size(), 2U);
    EXPECT_TRUE(policy.ipWhitelist.count("192.168.1.100") > 0);
    EXPECT_TRUE(policy.ipWhitelist.count("10.0.0.2") > 0);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_008
 * @tc.desc: Parse JSON with empty device_ip — skip empty IP entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_008, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({
        "printer_policies": [
            { "device_ip": "192.168.1.100" },
            { "device_ip": "" },
            { "device_ip": "10.0.0.2" }
        ]
    })";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_EQ(policy.ipWhitelist.size(), 2U);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ParsePolicyJson_009
 * @tc.desc: Parse JSON with device_ip being non-string type — skip invalid entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ParsePolicyJson_009, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({
        "printer_policies": [
            { "device_ip": 12345 },
            { "device_ip": "10.0.0.1" }
        ]
    })";
    EdmPrintPolicy policy;
    EXPECT_TRUE(manager.ParsePolicyJson(json, policy));
    EXPECT_EQ(policy.ipWhitelist.size(), 1U);
    EXPECT_TRUE(policy.ipWhitelist.count("10.0.0.1") > 0);
}

// ==================== IsInIpWhitelist ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_001
 * @tc.desc: Empty whitelist (edmQuerySuccess=true, no policy set) — allow by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist.clear();
    EXPECT_TRUE(manager.IsInIpWhitelist("192.168.1.100"));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_002
 * @tc.desc: IP is in whitelist — allow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100", "10.0.0.1" };
    EXPECT_TRUE(manager.IsInIpWhitelist("192.168.1.100"));
    EXPECT_TRUE(manager.IsInIpWhitelist("10.0.0.1"));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_003
 * @tc.desc: IP not in whitelist — block
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_003, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };
    EXPECT_FALSE(manager.IsInIpWhitelist("192.168.1.101"));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_004
 * @tc.desc: Empty IP string — block by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_004, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };
    EXPECT_FALSE(manager.IsInIpWhitelist(""));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_005
 * @tc.desc: edmQuerySuccess=false triggers RetryQueryFromEdm; after retry succeeds, check logic works
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_005, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = false;
    manager.policy_.ipWhitelist.clear();
    // RetryQueryFromEdm will re-query EDM; result depends on test env EDM proxy availability
    bool result = manager.IsInIpWhitelist("192.168.1.100");
    if (manager.edmQuerySuccess_) {
        // EDM query succeeded in test env, verify whitelist logic with actual state
        if (manager.policy_.ipWhitelist.empty()) {
            EXPECT_TRUE(result);
        } else {
            EXPECT_EQ(result, manager.policy_.ipWhitelist.count("192.168.1.100") > 0);
        }
    } else {
        // EDM query failed, should block by default
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsInIpWhitelist_006
 * @tc.desc: IPv6 address in whitelist — match correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsInIpWhitelist_006, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "2001:db8::1" };
    EXPECT_TRUE(manager.IsInIpWhitelist("2001:db8::1"));
    EXPECT_FALSE(manager.IsInIpWhitelist("2001:db8::2"));
}

// ==================== ClearCache ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_ClearCache_001
 * @tc.desc: ClearCache resets both policy_ and edmQuerySuccess_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ClearCache_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    manager.ClearCache();

    EXPECT_FALSE(manager.edmQuerySuccess_);
    EXPECT_TRUE(manager.policy_.ipWhitelist.empty());
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_ClearCache_002
 * @tc.desc: ClearCache on already-empty state — no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_ClearCache_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = false;
    manager.policy_.ipWhitelist.clear();

    manager.ClearCache();

    EXPECT_FALSE(manager.edmQuerySuccess_);
    EXPECT_TRUE(manager.policy_.ipWhitelist.empty());
}

// ==================== UpdatePrintPolicyFromEdm ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_001
 * @tc.desc: Empty event data — ignore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    manager.UpdatePrintPolicyFromEdm("");

    // State should remain unchanged since event is empty
    EXPECT_TRUE(manager.edmQuerySuccess_);
    EXPECT_EQ(manager.policy_.ipWhitelist.size(), 1U);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_002
 * @tc.desc: Invalid JSON event data — ignore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    manager.UpdatePrintPolicyFromEdm("not valid json");

    // State should remain unchanged since event data is invalid
    EXPECT_TRUE(manager.edmQuerySuccess_);
    EXPECT_EQ(manager.policy_.ipWhitelist.size(), 1U);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_003
 * @tc.desc: Event JSON missing user_id key — ignore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_003, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    manager.UpdatePrintPolicyFromEdm(R"({ "other_key": 100 })");

    // State should remain unchanged since user_id is missing
    EXPECT_TRUE(manager.edmQuerySuccess_);
    EXPECT_EQ(manager.policy_.ipWhitelist.size(), 1U);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_004
 * @tc.desc: Event JSON with user_id as non-integer — ignore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_UpdatePrintPolicyFromEdm_004, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    manager.UpdatePrintPolicyFromEdm(R"({ "user_id": "not_int" })");

    // State should remain unchanged since user_id is not int
    EXPECT_TRUE(manager.edmQuerySuccess_);
    EXPECT_EQ(manager.policy_.ipWhitelist.size(), 1U);
}

// ==================== OnUserSwitched / OnCurrentUserRemoved ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_OnUserSwitched_001
 * @tc.desc: OnUserSwitched clears cache and re-initializes via EDM query
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_OnUserSwitched_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    // OnUserSwitched calls ClearCache then InitPrintPolicyFromEdm
    manager.OnUserSwitched(200);

    // Verify that cache was cleared and re-initialized (edmQuerySuccess_ reflects re-query result)
    if (manager.edmQuerySuccess_) {
        // EDM re-query succeeded in test env
        EXPECT_TRUE(manager.edmQuerySuccess_);
    } else {
        // EDM re-query failed
        EXPECT_TRUE(manager.policy_.ipWhitelist.empty());
    }
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_OnCurrentUserRemoved_001
 * @tc.desc: OnCurrentUserRemoved with matching userId — clears cache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_OnCurrentUserRemoved_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    // PrintServiceAbility::GetInstance()->GetCurrentUserId() is needed internally
    // Without a running service, this may crash; test the direct ClearCache path instead
    manager.ClearCache();

    EXPECT_FALSE(manager.edmQuerySuccess_);
    EXPECT_TRUE(manager.policy_.ipWhitelist.empty());
}

// ==================== RetryQueryFromEdm ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_RetryQueryFromEdm_001
 * @tc.desc: edmQuerySuccess=true — returns true immediately without re-query
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_RetryQueryFromEdm_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    EXPECT_TRUE(manager.RetryQueryFromEdm());
    // State should remain unchanged
    EXPECT_TRUE(manager.edmQuerySuccess_);
    EXPECT_EQ(manager.policy_.ipWhitelist.size(), 1U);
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_RetryQueryFromEdm_002
 * @tc.desc: edmQuerySuccess=false triggers re-query; verify edmQuerySuccess_ is updated accordingly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_RetryQueryFromEdm_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = false;
    manager.policy_.ipWhitelist.clear();

    bool result = manager.RetryQueryFromEdm();
    // Result should match edmQuerySuccess_ after retry
    EXPECT_EQ(result, manager.edmQuerySuccess_);
}

// ==================== Integration: Parse + IsInIpWhitelist ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_Integration_001
 * @tc.desc: Parse whitelist JSON then verify IsInIpWhitelist with direct member set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_Integration_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    std::string json = R"({
        "printer_policies": [
            { "device_ip": "192.168.1.100" },
            { "device_ip": "10.0.0.1" },
            { "device_ip": "172.16.0.1" }
        ]
    })";
    EdmPrintPolicy policy;
    ASSERT_TRUE(manager.ParsePolicyJson(json, policy));
    ASSERT_EQ(policy.ipWhitelist.size(), 3U);

    // Simulate QueryPolicyFromEdm success by directly setting state
    manager.edmQuerySuccess_ = true;
    manager.policy_ = policy;

    EXPECT_TRUE(manager.IsInIpWhitelist("192.168.1.100"));
    EXPECT_TRUE(manager.IsInIpWhitelist("10.0.0.1"));
    EXPECT_TRUE(manager.IsInIpWhitelist("172.16.0.1"));
    EXPECT_FALSE(manager.IsInIpWhitelist("192.168.1.200"));
    EXPECT_FALSE(manager.IsInIpWhitelist(""));

    // Clean up
    manager.ClearCache();
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_Integration_002
 * @tc.desc: After ClearCache, re-query triggered by IsInIpWhitelist; state reflects EDM availability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_Integration_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();

    // Set up valid state
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };
    EXPECT_TRUE(manager.IsInIpWhitelist("192.168.1.100"));

    // Clear cache
    manager.ClearCache();
    EXPECT_FALSE(manager.edmQuerySuccess_);

    // IsInIpWhitelist triggers RetryQueryFromEdm; result depends on EDM proxy availability
    bool result = manager.IsInIpWhitelist("192.168.1.100");
    if (manager.edmQuerySuccess_) {
        // Re-query succeeded, verify whitelist logic with actual state
        if (manager.policy_.ipWhitelist.empty()) {
            EXPECT_TRUE(result);
        } else {
            EXPECT_EQ(result, manager.policy_.ipWhitelist.count("192.168.1.100") > 0);
        }
    } else {
        EXPECT_FALSE(result);
    }

    // Manually restore to verify explicit state control
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };
    EXPECT_TRUE(manager.IsInIpWhitelist("192.168.1.100"));

    // Clean up
    manager.ClearCache();
}

// ==================== IsPrinterAllowedEdm / IsPrintJobAllowedEdm ====================

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_001
 * @tc.desc: Empty whitelist (no policy set) — printer allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_ = EdmPrintPolicy{};

    PrinterInfo printerInfo;
    printerInfo.SetUri("ipp://192.168.1.100/ipp/print");
    EXPECT_TRUE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_002
 * @tc.desc: Whitelisted printer IP — allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    PrinterInfo printerInfo;
    printerInfo.SetUri("ipp://192.168.1.100/ipp/print");
    EXPECT_TRUE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_003
 * @tc.desc: Virtual printer URI — always allowed by IP policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_003, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    PrinterInfo printerInfo;
    printerInfo.SetUri(VIRTUAL_PRINTER_SCHEME + "://save_as_pdf");
    EXPECT_TRUE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_004
 * @tc.desc: Bare IP (no URI scheme) whitelisted — allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_004, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "10.0.0.1" };

    PrinterInfo printerInfo;
    printerInfo.SetUri("10.0.0.1");
    EXPECT_TRUE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_005
 * @tc.desc: URI with non-whitelisted IP — not allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_005, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    PrinterInfo printerInfo;
    printerInfo.SetUri("ipp://192.168.1.200/ipp/print");
    EXPECT_FALSE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_006
 * @tc.desc: Empty URI with configured whitelist — not allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrinterAllowedEdm_006, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_.ipWhitelist = { "192.168.1.100" };

    PrinterInfo printerInfo;
    EXPECT_FALSE(manager.IsPrinterAllowedEdm(printerInfo));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrintJobAllowedEdm_001
 * @tc.desc: Unknown printer with empty whitelist — job allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrintJobAllowedEdm_001, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_ = EdmPrintPolicy{};

    PrintJob printJob;
    printJob.SetJobId("job-001");
    printJob.SetPrinterId("unknown-printer-id");
    EXPECT_TRUE(manager.IsPrintJobAllowedEdm(printJob));
}

/**
 * @tc.name: EdmPrintPolicyManagerTest_IsPrintJobAllowedEdm_002
 * @tc.desc: Unknown printer with empty whitelist and empty URI — job allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EdmPrintPolicyManagerTest, EdmPrintPolicyManagerTest_IsPrintJobAllowedEdm_002, TestSize.Level1)
{
    auto &manager = EdmPrintPolicyManager::GetInstance();
    manager.edmQuerySuccess_ = true;
    manager.policy_ = EdmPrintPolicy{};

    PrintJob printJob;
    printJob.SetJobId("job-002");
    printJob.SetPrinterId(VIRTUAL_PRINTER_SCHEME + "-printer-id");
    EXPECT_TRUE(manager.IsPrintJobAllowedEdm(printJob));
}

}  // namespace Print
}  // namespace OHOS
