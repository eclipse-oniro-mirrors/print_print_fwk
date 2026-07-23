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
#include <gmock/gmock.h>
#define private public
#include "remote_printer_manager.h"
#undef private
#include "mock/mock_bundle_mgr_client.h"
#include "mock/mock_print_bms_helper.h"
#include "printer_info.h"
#include "print_constant.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class RemotePrinterManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemotePrinterManagerTest::SetUpTestCase(void)
{}

void RemotePrinterManagerTest::TearDownTestCase(void)
{}

void RemotePrinterManagerTest::SetUp(void)
{}

void RemotePrinterManagerTest::TearDown(void)
{}

/**
 * @tc.name: StartPrinterDiscovery_001
 * @tc.desc: Branch: isDiscoveryRunning_ == true (already running)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, StartPrinterDiscovery_001, TestSize.Level1)
{
    RemotePrinterManager manager;
    manager.StartPrinterDiscovery();
    manager.StartPrinterDiscovery();
}

/**
 * @tc.name: StartPrinterDiscovery_002
 * @tc.desc: Branch: isDiscoveryRunning_ == false -> start thread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, StartPrinterDiscovery_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    manager.StartPrinterDiscovery();
}

/**
 * @tc.name: StopPrinterDiscovery_001
 * @tc.desc: Branch: stop discovery loop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, StopPrinterDiscovery_001, TestSize.Level1)
{
    RemotePrinterManager manager;
    manager.StartPrinterDiscovery();
    EXPECT_TRUE(manager.StopPrinterDiscovery());
}

/**
 * @tc.name: ConvertStatusToPrinterStatus_001
 * @tc.desc: Branch: status == "online" -> return PRINTER_STATUS_IDLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, ConvertStatusToPrinterStatus_001, TestSize.Level1)
{
    EXPECT_EQ(PRINTER_STATUS_IDLE,
        RemotePrinterManager::ConvertStatusToPrinterStatus("online"));
}

/**
 * @tc.name: ConvertStatusToPrinterStatus_002
 * @tc.desc: Branch: status == "offline" -> return PRINTER_STATUS_UNAVAILABLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, ConvertStatusToPrinterStatus_002, TestSize.Level1)
{
    EXPECT_EQ(PRINTER_STATUS_UNAVAILABLE,
        RemotePrinterManager::ConvertStatusToPrinterStatus("offline"));
}

/**
 * @tc.name: ConvertStatusToPrinterStatus_003
 * @tc.desc: Branch: unknown status -> return PRINTER_STATUS_UNAVAILABLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, ConvertStatusToPrinterStatus_003, TestSize.Level1)
{
    EXPECT_EQ(PRINTER_STATUS_UNAVAILABLE,
        RemotePrinterManager::ConvertStatusToPrinterStatus("unknown"));
}

/**
 * @tc.name: BuildPrinterInfo_001
 * @tc.desc: Branch: !item.isObject() -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_001, TestSize.Level1)
{
    Json::Value item = "invalid";
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo_002
 * @tc.desc: Branch: devId missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_002, TestSize.Level1)
{
    Json::Value item;
    item["devName"] = "Test";
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo
 * @tc.desc: Branch: devName missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_devName, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "Test";
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo
 * @tc.desc: Branch: status missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_status, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "Test";
    item["devName"] = "Test";
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo_003
 * @tc.desc: Branch: devInfo missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_003, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "test_001";
    item["devName"] = "Test Printer";
    item["status"] = "online";
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo_004
 * @tc.desc: Branch: sn missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_004, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "test_001";
    item["devName"] = "Test Printer";
    item["status"] = "online";
    Json::Value devInfo;
    devInfo["prodId"] = "PROD001";
    item["devInfo"] = devInfo;
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo
 * @tc.desc: Branch: prodId missing -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_prodId, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "test_001";
    item["devName"] = "Test Printer";
    item["status"] = "online";
    Json::Value devInfo;
    devInfo["sn"] = "PROD001";
    item["devInfo"] = devInfo;
    PrinterInfo info;
    EXPECT_FALSE(RemotePrinterManager::BuildPrinterInfo(item, info));
}

/**
 * @tc.name: BuildPrinterInfo_005
 * @tc.desc: Branch: valid input -> return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, BuildPrinterInfo_005, TestSize.Level1)
{
    Json::Value item;
    item["devId"] = "test_001";
    item["devName"] = "Test Printer";
    item["status"] = "online";
    Json::Value devInfo;
    devInfo["sn"] = "SN12345";
    devInfo["prodId"] = "PROD001";
    item["devInfo"] = devInfo;
    item["services"] = Json::arrayValue;
    PrinterInfo info;
    EXPECT_TRUE(RemotePrinterManager::BuildPrinterInfo(item, info));
    EXPECT_EQ("test_001", info.GetPrinterId());
    EXPECT_EQ("Test Printer", info.GetPrinterName());
}

/**
 * @tc.name: GetPrinterInfo_001
 * @tc.desc: Branch: get printer info -> return info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, GetPrinterInfo_001, TestSize.Level1)
{
    PrinterInfo info;
    info.SetPrinterId("111");

    RemotePrinterManager manager;
    manager.printerMap_["111"] = std::make_shared<PrinterInfo>(info);

    auto retrieved = manager.GetPrinterInfo("111");
    EXPECT_NE(nullptr, retrieved);
}

/**
 * @tc.name: GetPrinterInfo_002
 * @tc.desc: Branch: get non-existent printer info -> return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, GetPrinterInfo_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    auto retrieved = manager.GetPrinterInfo("non_existent_printer");
    EXPECT_EQ(nullptr, retrieved);
}

/**
 * @tc.name: UpdatePrinterStatus_002
 * @tc.desc: Branch: update non-existent printer status -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, UpdatePrinterStatus_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_FALSE(manager.UpdatePrinterStatus("non_existent_printer", PRINTER_STATUS_IDLE));
}


/**
 * @tc.name: OnPrinterListReceived_002
 * @tc.desc: Branch: JSON not array -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterListReceived_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_TRUE(manager.OnPrinterListReceived("{\"key\": \"value\"}"));
}

/**
 * @tc.name: OnPrinterListReceived_003
 * @tc.desc: Branch: empty array -> return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterListReceived_003, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_TRUE(manager.OnPrinterListReceived("[]"));
}

/**
 * @tc.name: OnPrinterListReceived_004
 * @tc.desc: Branch: valid printer array -> add printers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterListReceived_004, TestSize.Level1)
{
    RemotePrinterManager manager;
    std::string response = "[{\"devId\":\"printer1\",\"devName\":\"Printer1\",\"status\":\"online\","
        "\"devInfo\":{\"sn\":\"SN001\",\"prodId\":\"PROD001\"}}]";
    EXPECT_TRUE(manager.OnPrinterListReceived(response));
}

/**
 * @tc.name: OnPrinterStatusReceived_002
 * @tc.desc: Branch: JSON not array -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterStatusReceived_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_TRUE(manager.OnPrinterStatusReceived("{\"key\": \"value\"}"));
}

/**
 * @tc.name: OnPrinterStatusReceived_003
 * @tc.desc: Branch: empty array -> return true (no printers to update)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterStatusReceived_003, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_TRUE(manager.OnPrinterStatusReceived("[]"));
}

/**
 * @tc.name: OnPrinterStatusReceived_004
 * @tc.desc: Branch: valid status array with devId missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, OnPrinterStatusReceived_004, TestSize.Level1)
{
    RemotePrinterManager manager;
    std::string response = "[{\"status\":\"online\"}]";
    EXPECT_TRUE(manager.OnPrinterStatusReceived(response));
}

/**
 * @tc.name: Disconnect_001
 * @tc.desc: Branch: stop discovery, clear printers, unbind service -> return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, Disconnect_001, TestSize.Level1)
{
    RemotePrinterManager manager;
    EXPECT_TRUE(manager.Disconnect());
}

/**
 * @tc.name: Disconnect_002
 * @tc.desc: Branch: disconnect while discovery running -> stop and return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemotePrinterManagerTest, Disconnect_002, TestSize.Level1)
{
    RemotePrinterManager manager;
    manager.StartPrinterDiscovery();
    EXPECT_TRUE(manager.Disconnect());
}

} // namespace OHOS::Print