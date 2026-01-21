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
#define private public
#define protected public
#include "vendor_wlan_group.h"
#include "print_constant.h"
#include "print_log.h"
#include "mock/mock_print_service_ability.h"

namespace {
const int WAIT_TIME_MS = 100;
const std::string PRINTER_TEST_IP = "192.168.2.222";
const std::string PRINTER_TEST_GLOBAL_ID = "fwk.driver.wlan.group:192.168.2.222";
const std::string PRINTER_TEST_URI = "ipp://192.168.2.222:631";
const std::string PRINTER_TEST_PPDDTAT = "test_ppd_data";
const std::string PRINTER_TEST_UUID = "test_uuid";
}  // namespace
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
class VendorWlanGroupTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void VendorWlanGroupTest::SetUpTestCase(void)
{}

void VendorWlanGroupTest::TearDownTestCase(void)
{}

void VendorWlanGroupTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("VendorWlanGroupTest_%{public}d", ++testNo);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0001_NeedRename, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->parentVendorManager, &vendorManager);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0002_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->OnQueryCapability(printerId, 0), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnQueryCapability(printerId, 0), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0003_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->OnQueryCapabilityByIp(printerId, "ipp"), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnQueryCapabilityByIp(printerId, "ipp"), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0004_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    PrinterInfo info;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_CALL(*mock, AddVendorPrinterToDiscovery(_, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(vendorWlanGroup->OnPrinterDiscovered(VENDOR_WLAN_GROUP, info), EXTENSION_ERROR_NONE);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnPrinterDiscovered(VENDOR_WLAN_GROUP, info), EXTENSION_ERROR_CALLBACK_NULL);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0005_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    PrinterInfo info;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_CALL(*mock, AddIpPrinterToSystemData(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, UpdateVendorPrinterToDiscovery(_, _)).WillRepeatedly(Return(true));
    vendorManager.SetConnectingPrinter(IP_AUTO, PRINTER_TEST_GLOBAL_ID);
    EXPECT_EQ(vendorWlanGroup->OnUpdatePrinterToDiscovery(VENDOR_WLAN_GROUP, info), EXTENSION_ERROR_NONE);
    vendorManager.SetConnectingPrinter(ID_AUTO, PRINTER_TEST_GLOBAL_ID);
    EXPECT_EQ(vendorWlanGroup->OnUpdatePrinterToDiscovery(VENDOR_WLAN_GROUP, info), EXTENSION_ERROR_NONE);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnUpdatePrinterToDiscovery(VENDOR_WLAN_GROUP, info), EXTENSION_ERROR_CALLBACK_NULL);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0006_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->OnPrinterRemoved(VENDOR_WLAN_GROUP, printerId), EXTENSION_ERROR_CALLBACK_FAIL);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnPrinterRemoved(VENDOR_WLAN_GROUP, printerId), EXTENSION_ERROR_CALLBACK_NULL);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0007_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->IsConnectingPrinter(printerId, PRINTER_TEST_URI), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->IsConnectingPrinter(printerId, PRINTER_TEST_URI), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0008_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->IsConnectingPrinter(printerId, PRINTER_TEST_URI), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->IsConnectingPrinter(printerId, PRINTER_TEST_URI), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0009_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    vendorWlanGroup->SetConnectingPrinter(ID_AUTO, printerId);
    EXPECT_EQ(vendorWlanGroup->parentVendorManager->connectingState, STATE_CONNECTING);
    vendorWlanGroup->parentVendorManager = nullptr;
    vendorWlanGroup->SetConnectingPrinter(ID_AUTO, printerId);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0010_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->OnPrinterPpdQueried(VENDOR_WLAN_GROUP, printerId, "", PRINTER_TEST_PPDDTAT), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnPrinterPpdQueried(VENDOR_WLAN_GROUP, printerId, "", PRINTER_TEST_PPDDTAT), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0011_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_IP;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_EQ(vendorWlanGroup->IsGroupDriver(printerId), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->IsGroupDriver(printerId), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0012_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_IP;
    std::string vendorName = VENDOR_BSUNI_DRIVER;
    EXPECT_EQ(vendorWlanGroup->ConvertGroupDriver(printerId, vendorName), false);
    vendorName = VENDOR_WLAN_GROUP;
    EXPECT_EQ(vendorWlanGroup->ConvertGroupDriver(printerId, vendorName), false);
    vendorWlanGroup->printerVendorGroupList_[printerId] = "";
    EXPECT_EQ(vendorWlanGroup->ConvertGroupDriver(printerId, vendorName), false);
    vendorWlanGroup->printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
    EXPECT_EQ(vendorWlanGroup->ConvertGroupDriver(printerId, vendorName), true);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0013_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    auto printerInfo = std::make_shared<PrinterInfo>();
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_CALL(*mock, QueryDiscoveredPrinterInfoById(_)).WillOnce(Return(nullptr)).WillRepeatedly(Return(printerInfo));
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), false);
    printerInfo->SetOption("{\"bsunidriverSupport\": \"true\"}");
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), true);
    printerInfo->SetOption("{\"bsunidriverSupport\": \"false\"}");
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), false);
    printerInfo->SetOption("{\"bsunidriverSupport\": \"need_gs\"}");
    vendorWlanGroup->hasGs = false;
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), false);
    vendorWlanGroup->hasGs = true;
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), true);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->IsBsunidriverSupport(PRINTER_TEST_GLOBAL_ID), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0014_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    vendorWlanGroup->RemoveGroupPrinterFromVendorGroupList(printerId);
    vendorWlanGroup->printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
    vendorWlanGroup->RemoveGroupPrinterFromVendorGroupList(printerId);
    EXPECT_TRUE(vendorWlanGroup->printerVendorGroupList_.empty());
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0015_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    EXPECT_EQ(vendorWlanGroup->QueryVendorDriverByGroupPrinterId(printerId), "");
    vendorWlanGroup->printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
    EXPECT_EQ(vendorWlanGroup->QueryVendorDriverByGroupPrinterId(printerId), VENDOR_BSUNI_DRIVER);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0016_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_IP;
    EXPECT_EQ(vendorWlanGroup->GetGroupPrinterId(printerId), PRINTER_TEST_IP);
    vendorWlanGroup->groupPrinterIdMap_[printerId] = PRINTER_TEST_GLOBAL_ID;
    EXPECT_EQ(vendorWlanGroup->GetGroupPrinterId(printerId), PRINTER_TEST_GLOBAL_ID);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0017_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    vendorManager.SetConnectingPrinter(IP_AUTO, PRINTER_TEST_GLOBAL_ID);
    EXPECT_EQ(vendorWlanGroup->CheckPrinterAddedByIp(printerId), true);
    vendorManager.SetConnectingPrinter(ID_AUTO, PRINTER_TEST_GLOBAL_ID);
    EXPECT_EQ(vendorWlanGroup->CheckPrinterAddedByIp(printerId), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->CheckPrinterAddedByIp(printerId), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0018_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_IP;
    EXPECT_CALL(*mock, RemoveVendorPrinterFromDiscovery(_, _)).WillRepeatedly(Return(true));
    vendorWlanGroup->UpdateGroupPrinter(printerId, PRINTER_TEST_IP);
    EXPECT_EQ(vendorWlanGroup->groupPrinterIdMap_[printerId], PRINTER_TEST_IP);
    vendorWlanGroup->UpdateGroupPrinter(printerId, PRINTER_TEST_IP);
    EXPECT_EQ(vendorWlanGroup->groupPrinterIdMap_[printerId], PRINTER_TEST_IP);
    vendorWlanGroup->UpdateGroupPrinter(printerId, PRINTER_TEST_GLOBAL_ID);
    EXPECT_EQ(vendorWlanGroup->groupPrinterIdMap_[printerId], PRINTER_TEST_GLOBAL_ID);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0019_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_IP;
    EXPECT_EQ(vendorWlanGroup->HasGroupPrinter(printerId), false);
    vendorWlanGroup->UpdateGroupPrinter(printerId, PRINTER_TEST_IP);
    EXPECT_EQ(vendorWlanGroup->HasGroupPrinter(printerId), true);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0020_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = PRINTER_TEST_IP;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_CALL(*mock, RemoveVendorPrinterFromDiscovery(_, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(vendorWlanGroup->ConvertPrinterInfoId(info).GetPrinterId(), PRINTER_TEST_IP);
    info.SetPrinterUuid(PRINTER_TEST_UUID);
    EXPECT_EQ(vendorWlanGroup->ConvertPrinterInfoId(info).GetPrinterId(), PRINTER_TEST_UUID);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0021_NeedRename, TestSize.Level2)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    PrinterInfo info;
    EXPECT_EQ(vendorWlanGroup->ExtractPrinterIdByPrinterInfo(info), "");
    info.SetUri("test_uri");
    EXPECT_EQ(vendorWlanGroup->ExtractPrinterIdByPrinterInfo(info), "");
    info.SetUri("test_uri://");
    EXPECT_EQ(vendorWlanGroup->ExtractPrinterIdByPrinterInfo(info), "");
    info.SetUri("test_uri://");
    EXPECT_EQ(vendorWlanGroup->ExtractPrinterIdByPrinterInfo(info), "");
    info.SetUri(PRINTER_TEST_URI);
    EXPECT_EQ(vendorWlanGroup->ExtractPrinterIdByPrinterInfo(info), PRINTER_TEST_IP);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0022_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _))
        .WillOnce(Return(E_PRINT_SERVER_FAILURE))
        .WillRepeatedly(Return(E_PRINT_NONE));
    EXPECT_EQ(vendorWlanGroup->MonitorPrinterStatus(printerId, true), false);
    EXPECT_EQ(vendorWlanGroup->MonitorPrinterStatus(printerId, true), false);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->MonitorPrinterStatus(printerId, true), false);
}

HWTEST_F(VendorWlanGroupTest, VendorWlanGroupTest_0023_NeedRename, TestSize.Level2)
{
    std::string printerId = PRINTER_TEST_GLOBAL_ID;
    PrinterVendorStatus state;
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_CALL(*mock, OnVendorStatusUpdate(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(vendorWlanGroup->OnPrinterStatusChanged(VENDOR_WLAN_GROUP, printerId, state), true);
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_EQ(vendorWlanGroup->OnPrinterStatusChanged(VENDOR_WLAN_GROUP, printerId, state), false);
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnEmpty_WhenUriNotContainScheme, TestSize.Level1)
{
    std::string uri = "aaa";
    EXPECT_TRUE(PrintUtils::ExtractHostFromUri(uri).empty());
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnEmpty_WhenUriNotContainHost, TestSize.Level1)
{
    std::string uri = "aaa://";
    EXPECT_TRUE(PrintUtils::ExtractHostFromUri(uri).empty());
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriContainScheme, TestSize.Level1)
{
    std::string uri = "aaa://b";
    std::string expected = "b";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriContainPort, TestSize.Level1)
{
    std::string uri = "aaa://b:80";
    std::string expected = "b";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriContainPath, TestSize.Level1)
{
    std::string uri = "aaa://b/path";
    std::string expected = "b";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriContainQuery, TestSize.Level1)
{
    std::string uri = "aaa://b?query";
    std::string expected = "b";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriContainFragment, TestSize.Level1)
{
    std::string uri = "aaa://example.cc#fragment";
    std::string expected = "example.cc";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, ExtractHostFromUri_ShouldReturnHost_WhenUriIsIPv6, TestSize.Level1)
{
    std::string uri = "aaa://[ipv6:addr]#fragment";
    std::string expected = "ipv6:addr";
    EXPECT_EQ(expected, PrintUtils::ExtractHostFromUri(uri));
}

HWTEST_F(VendorWlanGroupTest, MonitorStatusByBsuniDriver_ShouldReturnFalse_WhenVendorManagerIsNull, TestSize.Level1)
{
    VendorWlanGroup group(nullptr);
    std::string printerId = "testId";
    EXPECT_FALSE(group.MonitorStatusByBsuniDriver(printerId, true));
}

HWTEST_F(VendorWlanGroupTest, MonitorStatusByBsuniDriver_ShouldReturnFalse_WhenGetPrinterInfoFailed, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = "testId";
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _)).WillOnce(Return(E_PRINT_GENERIC_FAILURE));
    EXPECT_FALSE(vendorWlanGroup->MonitorStatusByBsuniDriver(printerId, true));
}

HWTEST_F(VendorWlanGroupTest, MonitorStatusByBsuniDriver_ShouldReturnFalse_WhenGetPrinterIpFailed, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = "testId";
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _)).WillOnce(Return(E_PRINT_NONE));
    EXPECT_FALSE(vendorWlanGroup->MonitorStatusByBsuniDriver(printerId, true));
}

HWTEST_F(VendorWlanGroupTest, MonitorStatusByBsuniDriver_ShouldReturnFalse_WhenBsuniDriverIsNull, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = "testId";
    PrinterInfo info;
    info.SetUri(PRINTER_TEST_URI);
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _)).WillOnce(DoAll(SetArgReferee<1>(info), Return(E_PRINT_NONE)));
    EXPECT_FALSE(vendorWlanGroup->MonitorStatusByBsuniDriver(printerId, true));
}

HWTEST_F(VendorWlanGroupTest, MonitorStatusByBsuniDriver_ShouldReturnFalse_WhenOtherInMonitor, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    std::string printerId = "testId";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetUri(PRINTER_TEST_URI);
    std::vector<std::string> printers;
    printers.push_back("fwk.test.group:" + PRINTER_TEST_IP);
    printers.push_back(printerId);
    printers.push_back("fwk.driver.wlan.group:" + PRINTER_TEST_IP);
    EXPECT_CALL(*mock, QueryPrinterInfoByPrinterId(_, _)).WillOnce(DoAll(SetArgReferee<1>(info), Return(E_PRINT_NONE)));
    EXPECT_CALL(*mock, QueryAddedPrintersByIp(_)).WillOnce(Return(printers));
    EXPECT_FALSE(vendorWlanGroup->MonitorStatusByBsuniDriver(printerId, false));
}

HWTEST_F(VendorWlanGroupTest, ConnectPrinterByIpAndPpdTest, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIpAndPpd("192.168.1.1", "ipp", DEFAULT_PPD_NAME));
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIpAndPpd("192.168.1.1", "ipp", "custom.ppd"));
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIpAndPpd("192.168.1.1", "ipp", DEFAULT_PPD_NAME));
}

HWTEST_F(VendorWlanGroupTest, QueryPrinterSetTest, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    ConnectMethod method = IP_AUTO;
    std::string testIp = "192.168.1.1";
    std::string uri = "ipp://" +testIp + ":631/ipp/print";
    vendorWlanGroup->SetQueryPrinter(method, testIp);
    EXPECT_TRUE(vendorWlanGroup->IsQueryingPrinter(testIp, uri));
    method = ID_AUTO;
    vendorWlanGroup->SetQueryPrinter(method, testIp);
    EXPECT_TRUE(vendorWlanGroup->IsQueryingPrinter(testIp, uri));
    vendorWlanGroup->parentVendorManager = nullptr;
    vendorWlanGroup->SetQueryPrinter(method, testIp);
    EXPECT_FALSE(vendorWlanGroup->IsQueryingPrinter(testIp, uri));
}

HWTEST_F(VendorWlanGroupTest, ConnectPrinterByIdAndPpdTest, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    std::string printerId = "testId";
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIdAndPpd(printerId, VENDOR_BSUNI_DRIVER));
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIdAndPpd(printerId, DEFAULT_PPD_NAME));
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIdAndPpd(printerId, "auto"));
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIdAndPpd(printerId, "test.ppd"));
    vendorWlanGroup->parentVendorManager = nullptr;
    EXPECT_FALSE(vendorWlanGroup->ConnectPrinterByIdAndPpd(printerId, DEFAULT_PPD_NAME));
}

HWTEST_F(VendorWlanGroupTest, ConnectByPpdDriver_PrinterInfo_Empty, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);

    EXPECT_CALL(*mock, QueryDiscoveredPrinterInfoById(_))
        .WillOnce(Return(nullptr));

    std::string id = "test";
    EXPECT_FALSE(vendorWlanGroup->ConnectByPpdDriver(id));
}

HWTEST_F(VendorWlanGroupTest, ConnectByPpdDriver_Connect_Failed, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);

    auto printerInfo = std::make_shared<PrinterInfo>();

    EXPECT_CALL(*mock, QueryDiscoveredPrinterInfoById(_))
        .WillOnce(Return(printerInfo));

    std::string id = "test";
    EXPECT_FALSE(vendorWlanGroup->ConnectByPpdDriver(id));
}

HWTEST_F(VendorWlanGroupTest, printerVendorGroupListMutexCheck, TestSize.Level1)
{
    sptr<MockPrintServiceAbility> mock = new MockPrintServiceAbility();
    VendorManager vendorManager;
    EXPECT_TRUE(vendorManager.Init(mock, false));
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(&vendorManager);

    const int threadCount = 10;
    const int iterations = 1000;

    std::vector<std::string> printerIds = {"PRINTER_001", "PRINTER_002", "PRINTER_003"};
    std::vector<std::string> vendors = {"VENDOR_A", "VENDOR_B", "VENDOR_C"};

    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&vendorWlanGroup, &printerIds, &vendors, i, iterations]() {
            for (int j = 0; j < iterations; ++j) {
                std::string printerId = printerIds[i % 3];
                std::string vendor = vendors[j % 3];
                switch (rand() % 5) {
                    case 0:
                        vendorWlanGroup->SetGroupPrinterFromVendorGroupList(printerId, vendor);
                        break;
                    case 1:
                        vendorWlanGroup->RemoveGroupPrinterFromVendorGroupList(printerId);
                        break;
                    case 2:
                        vendorWlanGroup->QueryVendorDriverByGroupPrinterId(printerId);
                        break;
                    case 3:
                        vendorWlanGroup->ConvertGroupDriver(printerId, vendor);
                        break;
                    case 4:
                        vendorWlanGroup->IsGroupDriver(printerId);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
}
}  // namespace Print
}  // namespace OHOS