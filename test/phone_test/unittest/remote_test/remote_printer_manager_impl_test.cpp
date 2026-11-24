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
#include <chrono>
#include <future>
#include <json/json.h>
#include <thread>

#include "print_json_util.h"
#include "remote_constants.h"
#include "remote_printer_manager_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {

class TestRemotePrinterEventHandler : public IRemotePrinterEventHandler {
public:
    int32_t OnAddRemotePrinter(const PrinterInfo &info, const std::string &extensionId) override
    {
        lastAddedPrinterId_ = info.GetPrinterId();
        lastExtensionId_ = extensionId;
        return 0;
    }

    bool OnRemoveRemotePrinter(const std::string &uri) override
    {
        lastRemovedUri_ = uri;
        return true;
    }

    std::string lastAddedPrinterId_;
    std::string lastExtensionId_;
    std::string lastRemovedUri_;
};

Json::Value BuildValidPrinterItem(const std::string &devId)
{
    Json::Value root;
    root["devId"] = devId;
    root["devName"] = "TestPrinter";
    root["status"] = REMOTE_STATUS_ONLINE;
    root["devInfo"]["sn"] = "sn_" + devId;
    root["devInfo"]["prodId"] = "prod_" + devId;
    return root;
}

} // namespace

class RemotePrinterManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override;
    void TearDown() override;

protected:
    TestRemotePrinterEventHandler handler_;
};

void RemotePrinterManagerImplTest::SetUp()
{
    RemotePrinterManagerImpl::GetInstance().SetEventHandler(&handler_);
}

void RemotePrinterManagerImplTest::TearDown()
{
    RemotePrinterManagerImpl::GetInstance().StopPrinterDiscovery();
    RemotePrinterManagerImpl::GetInstance().ClearAllPrinters();
    RemotePrinterManagerImpl::GetInstance().SetEventHandler(nullptr);
}

HWTEST_F(RemotePrinterManagerImplTest, QueryInterface_CorrectAndWrongIid, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    void *correct = manager.QueryInterface(PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(correct, &manager);
    void *wrong = manager.QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER);
    EXPECT_EQ(wrong, nullptr);
}

HWTEST_F(RemotePrinterManagerImplTest, ConvertStatusToPrinterStatus_AllStatuses, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    EXPECT_EQ(manager.ConvertStatusToPrinterStatus(REMOTE_STATUS_ONLINE), PRINTER_STATUS_IDLE);
    EXPECT_EQ(manager.ConvertStatusToPrinterStatus(REMOTE_STATUS_OFFLINE), PRINTER_STATUS_UNAVAILABLE);
    EXPECT_EQ(manager.ConvertStatusToPrinterStatus("unknown"), PRINTER_STATUS_UNAVAILABLE);
    EXPECT_EQ(manager.ConvertStatusToPrinterStatus(""), PRINTER_STATUS_UNAVAILABLE);
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_ValidInput_ReturnTrue, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_001");

    PrinterInfo info;
    EXPECT_TRUE(manager.BuildPrinterInfo(root, info));
    EXPECT_EQ(info.GetPrinterId(), "dev_001");
    EXPECT_EQ(info.GetPrinterName(), "TestPrinter");
    EXPECT_EQ(info.GetUri(), "sn_dev_001");
    EXPECT_EQ(info.GetPrinterMake(), "prod_dev_001");
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_WithServices_ReturnTrue, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_services");
    root["services"] = "extra";

    PrinterInfo info;
    EXPECT_TRUE(manager.BuildPrinterInfo(root, info));
    Json::Value optionJson;
    ASSERT_TRUE(PrintJsonUtil::Parse(info.GetOption(), optionJson));
    EXPECT_EQ(optionJson["services"].asString(), "\"extra\"");
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_InvalidInput_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root;
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_NotObject_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root(Json::arrayValue);
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingDevId_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root.removeMember("devId");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingDevName_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root.removeMember("devName");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingStatus_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root.removeMember("status");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingDevInfo_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root.removeMember("devInfo");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_DevInfoNotObject_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root["devInfo"] = "not_object";
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingSn_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root["devInfo"].removeMember("sn");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, BuildPrinterInfo_MissingProdId_ReturnFalse, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value root = BuildValidPrinterItem("dev_x");
    root["devInfo"].removeMember("prodId");
    PrinterInfo info;
    EXPECT_FALSE(manager.BuildPrinterInfo(root, info));
}

HWTEST_F(RemotePrinterManagerImplTest, UpdatePrinterStatus_KnownAndUnknownPrinter, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    EXPECT_FALSE(manager.UpdatePrinterStatus("not_exist", PRINTER_STATUS_IDLE));

    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_status"));
    manager.OnPrinterListReceived(array);

    EXPECT_TRUE(manager.UpdatePrinterStatus("dev_status", PRINTER_STATUS_UNAVAILABLE));
    auto info = manager.GetPrinterInfo("dev_status");
    ASSERT_NE(info, nullptr);
    EXPECT_EQ(info->GetPrinterStatus(), static_cast<uint32_t>(PRINTER_STATUS_UNAVAILABLE));
}

HWTEST_F(RemotePrinterManagerImplTest, GetPrinterInfo_EmptyAndKnown, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    EXPECT_EQ(manager.GetPrinterInfo("not_exist"), nullptr);

    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_get"));
    manager.OnPrinterListReceived(array);

    auto info = manager.GetPrinterInfo("dev_get");
    ASSERT_NE(info, nullptr);
    EXPECT_EQ(info->GetPrinterId(), "dev_get");
}

HWTEST_F(RemotePrinterManagerImplTest, StartStopPrinterDiscovery_Lifecycle, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    EXPECT_TRUE(manager.StopPrinterDiscovery());
    manager.StartPrinterDiscovery();
    EXPECT_TRUE(manager.StopPrinterDiscovery());
    manager.StartPrinterDiscovery();
    manager.StartPrinterDiscovery();
    EXPECT_TRUE(manager.StopPrinterDiscovery());
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterListReceived_EmptyAndMixedItems, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value empty(Json::arrayValue);
    EXPECT_TRUE(manager.OnPrinterListReceived(empty));

    Json::Value mixed(Json::arrayValue);
    mixed.append(BuildValidPrinterItem("dev_valid"));
    Json::Value invalid;
    mixed.append(invalid);

    EXPECT_TRUE(manager.OnPrinterListReceived(mixed));
    auto info = manager.GetPrinterInfo("dev_valid");
    ASSERT_NE(info, nullptr);
    EXPECT_EQ(info->GetPrinterId(), "dev_valid");
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterListReceived_RemoveDeprecatedPrinter_ReturnTrue, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value first(Json::arrayValue);
    first.append(BuildValidPrinterItem("dev_old"));
    manager.OnPrinterListReceived(first);

    Json::Value second(Json::arrayValue);
    second.append(BuildValidPrinterItem("dev_new"));
    EXPECT_TRUE(manager.OnPrinterListReceived(second));

    EXPECT_EQ(manager.GetPrinterInfo("dev_old"), nullptr);
    EXPECT_NE(manager.GetPrinterInfo("dev_new"), nullptr);
    EXPECT_EQ(handler_.lastRemovedUri_, "sn_dev_old");
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterStatusReceived_EmptyAndInvalidItems, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value empty(Json::arrayValue);
    EXPECT_TRUE(manager.OnPrinterStatusReceived(empty));

    Json::Value array(Json::arrayValue);
    Json::Value notObject = "string";
    array.append(notObject);

    Json::Value missingDevId;
    missingDevId["status"] = REMOTE_STATUS_ONLINE;
    array.append(missingDevId);

    Json::Value missingStatus;
    missingStatus["devId"] = "dev_x";
    array.append(missingStatus);

    EXPECT_TRUE(manager.OnPrinterStatusReceived(array));
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterStatusReceived_PrinterIdle_NotifyAdded, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value list(Json::arrayValue);
    list.append(BuildValidPrinterItem("dev_idle"));
    manager.OnPrinterListReceived(list);

    Json::Value status(Json::arrayValue);
    Json::Value item;
    item["devId"] = "dev_idle";
    item["status"] = REMOTE_STATUS_ONLINE;
    status.append(item);

    EXPECT_TRUE(manager.OnPrinterStatusReceived(status));
    EXPECT_EQ(handler_.lastAddedPrinterId_, "dev_idle");
    EXPECT_EQ(handler_.lastExtensionId_, REMOTE_EXT_BUNDLE_NAME);
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterStatusReceived_PrinterUnavailable_NotifyRemoved, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value list(Json::arrayValue);
    list.append(BuildValidPrinterItem("dev_remove"));
    manager.OnPrinterListReceived(list);

    Json::Value status(Json::arrayValue);
    Json::Value item;
    item["devId"] = "dev_remove";
    item["status"] = REMOTE_STATUS_OFFLINE;
    status.append(item);

    EXPECT_TRUE(manager.OnPrinterStatusReceived(status));
    EXPECT_EQ(handler_.lastRemovedUri_, "sn_dev_remove");
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterStatusReceived_UnknownStatus_NotifyRemoved, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value list(Json::arrayValue);
    list.append(BuildValidPrinterItem("dev_unknown"));
    manager.OnPrinterListReceived(list);

    Json::Value status(Json::arrayValue);
    Json::Value item;
    item["devId"] = "dev_unknown";
    item["status"] = "other";
    status.append(item);

    EXPECT_TRUE(manager.OnPrinterStatusReceived(status));
    EXPECT_EQ(handler_.lastRemovedUri_, "sn_dev_unknown");
}

HWTEST_F(RemotePrinterManagerImplTest, OnPrinterStatusReceived_PrinterNotFound_Ignored, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value status(Json::arrayValue);
    Json::Value item;
    item["devId"] = "not_exist";
    item["status"] = REMOTE_STATUS_ONLINE;
    status.append(item);

    EXPECT_TRUE(manager.OnPrinterStatusReceived(status));
    EXPECT_TRUE(handler_.lastAddedPrinterId_.empty());
}

HWTEST_F(RemotePrinterManagerImplTest, ClearAllPrinters_RemovesAllAndNotifies, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_clear"));
    manager.OnPrinterListReceived(array);

    manager.ClearAllPrinters();
    EXPECT_EQ(manager.GetPrinterInfo("dev_clear"), nullptr);
    EXPECT_EQ(handler_.lastRemovedUri_, "sn_dev_clear");
}

HWTEST_F(RemotePrinterManagerImplTest, Destroy_StopsDiscoveryAndClearsPrinters, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_destroy"));
    manager.OnPrinterListReceived(array);

    EXPECT_TRUE(manager.Destroy());
    EXPECT_EQ(manager.GetPrinterInfo("dev_destroy"), nullptr);
}

HWTEST_F(RemotePrinterManagerImplTest, Disconnect_StopsDiscoveryAndClearsPrinters, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_disconnect"));
    manager.OnPrinterListReceived(array);

    EXPECT_TRUE(manager.Disconnect());
    EXPECT_EQ(manager.GetPrinterInfo("dev_disconnect"), nullptr);
}

HWTEST_F(RemotePrinterManagerImplTest, NotifyPrinterAdded_WithoutHandler_NoCrash, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    manager.SetEventHandler(nullptr);

    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_no_handler"));
    manager.OnPrinterListReceived(array);

    Json::Value status(Json::arrayValue);
    Json::Value item;
    item["devId"] = "dev_no_handler";
    item["status"] = REMOTE_STATUS_ONLINE;
    status.append(item);
    EXPECT_TRUE(manager.OnPrinterStatusReceived(status));
}

HWTEST_F(RemotePrinterManagerImplTest, CreateRemotePrintFeature_ReturnsInstance, TestSize.Level1)
{
    auto feature = CreateRemotePrintFeature();
    ASSERT_NE(feature, nullptr);
    auto remote = static_cast<IRemotePrinterManager *>(feature->QueryInterface(
        PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER));
    EXPECT_NE(remote, nullptr);
    EXPECT_EQ(feature, &RemotePrinterManagerImpl::GetInstance());
    EXPECT_EQ(static_cast<void *>(remote), static_cast<void *>(feature));
    DestroyRemotePrintFeature(feature);
}

HWTEST_F(RemotePrinterManagerImplTest, DestroyRemotePrintFeature_InvalidInputs_NoCrash, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DestroyRemotePrintFeature(nullptr));

    auto feature = CreateRemotePrintFeature();
    ASSERT_NE(feature, nullptr);
    TestRemotePrinterEventHandler fakeHandler;
    RemotePrinterManagerImpl::GetInstance().SetEventHandler(&fakeHandler);
    EXPECT_NO_FATAL_FAILURE(DestroyRemotePrintFeature(feature));
    EXPECT_EQ(RemotePrinterManagerImpl::GetInstance().eventHandler_, nullptr);

    class DummyFeature : public IPrintFeature {
    public:
        void *QueryInterface(PrintFeatureIid /* iid */) override
        {
            return nullptr;
        }
    };
    DummyFeature dummy;
    EXPECT_NO_FATAL_FAILURE(DestroyRemotePrintFeature(&dummy));
}

HWTEST_F(RemotePrinterManagerImplTest, WaitForActiveCallsIdle_TimeoutThenIdle, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    std::promise<void> acquired;
    std::thread t([&manager, &acquired] {
        RemotePrinterManagerImpl::ActiveCallGuard guard(manager);
        acquired.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
    acquired.get_future().wait();
    EXPECT_FALSE(manager.WaitForActiveCallsIdle(50));
    t.join();
    EXPECT_TRUE(manager.WaitForActiveCallsIdle(1000));
}

HWTEST_F(RemotePrinterManagerImplTest, ClearAllPrinters_WithExternalActiveCall_Completes, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_nested"));
    manager.OnPrinterListReceived(array);

    std::promise<void> acquired;
    std::thread t([&manager, &acquired] {
        RemotePrinterManagerImpl::ActiveCallGuard guard(manager);
        acquired.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    acquired.get_future().wait();
    manager.ClearAllPrinters();
    t.join();
    EXPECT_EQ(manager.GetPrinterInfo("dev_nested"), nullptr);
}

HWTEST_F(RemotePrinterManagerImplTest, Destroy_WaitsForActiveCallAndClears, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_destroy_wait"));
    manager.OnPrinterListReceived(array);

    std::promise<void> acquired;
    std::thread t([&manager, &acquired] {
        RemotePrinterManagerImpl::ActiveCallGuard guard(manager);
        acquired.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    acquired.get_future().wait();
    EXPECT_TRUE(manager.Destroy());
    t.join();
    EXPECT_EQ(manager.GetPrinterInfo("dev_destroy_wait"), nullptr);
    EXPECT_EQ(manager.eventHandler_, nullptr);
    manager.SetEventHandler(&handler_);
}

HWTEST_F(RemotePrinterManagerImplTest, Disconnect_WaitsForActiveCallAndClears, TestSize.Level1)
{
    auto &manager = RemotePrinterManagerImpl::GetInstance();
    Json::Value array(Json::arrayValue);
    array.append(BuildValidPrinterItem("dev_disconnect_wait"));
    manager.OnPrinterListReceived(array);

    std::promise<void> acquired;
    std::thread t([&manager, &acquired] {
        RemotePrinterManagerImpl::ActiveCallGuard guard(manager);
        acquired.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    acquired.get_future().wait();
    EXPECT_TRUE(manager.Disconnect());
    t.join();
    EXPECT_EQ(manager.GetPrinterInfo("dev_disconnect_wait"), nullptr);
}

} // namespace OHOS::Print
