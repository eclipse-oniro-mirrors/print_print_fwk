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
#include <json/json.h>

#include "remote_printer_manager.h"
#include "i_remote_printer_manager.h"
#include "i_print_feature.h"
#include "print_feature_plugin_manager.h"
#include "print_feature_plugin_loader.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {

class MockRemotePrinterEventHandler : public IRemotePrinterEventHandler {
public:
    int32_t OnAddRemotePrinter(const PrinterInfo &info, const std::string &extensionId) override
    {
        (void)info;
        (void)extensionId;
        return 0;
    }

    bool OnRemoveRemotePrinter(const std::string &uri) override
    {
        (void)uri;
        return true;
    }
};

class FakeFeatureNoRemote : public IPrintFeature {
public:
    void *QueryInterface(PrintFeatureIid /* iid */) override
    {
        return nullptr;
    }
};

class FakeRemotePrinterManager : public IRemotePrinterManager {
public:
    void *QueryInterface(PrintFeatureIid iid) override
    {
        if (iid == PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER) {
            return static_cast<IRemotePrinterManager *>(this);
        }
        return nullptr;
    }

    void SetEventHandler(IRemotePrinterEventHandler *handler) override
    {
        handler_ = handler;
    }

    bool Destroy() override { return true; }
    bool Disconnect() override { return true; }
    void StartPrinterDiscovery() override { startDiscoveryCalled_ = true; }
    bool StopPrinterDiscovery() override { return true; }
    std::shared_ptr<PrinterInfo> GetPrinterInfo(const std::string & /*printerId*/) override { return nullptr; }
    bool UpdatePrinterStatus(const std::string & /*printerId*/, PrinterStatus /*status*/) override { return false; }
    bool OnPrinterListReceived(const Json::Value & /*jsonArray*/) override { return true; }
    bool OnPrinterStatusReceived(const Json::Value & /*jsonArray*/) override { return true; }
    void ClearAllPrinters() override {}

    IRemotePrinterEventHandler *handler_ = nullptr;
    bool startDiscoveryCalled_ = false;
};

class MockRemotePrinterManager : public IRemotePrinterManager {
public:
    MockRemotePrinterManager() = default;
    ~MockRemotePrinterManager() override = default;

    void *QueryInterface(PrintFeatureIid /* iid */) override
    {
        return nullptr;
    }

    void SetEventHandler(IRemotePrinterEventHandler *handler) override
    {
        handler_ = handler;
    }

    bool Destroy() override { return true; }
    bool Disconnect() override
    {
        disconnectCalled_ = true;
        return true;
    }

    void StartPrinterDiscovery() override
    {
        startDiscoveryCalled_ = true;
    }

    bool StopPrinterDiscovery() override
    {
        stopDiscoveryCalled_ = true;
        return true;
    }

    std::shared_ptr<PrinterInfo> GetPrinterInfo(const std::string & /*printerId*/) override
    {
        return nullptr;
    }

    bool UpdatePrinterStatus(const std::string & /*printerId*/, PrinterStatus /*status*/) override
    {
        return false;
    }

    bool OnPrinterListReceived(const Json::Value & /*jsonArray*/) override
    {
        return true;
    }

    bool OnPrinterStatusReceived(const Json::Value & /*jsonArray*/) override
    {
        return true;
    }

    void ClearAllPrinters() override {}

    IRemotePrinterEventHandler *handler_ = nullptr;
    bool disconnectCalled_ = false;
    bool startDiscoveryCalled_ = false;
    bool stopDiscoveryCalled_ = false;
};

} // namespace

class RemotePrinterManagerProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override;
    void TearDown() override;

protected:
    MockRemotePrinterManager mockImpl_;
    MockRemotePrinterEventHandler handler_;
};

void RemotePrinterManagerProxyTest::SetUp()
{
    RemotePrinterManager::GetInstance().impl_ = nullptr;
    RemotePrinterManager::GetInstance().handler_ = nullptr;
}

void RemotePrinterManagerProxyTest::TearDown()
{
    RemotePrinterManager::GetInstance().impl_ = nullptr;
    RemotePrinterManager::GetInstance().handler_ = nullptr;
    PrintFeaturePluginManager::GetInstance().UnloadAll();
}

HWTEST_F(RemotePrinterManagerProxyTest, Singleton_AndHandlerStorage, TestSize.Level1)
{
    auto &instance1 = RemotePrinterManager::GetInstance();
    auto &instance2 = RemotePrinterManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);

    instance1.SetEventHandler(&handler_);
    EXPECT_EQ(instance1.handler_, &handler_);
}

HWTEST_F(RemotePrinterManagerProxyTest, ImplNull_OperationsReturnDefaults, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    EXPECT_NO_FATAL_FAILURE(manager.StartPrinterDiscovery());
    EXPECT_FALSE(mockImpl_.startDiscoveryCalled_);
    EXPECT_TRUE(manager.StopPrinterDiscovery());
    EXPECT_TRUE(manager.Disconnect());
}

HWTEST_F(RemotePrinterManagerProxyTest, ImplNotNull_OperationsForward, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    manager.impl_ = &mockImpl_;

    manager.SetEventHandler(&handler_);
    EXPECT_EQ(mockImpl_.handler_, &handler_);

    manager.StartPrinterDiscovery();
    EXPECT_TRUE(mockImpl_.startDiscoveryCalled_);

    EXPECT_TRUE(manager.StopPrinterDiscovery());
    EXPECT_TRUE(mockImpl_.stopDiscoveryCalled_);

    EXPECT_TRUE(manager.Disconnect());
    EXPECT_TRUE(mockImpl_.disconnectCalled_);
}

HWTEST_F(RemotePrinterManagerProxyTest, EnsureLoaded_PluginFeatureWithoutRemoteInterface_KeepsImplNull, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    manager.impl_ = nullptr;

    auto *fakeFeature = new FakeFeatureNoRemote();
    PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fakeFeature, PrintFeatureDeleter(nullptr));

    manager.SetEventHandler(&handler_);
    manager.StartPrinterDiscovery();
    EXPECT_EQ(manager.impl_, nullptr);
}

HWTEST_F(RemotePrinterManagerProxyTest, EnsureLoaded_PluginFeatureWithRemoteInterface_SetsImplAndForwards,
    TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    manager.impl_ = nullptr;

    auto *fakeRemote = new FakeRemotePrinterManager();
    PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fakeRemote, PrintFeatureDeleter(nullptr));

    manager.SetEventHandler(&handler_);
    manager.StartPrinterDiscovery();
    EXPECT_EQ(manager.impl_, fakeRemote);
    EXPECT_EQ(fakeRemote->handler_, &handler_);
    EXPECT_TRUE(fakeRemote->startDiscoveryCalled_);
}

HWTEST_F(RemotePrinterManagerProxyTest, EnsureLoaded_BaseNull_KeepsImplNull, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    manager.impl_ = nullptr;
    PrintFeaturePluginManager::GetInstance().UnloadAll();

    manager.SetEventHandler(&handler_);
    manager.StartPrinterDiscovery();
    EXPECT_EQ(manager.impl_, nullptr);
}

HWTEST_F(RemotePrinterManagerProxyTest, Operations_WhenImplAlreadyLoaded_SkipEnsureLoaded, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    FakeRemotePrinterManager fakeRemote;
    manager.impl_ = &fakeRemote;

    manager.SetEventHandler(&handler_);
    manager.StartPrinterDiscovery();
    EXPECT_EQ(fakeRemote.handler_, &handler_);
    EXPECT_TRUE(fakeRemote.startDiscoveryCalled_);
}

} // namespace OHOS::Print
