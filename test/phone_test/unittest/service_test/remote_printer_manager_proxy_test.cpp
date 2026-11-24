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

} // namespace

class RemotePluginPathGuard {
public:
    RemotePluginPathGuard()
    {
        auto &entry = PrintFeaturePluginManager::GetInstance()
            .features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
        originalPath_ = entry.libPath;
        entry.libPath = "/system/lib/libprint_feature_remote_nonexistent_test.z.so";
    }
    ~RemotePluginPathGuard()
    {
        auto &entry = PrintFeaturePluginManager::GetInstance()
            .features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
        entry.libPath = originalPath_;
    }
private:
    std::string originalPath_;
};

class RemotePrinterManagerProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override;
    void TearDown() override;

protected:
    RemotePluginPathGuard pathGuard_;
    MockRemotePrinterEventHandler handler_;
};

void RemotePrinterManagerProxyTest::SetUp()
{
    RemotePrinterManager::GetInstance().handler_ = nullptr;
}

void RemotePrinterManagerProxyTest::TearDown()
{
    RemotePrinterManager::GetInstance().handler_ = nullptr;
    PrintFeaturePluginManager::GetInstance().UnloadAll();
}

HWTEST_F(RemotePrinterManagerProxyTest, Singleton_AndHandlerStorage, TestSize.Level1)
{
    auto &instance = RemotePrinterManager::GetInstance();
    instance.SetEventHandler(&handler_);
    EXPECT_EQ(instance.handler_, &handler_);

    MockRemotePrinterEventHandler handler2;
    instance.SetEventHandler(&handler2);
    EXPECT_EQ(instance.handler_, &handler2);
}

HWTEST_F(RemotePrinterManagerProxyTest, ImplNull_OperationsReturnDefaults, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    // With no remote plugin loaded, the proxy must return safe defaults.
    EXPECT_TRUE(manager.StopPrinterDiscovery());
    EXPECT_TRUE(manager.Disconnect());
}

HWTEST_F(RemotePrinterManagerProxyTest, ImplNotNull_OperationsForward, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();

    auto *fakeRemote = new FakeRemotePrinterManager();
    PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fakeRemote, PrintFeatureDeleter(nullptr));

    manager.SetEventHandler(&handler_);
    EXPECT_EQ(fakeRemote->handler_, &handler_);

    manager.StartPrinterDiscovery();
    EXPECT_TRUE(fakeRemote->startDiscoveryCalled_);

    EXPECT_TRUE(manager.StopPrinterDiscovery());
    EXPECT_TRUE(manager.Disconnect());
}

HWTEST_F(RemotePrinterManagerProxyTest, EnsureLoaded_PluginFeatureWithoutRemoteInterface_NoCrash, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();

    auto *fakeFeature = new FakeFeatureNoRemote();
    PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fakeFeature, PrintFeatureDeleter(nullptr));

    EXPECT_NO_FATAL_FAILURE(manager.SetEventHandler(&handler_));
    EXPECT_NO_FATAL_FAILURE(manager.StartPrinterDiscovery());
    EXPECT_TRUE(manager.StopPrinterDiscovery());
}

HWTEST_F(RemotePrinterManagerProxyTest, EnsureLoaded_BaseNull_KeepsImplNull, TestSize.Level1)
{
    auto &manager = RemotePrinterManager::GetInstance();
    // The fixture guard already points the remote plugin path at a non-existent library.
    // SetEventHandler must still store the handler locally when no plugin is loaded.
    manager.SetEventHandler(&handler_);
    EXPECT_EQ(manager.handler_, &handler_);
}

} // namespace OHOS::Print
