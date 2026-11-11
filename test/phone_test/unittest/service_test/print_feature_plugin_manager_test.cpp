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
#include <climits>
#include <cstring>
#include <unistd.h>

#include "i_print_feature.h"
#include "print_feature_plugin_loader.h"
#include "print_feature_plugin_manager.h"
#include "print_feature_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {

class FakePrintFeature : public IPrintFeature {
public:
    void *QueryInterface(PrintFeatureIid /* iid */) override
    {
        return nullptr;
    }
};

std::string GetExeDir()
{
    char exePath[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len <= 0) {
        return "";
    }
    exePath[len] = '\0';
    std::string path(exePath);
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return "";
    }
    return path.substr(0, pos + 1);
}

std::string GetTestPluginPath()
{
    std::string dir = GetExeDir();
    if (dir.empty() || dir.back() == '/') {
        return dir + "libprint_feature_test.z.so";
    }
    return dir + "/libprint_feature_test.z.so";
}

} // namespace

class FeatureEntryGuard {
public:
    explicit FeatureEntryGuard(PrintFeatureType type)
        : entry_(PrintFeaturePluginManager::GetInstance().features_[type])
    {
        originalPath_ = entry_.libPath;
        originalCreate_ = entry_.createSymbol;
        originalDestroy_ = entry_.destroySymbol;
    }
    ~FeatureEntryGuard()
    {
        entry_.libPath = originalPath_;
        entry_.createSymbol = originalCreate_;
        entry_.destroySymbol = originalDestroy_;
    }
private:
    PrintFeaturePluginManager::FeatureEntry &entry_;
    std::string originalPath_;
    std::string originalCreate_;
    std::string originalDestroy_;
};

class PrintFeaturePluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override {}
    void TearDown(void) override
    {
        PrintFeaturePluginManager::GetInstance().UnloadAll();
    }
};

HWTEST_F(PrintFeaturePluginManagerTest, Singleton_UnloadAll_AndUnknownFeature, TestSize.Level1)
{
    auto &instance1 = PrintFeaturePluginManager::GetInstance();
    auto &instance2 = PrintFeaturePluginManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);

    EXPECT_NO_FATAL_FAILURE(instance1.UnloadAll());
    auto feature = instance1.GetFeature(static_cast<PrintFeatureType>(99));
    EXPECT_EQ(feature, nullptr);
}

#ifdef REMOTE_SERVICE_ENABLE
HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_RemotePrinterManager_LoadSuccess, TestSize.Level1)
{
    auto feature = PrintFeaturePluginManager::GetInstance().GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_NE(feature, nullptr);
}
#endif // REMOTE_SERVICE_ENABLE

#ifdef HAVE_PRINT_FAILURE_AI_NOTIFIER
HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_AiNotifier_LoadSuccess, TestSize.Level1)
{
    auto feature = PrintFeaturePluginManager::GetInstance().GetFeature(PrintFeatureType::AI_NOTIFIER);
    EXPECT_NE(feature, nullptr);
}
#endif // HAVE_PRINT_FAILURE_AI_NOTIFIER

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_RemotePrinterManager_WhenPluginUnavailable_ReturnsNull,
    TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    FeatureEntryGuard guard(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].libPath = "/system/lib/nonexistent_plugin.z.so";
    auto feature = manager.GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(feature, nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_WithExistingImpl_ReturnsSameInstance, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();

    auto *fakeFeature = new FakePrintFeature();
    manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fakeFeature, PrintFeatureDeleter(nullptr));

    auto feature = manager.GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(feature, fakeFeature);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_CreateSymbolMissing_ReturnsNull, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    FeatureEntryGuard guard(PrintFeatureType::REMOTE_PRINTER_MANAGER);

    auto &entry = manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
    entry.libPath = GetTestPluginPath();
    entry.createSymbol = "CreateRemotePrintFeature";
    entry.destroySymbol = "DestroyRemotePrintFeature";
    entry.loader = std::make_unique<PrintFeaturePluginLoader>(
        "remote", entry.libPath, entry.createSymbol, entry.destroySymbol);

    auto feature = manager.GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(feature, nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_CreateReturnsNull_UnloadsAndReturnsNull, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    FeatureEntryGuard guard(PrintFeatureType::REMOTE_PRINTER_MANAGER);

    auto &entry = manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
    entry.libPath = GetTestPluginPath();
    entry.createSymbol = "CreateNullPrintFeature";
    entry.destroySymbol = "DestroyPrintFeature";
    entry.loader = std::make_unique<PrintFeaturePluginLoader>(
        "remote", entry.libPath, entry.createSymbol, entry.destroySymbol);

    auto feature = manager.GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(feature, nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_RemotePrinterManager_LoadTestPlugin_Success, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    FeatureEntryGuard guard(PrintFeatureType::REMOTE_PRINTER_MANAGER);

    auto &entry = manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
    entry.libPath = GetTestPluginPath();
    entry.createSymbol = "CreatePrintFeature";
    entry.destroySymbol = "DestroyPrintFeature";
    entry.loader.reset();
    entry.impl.reset();

    auto feature = manager.GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_NE(feature, nullptr);
    EXPECT_EQ(feature, manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl.get());

    manager.UnloadAll();
    EXPECT_EQ(manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl, nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_AiNotifier_LoadTestPlugin_Success, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    FeatureEntryGuard guard(PrintFeatureType::AI_NOTIFIER);

    auto &entry = manager.features_[PrintFeatureType::AI_NOTIFIER];
    entry.libPath = GetTestPluginPath();
    entry.createSymbol = "CreatePrintFeature";
    entry.destroySymbol = "DestroyPrintFeature";
    entry.loader.reset();
    entry.impl.reset();

    auto feature = manager.GetFeature(PrintFeatureType::AI_NOTIFIER);
    EXPECT_NE(feature, nullptr);

    manager.UnloadAll();
    EXPECT_EQ(manager.features_[PrintFeatureType::AI_NOTIFIER].impl, nullptr);
}

} // namespace OHOS::Print
