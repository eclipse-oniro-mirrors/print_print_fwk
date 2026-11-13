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
#include <climits>
#include <future>
#include <thread>
#include <unistd.h>

#include "print_failure_ai_notifier_impl.h"
#include "print_feature_plugin_manager.h"
#include "print_feature_type.h"
#include "remote_printer_manager_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {

bool FileExists(const std::string &path)
{
    return access(path.c_str(), F_OK) == 0;
}

std::string GetRemotePluginPath()
{
    return PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].libPath;
}

std::string GetAiPluginPath()
{
    return PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::AI_NOTIFIER].libPath;
}

bool IsRemotePluginAvailable()
{
    return FileExists(GetRemotePluginPath());
}

bool IsAiPluginAvailable()
{
    return FileExists(GetAiPluginPath());
}

class UnloadingStateGuard {
public:
    explicit UnloadingStateGuard(PrintFeaturePluginManager &manager)
        : manager_(manager)
    {
        manager_.unloading_ = true;
    }
    ~UnloadingStateGuard()
    {
        manager_.unloading_ = false;
    }
private:
    PrintFeaturePluginManager &manager_;
};

} // namespace

class PrintFeaturePluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void)
    {
        PrintFeaturePluginManager::GetInstance().UnloadAll();
    }
};

HWTEST_F(PrintFeaturePluginManagerTest, GetInstance_AlwaysReturnSameInstance, TestSize.Level1)
{
    auto &instance = PrintFeaturePluginManager::GetInstance();
    EXPECT_NE(&instance, nullptr);
    EXPECT_NO_FATAL_FAILURE(instance.UnloadAll());
    auto guard = instance.AcquireFeature(static_cast<PrintFeatureType>(99));
    EXPECT_EQ(guard.Get(), nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, AcquireFeature_UnknownType_ReturnsEmptyGuard, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto guard = manager.AcquireFeature(static_cast<PrintFeatureType>(99));
    EXPECT_EQ(guard.Get(), nullptr);
    EXPECT_EQ(manager.AcquireFeature(static_cast<PrintFeatureType>(99)).Get(), nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, UnloadAll_WithoutLoad_NoCrash, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    EXPECT_NO_FATAL_FAILURE(manager.UnloadAll());
    auto guard = manager.AcquireFeature(static_cast<PrintFeatureType>(99));
    EXPECT_EQ(guard.Get(), nullptr);
    EXPECT_NO_FATAL_FAILURE(manager.UnloadAll());
}

#ifdef REMOTE_SERVICE_ENABLE
HWTEST_F(PrintFeaturePluginManagerTest, AcquireFeature_RemotePrinterManager_LoadSuccess, TestSize.Level1)
{
    if (!IsRemotePluginAvailable()) {
        GTEST_SKIP() << "remote plugin not deployed: " << GetRemotePluginPath();
    }
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    ASSERT_NE(guard.Get(), nullptr);
    auto remote = guard.Get()->QueryInterface(PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER);
    EXPECT_NE(remote, nullptr);
    EXPECT_EQ(static_cast<void *>(remote), static_cast<void *>(guard.Get()));
}
#endif // REMOTE_SERVICE_ENABLE

#ifdef HAVE_PRINT_FAILURE_AI_NOTIFIER
HWTEST_F(PrintFeaturePluginManagerTest, AcquireFeature_AiNotifier_LoadSuccess, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto guard = manager.AcquireFeature(PrintFeatureType::AI_NOTIFIER);
    ASSERT_NE(guard.Get(), nullptr);
    auto ai = guard.Get()->QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER);
    EXPECT_NE(ai, nullptr);
    EXPECT_EQ(static_cast<void *>(ai), static_cast<void *>(guard.Get()));
}
#endif // HAVE_PRINT_FAILURE_AI_NOTIFIER

class FakePrintFeature : public IPrintFeature {
public:
    void *QueryInterface(PrintFeatureIid /* iid */) override
    {
        return nullptr;
    }
};

HWTEST_F(PrintFeaturePluginManagerTest, AcquireFeature_WhileUnloading_ReturnsEmptyGuard, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    UnloadingStateGuard unloadingGuard(manager);
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(guard.Get(), nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, AcquireFeature_WithExistingLoader_ReturnsEmptyGuard, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto &entry = manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER];
    entry.loader = std::make_unique<PrintFeaturePluginLoader>("remote",
        "/system/lib/nonexistent_remote.z.so",
        "CreateRemotePrintFeature", "DestroyRemotePrintFeature");
    entry.impl.reset();
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(guard.Get(), nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, FeatureUseGuard_MoveAndSelfAssign, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto *fake = new FakePrintFeature();
    manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fake, PrintFeatureDeleter(nullptr));

    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    EXPECT_EQ(guard.Get(), fake);

    auto moved = std::move(guard);
    EXPECT_EQ(guard.Get(), nullptr);
    EXPECT_EQ(moved.Get(), fake);

    moved = std::move(moved);
    EXPECT_EQ(moved.Get(), fake);

    moved = PrintFeaturePluginManager::FeatureUseGuard();
    EXPECT_EQ(moved.Get(), nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, FeatureUseGuard_Release_UnknownType_ResetsGuardAndLeavesCounts,
    TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();

    auto activeCountsBefore = manager.activeCounts_;

    {
        FakePrintFeature fake;
        PrintFeaturePluginManager::FeatureUseGuard guard(
            &manager, static_cast<PrintFeatureType>(99), &fake);
        EXPECT_EQ(guard.Get(), &fake);
    }

    EXPECT_EQ(manager.activeCounts_, activeCountsBefore);
}

HWTEST_F(PrintFeaturePluginManagerTest, FeatureUseGuard_Release_ActiveCountZero_NoCrash, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.activeCounts_[PrintFeatureType::REMOTE_PRINTER_MANAGER] = 0;
    auto *fake = new FakePrintFeature();
    {
        PrintFeaturePluginManager::FeatureUseGuard guard(
            &manager, PrintFeatureType::REMOTE_PRINTER_MANAGER, fake);
        EXPECT_EQ(guard.Get(), fake);
    }
    EXPECT_EQ(manager.activeCounts_[PrintFeatureType::REMOTE_PRINTER_MANAGER], 0);
}

HWTEST_F(PrintFeaturePluginManagerTest, UnloadAll_WaitsForActiveGuardAndClearsImpl, TestSize.Level1)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    manager.UnloadAll();
    auto *fake = new FakePrintFeature();
    manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl =
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(fake, PrintFeatureDeleter(nullptr));

    std::promise<void> guardAcquired;
    std::thread holder([&manager, &guardAcquired] {
        auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
        guardAcquired.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    guardAcquired.get_future().wait();
    manager.UnloadAll();
    holder.join();
    EXPECT_EQ(manager.features_[PrintFeatureType::REMOTE_PRINTER_MANAGER].impl, nullptr);
    EXPECT_EQ(manager.activeCounts_[PrintFeatureType::REMOTE_PRINTER_MANAGER], 0);
    EXPECT_FALSE(manager.unloading_);
}

} // namespace OHOS::Print
