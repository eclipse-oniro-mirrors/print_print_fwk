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
#include <string>
#include <unistd.h>

#include "i_print_feature.h"
#include "print_feature_plugin_loader.h"
#include "print_feature_plugin_manager.h"
#include "print_feature_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {

constexpr const char *MISSING_PLUGIN_NAME = "libprint_feature_missing.z.so";
constexpr const char *AI_PLUGIN_CREATE_SYMBOL = "CreatePrintFailureAiNotifier";
constexpr const char *AI_PLUGIN_DESTROY_SYMBOL = "DestroyPrintFailureAiNotifier";
constexpr const char *MISSING_SYMBOL = "NotExistedSymbol";

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

std::string JoinPath(const std::string &dir, const std::string &name)
{
    if (dir.empty()) {
        return name;
    }
    if (dir.back() == '/') {
        return dir + name;
    }
    return dir + "/" + name;
}

bool FileExists(const std::string &path)
{
    return access(path.c_str(), F_OK) == 0;
}

std::string GetAiPluginPath()
{
    return PrintFeaturePluginManager::GetInstance().features_[PrintFeatureType::AI_NOTIFIER].libPath;
}

bool IsAiPluginAvailable()
{
    return FileExists(GetAiPluginPath());
}

class TempFileGuard {
public:
    explicit TempFileGuard(const std::string &path)
        : path_(path)
    {
        (void)remove(path_.c_str());
        FILE *fp = fopen(path_.c_str(), "w");
        if (fp != nullptr) {
            fprintf(fp, "not a shared library");
            fclose(fp);
            created_ = true;
        }
    }
    ~TempFileGuard()
    {
        (void)remove(path_.c_str());
    }
    bool IsCreated() const
    {
        return created_;
    }
    const std::string &GetPath() const
    {
        return path_;
    }
private:
    std::string path_;
    bool created_ = false;
};

} // namespace

class PrintFeaturePluginLoaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintFeaturePluginLoaderTest::SetUpTestCase(void)
{
}

void PrintFeaturePluginLoaderTest::TearDownTestCase(void)
{
}

void PrintFeaturePluginLoaderTest::SetUp(void)
{
}

void PrintFeaturePluginLoaderTest::TearDown(void)
{
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_MissingPath_ReturnFalse, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("missing", JoinPath(GetExeDir(), MISSING_PLUGIN_NAME));
    EXPECT_FALSE(loader.IsLoaded());
    EXPECT_FALSE(loader.Load());
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Unload_NotLoaded_NoCrash, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("notloaded", JoinPath(GetExeDir(), MISSING_PLUGIN_NAME));
    loader.Unload();
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, GetSymbol_NotLoaded_ReturnNull, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("notloaded", JoinPath(GetExeDir(), MISSING_PLUGIN_NAME));
    EXPECT_FALSE(loader.IsLoaded());
    EXPECT_EQ(loader.GetSymbol(AI_PLUGIN_CREATE_SYMBOL), nullptr);
    EXPECT_EQ(loader.GetSymbol(AI_PLUGIN_DESTROY_SYMBOL), nullptr);
    EXPECT_EQ(loader.GetSymbol(MISSING_SYMBOL), nullptr);
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_ValidPlugin_Success, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    std::string pluginPath = GetAiPluginPath();
    PrintFeaturePluginLoader loader("ai_notifier", pluginPath,
        AI_PLUGIN_CREATE_SYMBOL, AI_PLUGIN_DESTROY_SYMBOL);
    ASSERT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_TRUE(loader.IsLoaded());

    auto createFn = loader.GetSymbol(AI_PLUGIN_CREATE_SYMBOL);
    auto destroyFn = loader.GetSymbol(AI_PLUGIN_DESTROY_SYMBOL);
    ASSERT_NE(createFn, nullptr);
    ASSERT_NE(destroyFn, nullptr);

    auto creator = reinterpret_cast<IPrintFeature *(*)()>(createFn);
    IPrintFeature *feature = creator();
    ASSERT_NE(feature, nullptr);
    EXPECT_NE(feature->QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER), nullptr);

    auto destroyer = reinterpret_cast<void (*)(IPrintFeature *)>(destroyFn);
    destroyer(feature);

    loader.Unload();
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_DoubleLoad_Idempotent, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    std::string pluginPath = GetAiPluginPath();
    PrintFeaturePluginLoader loader("ai_notifier", pluginPath,
        AI_PLUGIN_CREATE_SYMBOL, AI_PLUGIN_DESTROY_SYMBOL);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_TRUE(loader.Load()) << "second load should be idempotent at: " << pluginPath;
    EXPECT_TRUE(loader.IsLoaded());
    loader.Unload();
}

HWTEST_F(PrintFeaturePluginLoaderTest, GetSymbol_MissingSymbol_ReturnNull, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    std::string pluginPath = GetAiPluginPath();
    PrintFeaturePluginLoader loader("ai_notifier", pluginPath,
        AI_PLUGIN_CREATE_SYMBOL, AI_PLUGIN_DESTROY_SYMBOL);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_EQ(loader.GetSymbol(MISSING_SYMBOL), nullptr);
    loader.Unload();
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_ValidPathButInvalidLibrary_ReturnsFalse, TestSize.Level1)
{
    TempFileGuard guard(JoinPath(GetExeDir(), "libprint_feature_bad.z.so"));
    ASSERT_TRUE(guard.IsCreated());

    PrintFeaturePluginLoader loader("bad", guard.GetPath());
    EXPECT_FALSE(loader.Load());
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Unload_DoubleUnload_Idempotent, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    std::string pluginPath = GetAiPluginPath();
    PrintFeaturePluginLoader loader("ai_notifier", pluginPath,
        AI_PLUGIN_CREATE_SYMBOL, AI_PLUGIN_DESTROY_SYMBOL);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    loader.Unload();
    EXPECT_FALSE(loader.IsLoaded());
    EXPECT_NO_FATAL_FAILURE(loader.Unload());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Constructor_WithCustomSymbols_StoresSymbols, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("custom", "/system/lib/custom.z.so", "CreateCustom", "DestroyCustom");
    EXPECT_EQ(loader.GetCreateSymbol(), "CreateCustom");
    EXPECT_EQ(loader.GetDestroySymbol(), "DestroyCustom");
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, GetSymbol_AfterUnload_ReturnsNull, TestSize.Level1)
{
    if (!IsAiPluginAvailable()) {
        GTEST_SKIP() << "ai notifier plugin not deployed: " << GetAiPluginPath();
    }
    std::string pluginPath = GetAiPluginPath();
    PrintFeaturePluginLoader loader("ai_notifier", pluginPath,
        AI_PLUGIN_CREATE_SYMBOL, AI_PLUGIN_DESTROY_SYMBOL);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    loader.Unload();
    EXPECT_EQ(loader.GetSymbol(AI_PLUGIN_CREATE_SYMBOL), nullptr);
}

} // namespace OHOS::Print
