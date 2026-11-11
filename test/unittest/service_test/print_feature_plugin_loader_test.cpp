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

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

namespace {
constexpr const char *TEST_PLUGIN_NAME = "libprint_feature_test.z.so";
constexpr const char *MISSING_PLUGIN_NAME = "libprint_feature_missing.z.so";
constexpr const char *CREATE_SYMBOL = "CreatePrintFeature";
constexpr const char *DESTROY_SYMBOL = "DestroyPrintFeature";

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

std::string GetPluginPath(const std::string &pluginName)
{
    return JoinPath(GetExeDir(), pluginName);
}

/* 单元测试时插件与测试二进制放在同一目录，由测试框架或手工推送部署。 */
std::string FindPluginPath(const std::string &pluginName)
{
    return GetPluginPath(pluginName);
}
}

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
    PrintFeaturePluginLoader loader("missing", GetPluginPath(MISSING_PLUGIN_NAME));
    EXPECT_FALSE(loader.IsLoaded());
    EXPECT_FALSE(loader.Load());
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Unload_NotLoaded_NoCrash, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("notloaded", GetPluginPath(MISSING_PLUGIN_NAME));
    loader.Unload();
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, GetSymbol_NotLoaded_ReturnNull, TestSize.Level1)
{
    PrintFeaturePluginLoader loader("notloaded", GetPluginPath(MISSING_PLUGIN_NAME));
    EXPECT_EQ(loader.GetSymbol(CREATE_SYMBOL), nullptr);
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_ValidPlugin_Success, TestSize.Level1)
{
    std::string pluginPath = FindPluginPath(TEST_PLUGIN_NAME);
    PrintFeaturePluginLoader loader("test", pluginPath);
    ASSERT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_TRUE(loader.IsLoaded());

    auto createFn = loader.GetSymbol(CREATE_SYMBOL);
    auto destroyFn = loader.GetSymbol(DESTROY_SYMBOL);
    ASSERT_NE(createFn, nullptr);
    ASSERT_NE(destroyFn, nullptr);

    auto creator = reinterpret_cast<IPrintFeature *(*)()>(createFn);
    IPrintFeature *feature = creator();
    ASSERT_NE(feature, nullptr);
    EXPECT_NE(feature->QueryInterface(PrintFeatureIid::IID_UNKNOWN), nullptr);

    auto destroyer = reinterpret_cast<void (*)(IPrintFeature *)>(destroyFn);
    destroyer(feature);

    loader.Unload();
    EXPECT_FALSE(loader.IsLoaded());
}

HWTEST_F(PrintFeaturePluginLoaderTest, Load_DoubleLoad_Idempotent, TestSize.Level1)
{
    std::string pluginPath = FindPluginPath(TEST_PLUGIN_NAME);
    PrintFeaturePluginLoader loader("test", pluginPath);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_TRUE(loader.Load()) << "second load should be idempotent at: " << pluginPath;
    EXPECT_TRUE(loader.IsLoaded());
    loader.Unload();
}

HWTEST_F(PrintFeaturePluginLoaderTest, GetSymbol_MissingSymbol_ReturnNull, TestSize.Level1)
{
    std::string pluginPath = FindPluginPath(TEST_PLUGIN_NAME);
    PrintFeaturePluginLoader loader("test", pluginPath);
    EXPECT_TRUE(loader.Load()) << "failed to load plugin at: " << pluginPath;
    EXPECT_EQ(loader.GetSymbol("NotExistedSymbol"), nullptr);
    loader.Unload();
}

} // namespace OHOS::Print
