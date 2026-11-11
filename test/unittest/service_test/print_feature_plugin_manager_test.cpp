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

#include "print_feature_plugin_manager.h"
#include "print_feature_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Print {

class PrintFeaturePluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintFeaturePluginManagerTest::SetUpTestCase(void)
{
}

void PrintFeaturePluginManagerTest::TearDownTestCase(void)
{
}

void PrintFeaturePluginManagerTest::SetUp(void)
{
}

void PrintFeaturePluginManagerTest::TearDown(void)
{
    PrintFeaturePluginManager::GetInstance().UnloadAll();
}

HWTEST_F(PrintFeaturePluginManagerTest, GetInstance_AlwaysReturnSameInstance, TestSize.Level1)
{
    auto &instance1 = PrintFeaturePluginManager::GetInstance();
    auto &instance2 = PrintFeaturePluginManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(PrintFeaturePluginManagerTest, GetFeature_UnknownType_ReturnNull, TestSize.Level1)
{
    auto feature = PrintFeaturePluginManager::GetInstance().GetFeature(static_cast<PrintFeatureType>(99));
    EXPECT_EQ(feature, nullptr);
}

HWTEST_F(PrintFeaturePluginManagerTest, UnloadAll_WithoutLoad_NoCrash, TestSize.Level1)
{
    PrintFeaturePluginManager::GetInstance().UnloadAll();
    EXPECT_EQ(PrintFeaturePluginManager::GetInstance().GetFeature(static_cast<PrintFeatureType>(99)), nullptr);
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

} // namespace OHOS::Print
