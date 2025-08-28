/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "print_extension.h"
#include "extension_base.h"
#include "mock_runtime.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class PrintExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionTest::SetUpTestCase(void)
{}

void PrintExtensionTest::TearDownTestCase(void)
{}

void PrintExtensionTest::SetUp(void)
{}

void PrintExtensionTest::TearDown(void)
{}

/**
 * @tc.name: PrintExtensionTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionTest, PrintExtensionTest_0001, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = nullptr;
    EXPECT_NE(PrintExtension::Create(runtime), nullptr);
}

HWTEST_F(PrintExtensionTest, PrintExtensionTest_0002, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntime>();
    EXPECT_NE(PrintExtension::Create(runtime), nullptr);
}

HWTEST_F(PrintExtensionTest, PrintExtensionTest_0003, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    EXPECT_NE(PrintExtension::Create(runtime), nullptr);
}

HWTEST_F(PrintExtensionTest, PrintExtensionTest_0004, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntime>();
    std::shared_ptr<AbilityLocalRecord> record = nullptr;
    std::shared_ptr<OHOSApplication> application = nullptr;
    std::shared_ptr<AbilityHandler> handler = nullptr;
    sptr<IRemoteObject> token = nullptr;
    PrintExtension *printExtension = PrintExtension::Create(runtime);
    std::shared_ptr<PrintExtensionContext> context;
    context = printExtension->CreateAndInitContext(record, application, handler, token);
    EXPECT_NE(context, nullptr);
}
}  // namespace AbilityRuntime
}  // namespace OHOS