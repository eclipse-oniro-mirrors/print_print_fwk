/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applipcable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "iservice_registry.h"
#include "print_constant.h"
#include "print_callback_proxy.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintCallbackProxyTest::SetUpTestCase(void) {}

void PrintCallbackProxyTest::TearDownTestCase(void) {}

void PrintCallbackProxyTest::SetUp(void) {}

void PrintCallbackProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintCallbackProxyTest_0001
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0001, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy printCallbackProxy(impl);
    printCallbackProxy.~PrintCallbackProxy();
}

/**
 * @tc.name: PrintCallbackProxyTest_0002
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0002, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy printCallbackProxy(impl);
    EXPECT_TRUE(printCallbackProxy.OnCallback());
}

/**
 * @tc.name: PrintCallbackProxyTest_0003
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0003, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy printCallbackProxy(impl);
    uint32_t state = 1;
    const OHOS::Print::PrinterInfo info;
    EXPECT_TRUE(printCallbackProxy.OnCallback(state, info));
}

/**
 * @tc.name: PrintCallbackProxyTest_0004
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0004, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy printCallbackProxy(impl);
    uint32_t state = 1;
    const OHOS::Print::PrintJob info;
    EXPECT_TRUE(printCallbackProxy.OnCallback(state, info));
}

/**
 * @tc.name: PrintCallbackProxyTest_0005
 * @tc.desc: printCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0005, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy printCallbackProxy(impl);
    const std::string extensionId, strInfo;
    EXPECT_TRUE(printCallbackProxy.OnCallback(extensionId, strInfo));
}
} // namespace Print
} // namespace OHOS
