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
#include "napi/native_api.h"
#include "napi_print_utils.h"

#include "iservice_registry.h"
#include "napi_print_utils.h"
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
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackProxyTest, PrintCallbackProxyTest_0001, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintCallbackProxy callback(impl);
    uint32_t state = 1;
    const OHOS::Print::PrinterInfo info;
    const OHOS::Print::PrintJob job;
    bool cb = callback.OnCallback();
    cb = callback.OnCallback(state, info);
    cb = callback.OnCallback(state, job);
    const std::string extensionId, strInfo;
    cb = callback.OnCallback(extensionId, strInfo);
}
} // namespace Print
} // namespace OHOS
