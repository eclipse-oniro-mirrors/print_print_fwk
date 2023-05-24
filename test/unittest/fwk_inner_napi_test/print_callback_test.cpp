/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "napi/native_api.h"

#include "print_callback.h"
#include "napi_print_utils.h"
#include "print_log.h"
#include <uv.h>

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintCallbackTest::SetUpTestCase(void) {}

void PrintCallbackTest::TearDownTestCase(void) {}

void PrintCallbackTest::SetUp(void) {}

void PrintCallbackTest::TearDown(void) {}

/**
 * @tc.name: PrintCallbackTest_0001
 * @tc.desc: Verify the Setfile function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCallbackTest, PrintCallbackTest_0001, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    OHOS::Print::PrintCallback callback(env, ref);
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