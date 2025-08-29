/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <functional>
#include <memory>
#include <map>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "scan_constant.h"

namespace OHOS {
namespace Scan {
class ScanAsyncCallTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ScanAsyncCallTest::SetUpTestCase(void)
{}

void ScanAsyncCallTest::TearDownTestCase(void)
{}

void ScanAsyncCallTest::SetUp(void)
{}

void ScanAsyncCallTest::TearDown(void)
{}

/**
 * @tc.name: ScanAsyncCallTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanAsyncCallTest, ScanAsyncCallTest_0001_NeedRename, TestSize.Level1)
{
    napi_env env;
    napi_callback_info info;
    auto context = std::make_shared<NapiScanContext>();
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    auto exec = [context](ScanAsyncCall::Context *ctx) { EXPECT_NE(context, nullptr); };
    asyncCall.Call(env, exec);
}
}  // namespace Scan
}  // namespace OHOS