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

#include "print_service_proxy.h"
#include "iremote_broker.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintServiceProxyTest::SetUpTestCase(void) {}

void PrintServiceProxyTest::TearDownTestCase(void) {}

void PrintServiceProxyTest::SetUp(void) {}

void PrintServiceProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintServiceProxyTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintServiceProxyTest, PrintServiceProxyTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintServiceProxy printServiceProxy;
    napi_env env = nullptr;
    info.SetVendorName("vendorName");
    PRINT_HILOGD("%{public}s", info.GetExtensionId().c_str());
    info.ToJsObject(env);
}

} // namespace Print
} // namespace OHOS