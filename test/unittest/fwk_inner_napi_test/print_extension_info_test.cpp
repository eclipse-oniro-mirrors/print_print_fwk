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
#include "print_extension_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintExtensionInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionInfoTest::SetUpTestCase(void) {}

void PrintExtensionInfoTest::TearDownTestCase(void) {}

void PrintExtensionInfoTest::SetUp(void) {}

void PrintExtensionInfoTest::TearDown(void) {}

/**
 * @tc.name: PrintExtInfoTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    OHOS::Print::PrintExtensionInfo info_ = info;
    napi_env env = nullptr;
    info.SetVendorName("vendorName");
    info.SetExtensionId("extensionId:123");
    PRINT_HILOGD("%{public}d", info.GetExtensionId());
    PRINT_HILOGD("%{public}d", info.GetVendorIcon());
    PRINT_HILOGD("%{public}d", info.GetVendorId());
    PRINT_HILOGD("%{public}d", info.GetVendorName());
    PRINT_HILOGD("%{public}d", info.GetVersion());
    info.ToJsObject(env);
    info.Dump();
}
} // namespace Print
} // namespace OHOS