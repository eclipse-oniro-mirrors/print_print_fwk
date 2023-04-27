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
#include "print_manager_client.h"

#include "iservice_registry.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class NapiPrintUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NapiPrintUtilTest::SetUpTestCase(void) {}

void NapiPrintUtilTest::TearDownTestCase(void) {}

void NapiPrintUtilTest::SetUp(void) {}

void NapiPrintUtilTest::TearDown(void) {}

/**
 * @tc.name: NapiPrintUtilTest_0001
 * @tc.desc: SetUint32Property
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0001, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value int_value = nullptr;
    napi_env env = nullptr;
    OHOS::Print::NapiPrintUtils::SetUint32Property(env, napiValue, "string", 1);
    int_value = OHOS::Print::NapiPrintUtils::CreateInt32(env, 1);
    OHOS::Print::NapiPrintUtils::GetInt32FromValue(env, int_value);
}
} // namespace Print
} // namespace OHOS
