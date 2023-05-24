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
#include "napi_print_task.cpp"
#include "print_async_call.cpp"
#include "print_constant.h"


using namespace testing::ext;

namespace OHOS {
namespace Print {
class NapiPrintTaskTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NapiPrintTaskTest::SetUpTestCase(void) {}

void NapiPrintTaskTest::TearDownTestCase(void) {}

void NapiPrintTaskTest::SetUp(void) {}

void NapiPrintTaskTest::TearDown(void) {}

/**
 * @tc.name: NapiPrintTaskTest_0001
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintTaskTest, NapiPrintTaskTest_0001, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintTask::Print(env, info);
}

/**
 * @tc.name: NapiPrintTaskTest_0002
 * @tc.desc: GetCtor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintTaskTest, NapiPrintTaskTest_0002, TestSize.Level1)
{
    napi_env env = nullptr;
    NapiPrintTask::GetCtor(env);
}

/**
 * @tc.name: NapiPrintTaskTest_0003
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintTaskTest, NapiPrintTaskTest_0003, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintTask::Initialize(env, info);
}

/**
 * @tc.name: NapiPrintTaskTest_0004
 * @tc.desc: IsValidFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintTaskTest, NapiPrintTaskTest_0004, TestSize.Level1)
{
    NapiPrintTask::IsValidFile("");
    NapiPrintTask::IsValidFile("datashare://1");
    NapiPrintTask::IsValidFile("fd://");
    NapiPrintTask::IsValidFile("error_filepath");
}
} // namespace Print
} // namespace OHOS
