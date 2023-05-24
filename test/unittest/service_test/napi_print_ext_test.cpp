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
#include "napi_print_ext.cpp"
#include "print_async_call.cpp"
#include "print_constant.h"


using namespace testing::ext;

namespace OHOS {
namespace Print {
class NapiPrintExtTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NapiPrintExtTest::SetUpTestCase(void) {}

void NapiPrintExtTest::TearDownTestCase(void) {}

void NapiPrintExtTest::SetUp(void) {}

void NapiPrintExtTest::TearDown(void) {}
/**
 * @tc.name: NapiPrintExtTest_0001
 * @tc.desc: AddPrinters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0001, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::AddPrinters(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0002
 * @tc.desc: RemovePrinters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0002, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::RemovePrinters(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0003
 * @tc.desc: UpdatePrinters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0003, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::UpdatePrinters(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0004
 * @tc.desc: UpdatePrinterState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0004, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::UpdatePrinterState(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0005
 * @tc.desc: UpdatePrintJobState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0005, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::UpdatePrintJobState(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0006
 * @tc.desc: UpdateExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0006, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    NapiPrintExt::UpdateExtensionInfo(env, info);
}

/**
 * @tc.name: NapiPrintExtTest_0007
 * @tc.desc: UpdateExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintExtTest, NapiPrintExtTest_0007, TestSize.Level1)
{
    NapiPrintExt::IsValidPrinterState(PRINTER_UNKNOWN);
    NapiPrintExt::IsValidPrinterState(PRINTER_ADDED);
    NapiPrintExt::IsValidPrintJobState(PRINT_JOB_UNKNOWN);
    uint32_t errorJobState = 6;
    NapiPrintExt::IsValidPrintJobState(errorJobState);
    NapiPrintExt::IsValidPrintJobSubState(PRINT_JOB_COMPLETED_SUCCESS);
    uint32_t errorSubState = 18;
    NapiPrintExt::IsValidPrintJobSubState(errorSubState);
}
} // namespace Print
} // namespace OHOS
