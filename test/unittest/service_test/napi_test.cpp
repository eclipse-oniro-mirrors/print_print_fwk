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
#include "napi_inner_print.cpp"
#include "napi_print_ext.cpp"
#include "napi_print_task.cpp"
#include "print_async_call.cpp"
#include "print_constant.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class NapiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NapiTest::SetUpTestCase(void) {}

void NapiTest::TearDownTestCase(void) {}

void NapiTest::SetUp(void) {}

void NapiTest::TearDown(void) {}
/**
 * @tc.name: NapiInnerPrintTest_0001
 * @tc.desc: QueryExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0001, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::QueryExtensionInfo(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0002
 * @tc.desc: StartDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0002, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::StartDiscovery(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0003
 * @tc.desc: StopDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0003, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::StopDiscovery(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0004
 * @tc.desc: ConnectPrinter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0004, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::ConnectPrinter(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0005
 * @tc.desc: QueryExtensionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0005, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::DisconnectPrinter(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0006
 * @tc.desc: StartPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0006, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::StartPrintJob(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0007
 * @tc.desc: CancelPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0007, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::CancelPrintJob(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0008
 * @tc.desc: RequestPreview
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0008, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::RequestPreview(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0009
 * @tc.desc: QueryCapability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0009, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::QueryCapability(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0010
 * @tc.desc: QueryAllPrintJob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0010, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::QueryAllPrintJob(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0011
 * @tc.desc: QueryPrintJobById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0011, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::QueryPrintJobById(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0012
 * @tc.desc: On
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0012, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::On(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0013
 * @tc.desc: Off
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0013, TestSize.Level1)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    OHOS::Print::NapiInnerPrint::Off(env, info);
}

/**
 * @tc.name: NapiInnerPrintTest_0014
 * @tc.desc: IsSupportType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiInnerPrintTest_0014, TestSize.Level1)
{
    OHOS::Print::NapiInnerPrint::IsSupportType(PRINTER_EVENT_TYPE);
    OHOS::Print::NapiInnerPrint::IsSupportType("ERROR_TYPE");
}

/**
 * @tc.name: NapiPrintExtTest_0001
 * @tc.desc: AddPrinters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiTest, NapiPrintExtTest_0001, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0002, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0003, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0004, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0005, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0006, TestSize.Level1)
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
HWTEST_F(NapiTest, NapiPrintExtTest_0007, TestSize.Level1)
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
