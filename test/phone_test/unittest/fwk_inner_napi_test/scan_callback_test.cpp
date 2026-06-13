/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <mutex>
#include <functional>
#include <new>
#define PRIVATE public
#define PROTECTED public
#include "scan_callback.h"
#undef PRIVATE
#undef PROTECTED
#include "scan_constant.h"
#include "mock_napi_scan_utils.h"

bool g_forceNewNothrowFailure = false;

static constexpr std::size_t MAX_ALLOC_SIZE = SIZE_MAX / 2;

void* operator new(std::size_t size, const std::nothrow_t&) noexcept
{
    if (size == 0 || size > MAX_ALLOC_SIZE || g_forceNewNothrowFailure) {
        return nullptr;
    }
    return malloc(size);
}

using namespace testing;
using namespace testing::ext;

namespace OHOS::Scan {
class ScanCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanCallbackTest::SetUpTestCase(void)
{}

void ScanCallbackTest::TearDownTestCase(void)
{}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_Constructor_001, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->env_, nullptr);
    EXPECT_EQ(callback->ref_, nullptr);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_Constructor_002, TestSize.Level1)
{
    std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction =
        [](std::vector<ScanDeviceInfo> &infos) {};
    auto callback = std::make_shared<ScanCallback>(callbackFunction);
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(callback->callbackFunction_, nullptr);
    EXPECT_EQ(callback->env_, nullptr);
    EXPECT_EQ(callback->ref_, nullptr);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnGetDevicesList_001, TestSize.Level1)
{
    std::vector<ScanDeviceInfo> infos;
    std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction =
        [](std::vector<ScanDeviceInfo> &infos) {};
    auto callback = std::make_shared<ScanCallback>(callbackFunction);
    EXPECT_NE(callback, nullptr);
    bool result = callback->OnGetDevicesList(infos);
    EXPECT_EQ(result, true);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnGetDevicesList_002, TestSize.Level1)
{
    std::vector<ScanDeviceInfo> infos;
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    callback->callbackFunction_ = nullptr;
    bool result = callback->OnGetDevicesList(infos);
    EXPECT_EQ(result, false);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnCallback_001, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    ScanDeviceInfo info;
    uint32_t state = 1;
    bool result = callback->OnCallback(state, info);
    EXPECT_EQ(result, false);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnCallbackSync_001, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    ScanDeviceInfoSync info;
    uint32_t state = 1;
    bool result = callback->OnCallbackSync(state, info);
    EXPECT_EQ(result, false);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_CallbackParam_001, TestSize.Level1)
{
    CallbackParam param;
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    auto mutexPtr = std::make_shared<std::mutex>();
    param.InitialCallbackParam(env, ref, mutexPtr);
    EXPECT_EQ(param.env, nullptr);
    EXPECT_EQ(param.ref, nullptr);
    EXPECT_EQ(param.mutexPtr, mutexPtr);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_CallbackParam_002, TestSize.Level1)
{
    CallbackParam param;
    uint32_t state = 1;
    ScanDeviceInfo info;
    info.SetDeviceId("test_device_id");
    param.SetCallbackParam(state, info);
    EXPECT_EQ(param.state, state);
    EXPECT_EQ(param.deviceInfo.GetDeviceId(), "test_device_id");
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_CallbackParam_003, TestSize.Level1)
{
    CallbackParam param;
    uint32_t state = 2;
    ScanDeviceInfoSync info;
    info.SetDeviceId("test_sync_device_id");
    param.SetCallbackSyncParam(state, info);
    EXPECT_EQ(param.state, state);
    EXPECT_EQ(param.deviceInfoSync.GetDeviceId(), "test_sync_device_id");
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_NapiCallFunction_001, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    CallbackParam cbParam;
    cbParam.env = nullptr;
    cbParam.ref = nullptr;
    cbParam.mutexPtr = std::make_shared<std::mutex>();
    napi_value callbackValues[1] = { nullptr };
    callback->NapiCallFunction(&cbParam, 1, callbackValues);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_NapiCallFunction_002, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    callback->NapiCallFunction(nullptr, 1, nullptr);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_Destructor_001, TestSize.Level1)
{
    auto callback = new ScanCallback(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    delete callback;
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_Destructor_002, TestSize.Level1)
{
    std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction =
        [](std::vector<ScanDeviceInfo> &infos) {};
    auto callback = new ScanCallback(callbackFunction);
    EXPECT_NE(callback, nullptr);
    delete callback;
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_ExecuteNapiEventWork_001, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    CallbackParam *param = nullptr;
    auto workFunc = [](CallbackParam *p) {};
    bool result = callback->ExecuteNapiEventWork(param, workFunc);
    EXPECT_EQ(result, false);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_ExecuteNapiEventWork_002, TestSize.Level1)
{
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    CallbackParam *param = new CallbackParam();
    param->env = nullptr;
    param->ref = nullptr;
    param->mutexPtr = std::make_shared<std::mutex>();
    auto workFunc = [](CallbackParam *p) {};
    bool result = callback->ExecuteNapiEventWork(param, workFunc);
    EXPECT_EQ(result, false);
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_Destructor_003, TestSize.Level1)
{
    auto callback = new ScanCallback(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    callback->env_ = reinterpret_cast<napi_env>(1);
    callback->ref_ = reinterpret_cast<napi_ref>(1);
    delete callback;
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_NapiCallFunction_003, TestSize.Level1)
{
    g_mockGetRefReturnNonNull = true;
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    CallbackParam cbParam;
    cbParam.env = nullptr;
    cbParam.ref = nullptr;
    cbParam.mutexPtr = std::make_shared<std::mutex>();
    napi_value callbackValues[1] = { nullptr };
    callback->NapiCallFunction(&cbParam, 1, callbackValues);
    g_mockGetRefReturnNonNull = false;
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnCallback_002, TestSize.Level1)
{
    g_forceNewNothrowFailure = true;
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    ScanDeviceInfo info;
    uint32_t state = 1;
    bool result = callback->OnCallback(state, info);
    EXPECT_EQ(result, false);
    g_forceNewNothrowFailure = false;
}

HWTEST_F(ScanCallbackTest, ScanCallbackTest_OnCallbackSync_002, TestSize.Level1)
{
    g_forceNewNothrowFailure = true;
    auto callback = std::make_shared<ScanCallback>(nullptr, nullptr);
    EXPECT_NE(callback, nullptr);
    ScanDeviceInfoSync info;
    uint32_t state = 1;
    bool result = callback->OnCallbackSync(state, info);
    EXPECT_EQ(result, false);
    g_forceNewNothrowFailure = false;
}
}  // namespace OHOS::Scan
