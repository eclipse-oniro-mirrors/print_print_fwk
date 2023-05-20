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

/**
 * @tc.name: NapiPrintUtilTest_0002
 * @tc.desc: Setint32Property
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0002, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value int_value = nullptr;
    napi_env env = nullptr;
    OHOS::Print::NapiPrintUtils::SetInt32Property(env, napiValue, "string", 2);
    OHOS::Print::NapiPrintUtils::SetUint32Property(env, napiValue, "string", 3);
    int_value = OHOS::Print::NapiPrintUtils::CreateUint32(env, 1);
    OHOS::Print::NapiPrintUtils::GetUint32FromValue(env, int_value);
    OHOS::Print::NapiPrintUtils::GetUint32Property(env, int_value, "string");
}

/**
 * @tc.name: NapiPrintUtilTest_0003
 * @tc.desc: SetStringPropertyUtf8
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0003, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value int_value = nullptr;
    napi_env env = nullptr;
    OHOS::Print::NapiPrintUtils::SetStringPropertyUtf8(env, napiValue, "string", "001");
    int_value = OHOS::Print::NapiPrintUtils::CreateStringUtf8(env, "002");
    OHOS::Print::NapiPrintUtils::GetStringFromValueUtf8(env, int_value);
    OHOS::Print::NapiPrintUtils::GetStringPropertyUtf8(env, int_value, "string");
}

/**
 * @tc.name: NapiPrintUtilTest_0004
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0004, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value int_value = nullptr;
    napi_env env = nullptr;
    int_value = OHOS::Print::NapiPrintUtils::CreateObject(env);
    OHOS::Print::NapiPrintUtils::SetBooleanProperty(env, napiValue, "string", 0);
    OHOS::Print::NapiPrintUtils::GetBooleanProperty(env, int_value, "string");
}

/**
 * @tc.name: NapiPrintUtilTest_0005
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0005, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value string_value = nullptr;
    napi_env env = nullptr;
    OHOS::Print::NapiPrintUtils::SetNamedProperty(env, napiValue, "string", string_value);
    OHOS::Print::NapiPrintUtils::GetNamedProperty(env, string_value, "string");
}

/**
 * @tc.name: NapiPrintUtilTest_0006
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0006, TestSize.Level1)
{
    napi_env env = nullptr;
    size_t num = 1;
    void **vec = nullptr;
    napi_value array_value = OHOS::Print::NapiPrintUtils::CreateArrayBuffer(env, 1, vec);
    OHOS::Print::NapiPrintUtils::GetInfoFromArrayBufferValue(env, array_value, &num);
    OHOS::Print::NapiPrintUtils::GetPropertyNames(env, array_value);
    OHOS::Print::NapiPrintUtils::GetUndefined(env);
}

/**
 * @tc.name: NapiPrintUtilTest_0007
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0007, TestSize.Level1)
{
    napi_value napiValue = nullptr;
    napi_value *argv = nullptr;
    napi_env env = nullptr;
    napi_value callback = nullptr;
    napi_value func = nullptr;
    OHOS::Print::NapiPrintUtils::CallFunction(env, napiValue, func, 0, argv);
    napi_ref napiRef = OHOS::Print::NapiPrintUtils::CreateReference(env, callback);
    OHOS::Print::NapiPrintUtils::GetReference(env, napiRef);
    OHOS::Print::NapiPrintUtils::DeleteReference(env, napiRef);
}

/**
 * @tc.name: NapiPrintUtilTest_0008
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0008, TestSize.Level1)
{
    std::string higher = "HIGHER_SPELLING";
    std::string lower = OHOS::Print::NapiPrintUtils::ToLower(higher);
    napi_value val = nullptr;
    napi_env env = nullptr;
    std::initializer_list<napi_property_descriptor> properties;
    napi_create_string_utf8(env, "val", NAPI_AUTO_LENGTH, &val);
    OHOS::Print::NapiPrintUtils::GetValueString(env, val);
    OHOS::Print::NapiPrintUtils::ValueIsArrayBuffer(env, val);
    OHOS::Print::NapiPrintUtils::DefineProperties(env, val, properties);
}

/**
 * @tc.name: NapiPrintUtilTest_0009
 * @tc.desc: SetBooleanProperty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiPrintUtilTest, NapiPrintUtilTest_0009, TestSize.Level1)
{
    std::string extensionId = "ext:idej-dnfk-nnwk";
    std::string extensionId_err = "idej-dnfk-nnwk";
    std::string localId = "local-id";
    uint32_t callbackId = 1000;
    OHOS::Print::NapiPrintUtils::GetExtensionId(extensionId);
    OHOS::Print::NapiPrintUtils::GetExtensionId(extensionId_err);
    std::string globalId = OHOS::Print::NapiPrintUtils::GetGlobalId(extensionId, localId);
    std::string localId_ = OHOS::Print::NapiPrintUtils::GetLocalId(globalId, extensionId);
    std::string localId_err = OHOS::Print::NapiPrintUtils::GetLocalId(globalId, extensionId_err);
    std::string cid = OHOS::Print::NapiPrintUtils::EncodeExtensionCid(extensionId, callbackId);
    OHOS::Print::NapiPrintUtils::DecodeExtensionCid(cid, extensionId, callbackId);
    OHOS::Print::NapiPrintUtils::DecodeExtensionCid(cid, extensionId_err, callbackId);
}
} // namespace Print
} // namespace OHOS
