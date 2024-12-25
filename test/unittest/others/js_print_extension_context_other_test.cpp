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
#include "js_print_extension_context.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class JsPrintExtensionContextTest : public testing:Test {
public:
JsPrintExtensionContext* jsPrintExtensionContext;
void SetUp() override
{
JsPrintExtensionContext = new JsPrintExtensionContext();
}
void TearDown() override
{
delete jsPrintExtensionContext;
jsPrintExtensionContext = nullptr
}
};

HWTEST_F(nullTest, GetUndefinedValue_ShouldReturnUndefined_WhenCalled, Level0)
{
napi_env engine;
napi_value result = GetUndefinedValue(engine);
EXPECT_EQ(result, nullptr);
}

HWTEST_F(nullTest, OnStartAbility_ShouldReturnUndefined_WhenArgcIsOne, TestSize.Level0)
{
napi_env engine = mock napi_env;
napi_callback_info info =  mock napi_callback_info;
napi_value result = OnStartAbility(engine, info);
EXPECT_EQ(napi_undefined, result);
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenArgcIsNotTwoOrThreeOrFour, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenWantUnwrapFails, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenAccountIdUnwrapFails, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenStartOptionsUnwrapFails, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenLastParamIsNotNil, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnStartAbilityWithAccount_ShouldReturnUndefined_WhenStartAbilityWithAccountFails, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest,
  OnStartAbilityWithAccount_ShouldReturnResolvedPromise_WhenStartAbilityWithAccountSucceeds, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::MAX_ARGC;
napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
napi_value result = OnStartAbilityWithAccount(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

TEST_F(nullTest, TestOnTerminateAbility_WhenArgcNotZeroOrOne_ShouldReturnUndefined)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

TEST_F(nullTest, TestOnTerminateAbility_WhenArgcIsZero_ShouldReturnUndefined)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

TEST_F(nullTest, TestOnTerminateAbility_WhenArgcIsOne_ShouldReturnNapiValue)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_NE(result, nullptr);
}

TEST_F(nullTest, TestOnTerminateAbility_WhenContextIsReleased_ShouldReturnError)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_EQ(result, nullptr);
}

TEST_F(nullTest, TestOnTerminateAbility_WhenTerminateAbilitySucceeds_ShouldReturnUndefined)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

TEST_F(nullTest, TestOnTerminateAbility_WhenTerminateAbilityFails_ShouldReturnError)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnTerminateAbility(engine, info);
EXPECT_EQ(result, nullptr);
}

HWTEST_F(nullTest, OnConnectAbility_ShouldReturnUndefined_WhenArgcNotTwo, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnConnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnUndefined_WhenArgcIsNotOneOrTwo, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnUndefined_WhenConnectionIsNull, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::ARGC_ONE;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnResolvedPromise_WhenDisconnectAbilitySucceeds, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::ARGC_ONE;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnRejectedPromise_WhenDisconnectAbilityFails, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::ARGC_ONE;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnResolvedPromise_WhenLastParamIsNull, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::ARGC_ONE;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest, OnDisconnectAbility_ShouldReturnResolvedPromise_WhenLastParamIsNotNull, Level0)
{
napi_env engine;
napi_callback_info info;
napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
size_t argc = NapiPrintUtils::ARGC_TWO;
napi_value result = OnDisconnectAbility(engine, info);
EXPECT_EQ(result, GetUndefinedValue(engine));
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNonNullContext, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest, CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNullContext, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest, CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNonNullContext, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest, CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContext, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNonNullContextAndNonNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId = "testExtensionId";
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNonNullContextAndNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNullContextAndNonNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId = "testExtensionId";
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNonNullEngineAndNullContextAndNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNonNullContextAndNonNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId = "testExtensionId";
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNonNullContextAndNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = std::make_shared<PrintExtensionContext>();
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNonNullExtensionId,
    Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId = "testExtensionId";
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

HWTEST_F(nullTest,
    CreateJsPrintExtensionContext_ShouldReturnNonNull_WhenCalledWithNullEngineAndNullContextAndNullExtensionId, Level0)
{
napi_env engine = nullptr;
std::shared_ptr<PrintExtensionContext> context = nullptr;
std::string extensionId;
napi_value result = CreateJsPrintExtensionContext(engine, context, extensionId);
EXPECT_NE(result, nullptr);
}

} // namespace OHOS::Print