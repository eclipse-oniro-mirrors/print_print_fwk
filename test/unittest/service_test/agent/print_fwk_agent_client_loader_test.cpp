/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "print_constant.h"
#include "agent/print_fwk_agent_client_loader.h"

using namespace OHOS::Print;

struct PrintFwkAgentClient {};

static_assert(PRINT_FWK_AGENT_CLIENT_ERR_BACKEND_CONFIG == 7);
static_assert(PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR == 8);
static_assert(PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED == 9);
static_assert(PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY == 10);
static_assert(PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT == 11);
static_assert(PRINT_AGENT_PROGRESS_RETRYING_ADD == 3);
static_assert(PRINT_AGENT_PROGRESS_DONE == 4);

namespace {
PrintFwkAgentClient g_client;
uint32_t g_destroyCount = 0;

void ResetFakeApiState()
{
    g_destroyCount = 0;
}

PrintFwkAgentClient *FakeCreate()
{
    return &g_client;
}

void FakeDestroy(PrintFwkAgentClient *)
{
    ++g_destroyCount;
}

int32_t FakeAddPrinter(PrintFwkAgentClient *, const PrintAddPrinterParam *,
    PrintAgentAddDoneCb, PrintAgentProgressCb, void *)
{
    return PRINT_FWK_AGENT_CLIENT_OK;
}

int32_t FakeRemovePrinter(PrintFwkAgentClient *, const char *, const char *,
    PrintAgentRemoveDoneCb, void *)
{
    return PRINT_FWK_AGENT_CLIENT_OK;
}

PrintFwkAgentClientApi CreateFakeApi()
{
    return {
        1,
        FakeCreate,
        FakeDestroy,
        FakeAddPrinter,
        FakeRemovePrinter,
    };
}
} // namespace

TEST(PrintFwkAgentClientLoaderTest, MapErrorCoversAllCodes)
{
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_OK),
              E_PRINT_NONE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_PARAM),
              E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_SERVER),
              E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS),
              E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND),
              E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_RPC),
              E_PRINT_RPC_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_UNIMPLEMENTED),
              E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_BACKEND_CONFIG),
              E_PRINT_RPC_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR),
              E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED),
              E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY),
              E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(PrintFwkAgentClientLoader::MapError(PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT),
              E_PRINT_RPC_FAILURE);
}

TEST(PrintFwkAgentClientLoaderTest, NotLoadedCallsReturnRpcFailure)
{
    PrintFwkAgentClientLoader loader;
    PrintAddPrinterParam params {};
    EXPECT_EQ(loader.AddPrinter(params, nullptr, nullptr, nullptr), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(loader.RemovePrinter("", "", nullptr, nullptr), E_PRINT_RPC_FAILURE);
}

TEST(PrintFwkAgentClientLoaderTest, ValidateApiRejectsWrongAbiVersion)
{
    PrintFwkAgentClientLoader loader;
    auto api = CreateFakeApi();
    api.abiVersion = 2;

    EXPECT_FALSE(loader.ValidateApi(&api));
}

TEST(PrintFwkAgentClientLoaderTest, ValidateApiRejectsMissingDestroy)
{
    PrintFwkAgentClientLoader loader;
    auto api = CreateFakeApi();
    api.destroy = nullptr;

    EXPECT_FALSE(loader.ValidateApi(&api));
}

TEST(PrintFwkAgentClientLoaderTest, UnloadDestroysOnlyOnce)
{
    ResetFakeApiState();
    PrintFwkAgentClientLoader loader;
    auto api = CreateFakeApi();
    loader.SetApiForTest(&api, &g_client);

    loader.Unload();
    EXPECT_EQ(g_destroyCount, 1u);

    loader.Unload();
    EXPECT_EQ(g_destroyCount, 1u);
}
