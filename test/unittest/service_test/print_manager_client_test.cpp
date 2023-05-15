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
class PrintManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintManagerClientTest::SetUpTestCase(void) {}

void PrintManagerClientTest::TearDownTestCase(void) {}

void PrintManagerClientTest::SetUp(void) {}

void PrintManagerClientTest::TearDown(void) {}

/**
 * @tc.name: PrintManagerClientTest_0001
 * @tc.desc: QueryAllExtension
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerClientTest, PrintManagerClientTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintManagerClient Testclient;
    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    std::vector<uint32_t> fdList = {1, 2};
    std::string taskId = "2";
    PrintExtensionInfo printExtensionInfo;
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorIcon(1);
    printExtensionInfo.SetVersion("1");
    printExtensionInfo.SetExtensionId("1");
    printExtensionInfo.SetVendorId("1");
    std::vector<PrintExtensionInfo> extensionInfos;
    extensionInfos.emplace_back(printExtensionInfo);
    Testclient.StartPrint(fileList, fdList, taskId);
    Testclient.QueryAllExtension(extensionInfos);
}
} // namespace Print
} // namespace OHOS
