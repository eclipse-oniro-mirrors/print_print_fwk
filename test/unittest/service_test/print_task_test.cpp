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
#include "print_task.h"
#include "print_task.cpp"
#include "napi_print_task.h"
#include "napi_print_utils.h"

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
class PrintTaskTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintTaskTest::SetUpTestCase(void) {}

void PrintTaskTest::TearDownTestCase(void) {}

void PrintTaskTest::SetUp(void) {}

void PrintTaskTest::TearDown(void) {}
/**
 * @tc.name: PrintTaskTest_0001
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintTaskTest, PrintTaskTest_0001, TestSize.Level1)
{
    std::vector<std::string> fileList = {"datashare://data/print/a.png",
        "datashare://data/print/b.png", "datashare://data/print/c.png"};
    OHOS::Print::PrintTask task(fileList);
}

/**
 * @tc.name: PrintTaskTest_0002
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintTaskTest, PrintTaskTest_0002, TestSize.Level1)
{
    std::vector<std::string> fileList = {"a", "b", "c"};
    OHOS::Print::PrintTask task(fileList);
    task.Start();
    task.Stop();
    std::string taskId = task.GetId();
    OHOS::Print::NapiPrintUtils::GetTaskEventId(taskId, "success");
    std::string taskType = "success";
    task.IsSupportType(taskType);
}

/**
 * @tc.name: PrintTaskTest_0003
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintTaskTest, PrintTaskTest_0003, TestSize.Level1)
{
    std::vector<std::string> fileList = {"fd://1", "fd://2", "fd://3"};
    OHOS::Print::PrintTask task(fileList);
    task.Start();
    task.Stop();
}
} // namespace Print
} // namespace OHOS
