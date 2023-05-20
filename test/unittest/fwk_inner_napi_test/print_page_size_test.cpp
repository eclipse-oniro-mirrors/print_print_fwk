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
#include "print_page_size.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintPageSizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintPageSizeTest::SetUpTestCase(void) {}

void PrintPageSizeTest::TearDownTestCase(void) {}

void PrintPageSizeTest::SetUp(void) {}

void PrintPageSizeTest::TearDown(void) {}

/**
 * @tc.name: PrintPageSizeTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPageSizeTest, PrintPageSizeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintPageSize printpageSize;
    OHOS::Print::PrintPageSize::BuildPageSizeMap();
    OHOS::Print::PrintPageSize(printpageSize_);
    DiscretePageName name = "name";
    PAGE_SIZE_ID id = "id";
    OHOS::Print::PrintPageSize(id, name, 1, 1);
    napi_env env = nullptr;
    napi_value val = nullptr;
    printpageSize.Reset();
    printpageSize.SetId("string");
    printpageSize.SetHeight(1);
    printpageSize.SetWidth(2);
    printpageSize.SetName("name");
    PRINT_HILOGD("%{public}s", printpageSize.GetId().c_str());
    PRINT_HILOGD("%{public}s", printpageSize.GetName().c_str());
    PRINT_HILOGD("%{public}d", printpageSize.GetHeight());
    printpageSize.ToJsObject(env);
    printpageSize.Dump();
    OHOS::Print::PrintPageSize::ValidateProperty(env, val);
    OHOS::Print::PrintPageSize::BuildFromJs(env, val);
    OHOS::Print::PrintPageSize pageSizeValue = printpageSize;
}
} // namespace Print
} // namespace OHOS