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
#include "print_preview_attribute.h"
#include "print_range.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintPreviewAttributeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintPreviewAttributeTest::SetUpTestCase(void) {}

void PrintPreviewAttributeTest::TearDownTestCase(void) {}

void PrintPreviewAttributeTest::SetUp(void) {}

void PrintPreviewAttributeTest::TearDown(void) {}

/**
 * @tc.name: PrintPreviewAttributeTest_0001
 * @tc.desc: Verify the StartPag function.
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintPreviewAttribute(attribute_);
    OHOS::Print::PrintRange range;
    attribute.SetResult(0);
    attribute.GetPreviewRange(range);
    attribute.Dump();
}
} // namespace Print
} // namespace OHOS