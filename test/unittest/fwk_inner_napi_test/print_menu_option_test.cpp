/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "print_menu_option.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintMenuOptionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintMenuOptionTest::SetUpTestCase(void)
{}

void PrintMenuOptionTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PrintMenuOptionTest_001
 * @tc.desc: Verify the reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMenuOptionTest, PrintMenuOptionTest_001, TestSize.Level1)
{
    OHOS::Print::PrintMenuOption menuOption;
    menuOption.Reset();
    EXPECT_EQ(false, menuOption.GetIsSelect());
}

/**
 * @tc.name: PrintMenuOptionTest_002
 * @tc.desc: Verify the SetMenuItemResourceName and GetMenuItemResourceName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMenuOptionTest, PrintMenuOptionTest_002, TestSize.Level1)
{
    OHOS::Print::PrintMenuOption menuOption;
    menuOption.SetMenuItemResourceName("menuItemResourceName");
    EXPECT_EQ("menuItemResourceName", menuOption.GetMenuItemResourceName());
}

/**
 * @tc.name: PrintMenuOptionTest_003
 * @tc.desc: Verify the SetIsSelect and GetIsSelect function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMenuOptionTest, PrintMenuOptionTest_003, TestSize.Level1)
{
    OHOS::Print::PrintMenuOption menuOption;
    menuOption.SetIsSelect(true);
    EXPECT_TRUE(menuOption.GetIsSelect());
}

/**
 * @tc.name: PrintMenuOptionTest_004
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintMenuOptionTest, PrintMenuOptionTest_004, TestSize.Level1)
{
    OHOS::Print::PrintMenuOption menuOption;
    menuOption.SetMenuItemResourceName("menuItemResourceName");
    menuOption.SetIsSelect(true);
    Parcel parcel;
    EXPECT_TRUE(menuOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintMenuOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

}  // namespace Print
}  // namespace OHOS
