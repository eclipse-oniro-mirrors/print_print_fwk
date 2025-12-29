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
#include "print_custom_option.h"
#include "print_menu_option.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCustomOptionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    OHOS::Print::PrintCustomOption GetDefaultPrintCustomOption();
};

void PrintCustomOptionTest::SetUpTestCase(void)
{}

void PrintCustomOptionTest::TearDownTestCase(void)
{}

OHOS::Print::PrintCustomOption PrintCustomOptionTest::GetDefaultPrintCustomOption()
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetOptionName("optionName");
    customOption.SetType(1);
    customOption.SetBundleName("bundleName");
    customOption.SetOptionResourceName("optionResourceName");
    return customOption;
}

/**
 * @tc.name: PrintCustomOptionTest_001
 * @tc.desc: Verify the Set function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_001, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    OHOS::Print::PrintCustomOption right;
    customOption.Set(right);
    EXPECT_EQ((uint32_t)0, customOption.GetType());
}

/**
 * @tc.name: PrintCustomOptionTest_002
 * @tc.desc: Verify the reset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_002, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.Reset();
    EXPECT_EQ((uint32_t)0, customOption.GetType());
}

/**
 * @tc.name: PrintCustomOptionTest_003
 * @tc.desc: Verify the SetOptionName and GetOptionName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_003, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetOptionName("optionName");
    EXPECT_EQ("optionName", customOption.GetOptionName());
}

/**
 * @tc.name: PrintCustomOptionTest_004
 * @tc.desc: Verify the SetType and GetType function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_004, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetType(1);
    EXPECT_EQ((uint32_t)1, customOption.GetType());
}

/**
 * @tc.name: PrintCustomOptionTest_005
 * @tc.desc: Verify the SetBundleName and GetBundleName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_005, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetBundleName("bundleName");
    EXPECT_EQ("bundleName", customOption.GetBundleName());
}

/**
 * @tc.name: PrintCustomOptionTest_006
 * @tc.desc: Verify the SetOptionResourceName and GetOptionResourceName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_006, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetOptionResourceName("optionResourceName");
    EXPECT_EQ("optionResourceName", customOption.GetOptionResourceName());
}

/**
 * @tc.name: PrintCustomOptionTest_007
 * @tc.desc: Verify the hasValue function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_007, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    std::vector<PrintMenuOption> menuOption;
    customOption.SetMenuOption(menuOption);
    EXPECT_TRUE(customOption.HasValue());
}

/**
 * @tc.name: PrintCustomOptionTest_008
 * @tc.desc: Verify settings and obtain MenuOption function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_008, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    std::vector<PrintMenuOption> menuOption, getMenuOption;
    PrintMenuOption testMenuOption;
    testMenuOption.SetMenuItemResourceName("menuItemResourceName");
    menuOption.emplace_back(testMenuOption);
    customOption.SetMenuOption(menuOption);
    customOption.GetMenuOption(getMenuOption);
    EXPECT_EQ(menuOption.size(), getMenuOption.size());
}

/**
 * @tc.name: PrintCustomOptionTest_009
 * @tc.desc: Verify the hasValue function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_009, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetIsSelect(true);
    EXPECT_TRUE(customOption.HasValue());
}

/**
 * @tc.name: PrintCustomOptionTest_0010
 * @tc.desc: Verify the SetIsSelect and GetIsSelect function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetIsSelect(true);
    EXPECT_TRUE(customOption.GetIsSelect());
}

/**
 * @tc.name: PrintCustomOptionTest_0011
 * @tc.desc: Verify the hasErrorResourceName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0011, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetErrorResourceName("errorResourceName");
    EXPECT_TRUE(customOption.HasErrorResourceName());
}

/**
 * @tc.name: PrintCustomOptionTest_0012
 * @tc.desc: Verify the SetErrorResourceName and GetErrorResourceName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption;
    customOption.SetErrorResourceName("errorResourceName");
    EXPECT_EQ("errorResourceName", customOption.GetErrorResourceName());
}

/**
 * @tc.name: PrintCustomOptionTest_0013
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0013, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption = GetDefaultPrintCustomOption();
    std::vector<PrintMenuOption> menuOption;
    PrintMenuOption testMenuOption;
    testMenuOption.SetMenuItemResourceName("menuItemResourceName");
    menuOption.emplace_back(testMenuOption);
    customOption.SetMenuOption(menuOption);
    customOption.SetErrorResourceName("errorResourceName");
    Parcel parcel;
    EXPECT_TRUE(customOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintCustomOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintCustomOptionTest_0014
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0014, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption = GetDefaultPrintCustomOption();
    customOption.SetIsSelect(true);
    customOption.SetErrorResourceName("errorResourceName");
    Parcel parcel;
    EXPECT_TRUE(customOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintCustomOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintCustomOptionTest_0015
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0015, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption = GetDefaultPrintCustomOption();
    customOption.SetErrorResourceName("errorResourceName");
    Parcel parcel;
    EXPECT_TRUE(customOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintCustomOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintCustomOptionTest_0016
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0016, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption = GetDefaultPrintCustomOption();
    std::vector<PrintMenuOption> menuOption;
    PrintMenuOption testMenuOption;
    testMenuOption.SetMenuItemResourceName("menuItemResourceName");
    menuOption.emplace_back(testMenuOption);
    customOption.SetMenuOption(menuOption);
    Parcel parcel;
    EXPECT_TRUE(customOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintCustomOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintCustomOptionTest_0017
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomOptionTest, PrintCustomOptionTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintCustomOption customOption = GetDefaultPrintCustomOption();
    customOption.SetIsSelect(true);
    Parcel parcel;
    EXPECT_TRUE(customOption.Marshalling(parcel));
    auto result = OHOS::Print::PrintCustomOption::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

}  // namespace Print
}  // namespace OHOS
