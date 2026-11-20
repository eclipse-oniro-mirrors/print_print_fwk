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
#include <string>
#include <vector>
#include "print_custom_page_size_util.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_page_size.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintCustomPageSizeUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintCustomPageSizeUtilTest::SetUpTestCase(void)
{}

void PrintCustomPageSizeUtilTest::TearDownTestCase(void)
{}

// ===== UpdateOptionWithCustomPageSizes decision table =====
// C1 = hasValidOption, C2 = userPrefs.HasCustomPageSizes()
// A1 = inject customPageSizeList into opsJson, A2 = SetOption write-back on printerPreference

/**
 * @tc.name: PrintCustomPageSizeUtilTest_UpdateOption_001
 * @tc.desc: C1=true C2=true -> A1+A2, list injected and pre-existing member preserved in write-back.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomPageSizeUtilTest, PrintCustomPageSizeUtilTest_UpdateOption_001, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> sizes;
    sizes.emplace_back("custom:t1_001", "FormT1(210x297mm)", 210, 297);
    userPrefs.SetCustomPageSizes(sizes);
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);
    opsJson["media"] = "ISO_A4";

    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, true);

    ASSERT_TRUE(opsJson.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    ASSERT_EQ(opsJson[CUSTOM_PAGE_SIZE_LIST_KEY].size(), 1U);
    EXPECT_EQ(opsJson[CUSTOM_PAGE_SIZE_LIST_KEY][0]["id"].asString(), "custom:t1_001");
    Json::Value resultOption;
    EXPECT_TRUE(PrintJsonUtil::Parse(pref.GetOption(), resultOption));
    EXPECT_TRUE(resultOption.isMember("media"));
    EXPECT_TRUE(resultOption.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
}

/**
 * @tc.name: PrintCustomPageSizeUtilTest_UpdateOption_002
 * @tc.desc: C1=false C2=true -> A1+A2, list injected even when stored option was invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomPageSizeUtilTest, PrintCustomPageSizeUtilTest_UpdateOption_002, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> sizes;
    sizes.emplace_back("custom:t2_001", "FormT2(100x200mm)", 100, 200);
    userPrefs.SetCustomPageSizes(sizes);
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);

    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, false);

    Json::Value resultOption;
    EXPECT_TRUE(PrintJsonUtil::Parse(pref.GetOption(), resultOption));
    ASSERT_TRUE(resultOption.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    ASSERT_EQ(resultOption[CUSTOM_PAGE_SIZE_LIST_KEY].size(), 1U);
    EXPECT_EQ(resultOption[CUSTOM_PAGE_SIZE_LIST_KEY][0]["id"].asString(), "custom:t2_001");
}

/**
 * @tc.name: PrintCustomPageSizeUtilTest_UpdateOption_003
 * @tc.desc: C1=true C2=false -> A2 only, option rewritten without customPageSizeList member.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomPageSizeUtilTest, PrintCustomPageSizeUtilTest_UpdateOption_003, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);
    opsJson["media"] = "ISO_A4";

    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, true);

    EXPECT_FALSE(opsJson.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    Json::Value resultOption;
    EXPECT_TRUE(PrintJsonUtil::Parse(pref.GetOption(), resultOption));
    EXPECT_TRUE(resultOption.isMember("media"));
    EXPECT_FALSE(resultOption.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
}

/**
 * @tc.name: PrintCustomPageSizeUtilTest_UpdateOption_004
 * @tc.desc: C1=false C2=false -> neither A1 nor A2, option stays empty (no "{}" written).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomPageSizeUtilTest, PrintCustomPageSizeUtilTest_UpdateOption_004, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);

    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, false);

    EXPECT_FALSE(opsJson.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    EXPECT_TRUE(pref.GetOption().empty());
}

/**
 * @tc.name: PrintCustomPageSizeUtilTest_UpdateOption_005
 * @tc.desc: Multiple custom page sizes are serialized in order with id/name/width/height fidelity.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintCustomPageSizeUtilTest, PrintCustomPageSizeUtilTest_UpdateOption_005, TestSize.Level1)
{
    PrinterUserPreferences userPrefs;
    std::vector<PrintPageSize> sizes;
    sizes.emplace_back("custom:t5_001", "FormA(210x297mm)", 210, 297);
    sizes.emplace_back("custom:t5_002", "FormB(148x210mm)", 148, 210);
    userPrefs.SetCustomPageSizes(sizes);
    PrinterPreferences pref;
    Json::Value opsJson(Json::objectValue);

    PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(userPrefs, pref, opsJson, false);

    ASSERT_TRUE(opsJson.isMember(CUSTOM_PAGE_SIZE_LIST_KEY));
    const Json::Value &list = opsJson[CUSTOM_PAGE_SIZE_LIST_KEY];
    ASSERT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0]["id"].asString(), "custom:t5_001");
    EXPECT_EQ(list[0]["name"].asString(), "FormA(210x297mm)");
    EXPECT_EQ(list[0]["width"].asUInt(), 210U);
    EXPECT_EQ(list[0]["height"].asUInt(), 297U);
    EXPECT_EQ(list[1]["id"].asString(), "custom:t5_002");
    EXPECT_EQ(list[1]["name"].asString(), "FormB(148x210mm)");
    EXPECT_EQ(list[1]["width"].asUInt(), 148U);
    EXPECT_EQ(list[1]["height"].asUInt(), 210U);
}
}  // namespace Print
}  // namespace OHOS
