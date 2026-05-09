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
#include "print_vendor_options_util.h"
#include "print_json_util.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintVendorOptionsUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void PrintVendorOptionsUtilTest::SetUpTestCase(void) {}

void PrintVendorOptionsUtilTest::TearDownTestCase(void) {}

void PrintVendorOptionsUtilTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintVendorOptionsUtilTest_%{public}d", ++testNo);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_UserPrefixField_ReturnsTrue, TestSize.Level1)
{
    std::string key = "user_username";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_TRUE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_UserPasswordField_ReturnsTrue, TestSize.Level1)
{
    std::string key = "user_password";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_TRUE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_GlobalField_ReturnsFalse, TestSize.Level1)
{
    std::string key = "paperSize";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_EmptyString_ReturnsFalse, TestSize.Level1)
{
    std::string key = "";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_ExactUserPrefix_ReturnsFalse, TestSize.Level1)
{
    std::string key = "user";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, IsUserField_PartialUserPrefix_ReturnsFalse, TestSize.Level1)
{
    std::string key = "use";
    bool result = PrintVendorOptionsUtil::IsUserField(key);
    EXPECT_FALSE(result);
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_NormalSplit_Succeeds, TestSize.Level1)
{
    std::string vendorOptions = "{\"paperSize\":\"A4\",\"user_username\":\"admin\",\"user_password\":\"pass123\"}";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    Json::Value printerJson;
    Json::Value userJson;
    PrintJsonUtil::Parse(printerVendorOptions, printerJson);
    PrintJsonUtil::Parse(userVendorOptions, userJson);

    EXPECT_TRUE(printerJson.isMember("paperSize"));
    EXPECT_FALSE(printerJson.isMember("user_username"));
    EXPECT_FALSE(printerJson.isMember("user_password"));

    EXPECT_TRUE(userJson.isMember("user_username"));
    EXPECT_TRUE(userJson.isMember("user_password"));
    EXPECT_FALSE(userJson.isMember("paperSize"));
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_OnlyGlobalFields_UserOptionsEmpty, TestSize.Level1)
{
    std::string vendorOptions = "{\"paperSize\":\"A4\",\"colorMode\":\"color\",\"duplex\":\"none\"}";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    Json::Value printerJson;
    Json::Value userJson;
    PrintJsonUtil::Parse(printerVendorOptions, printerJson);

    EXPECT_TRUE(printerJson.isMember("paperSize"));
    EXPECT_TRUE(printerJson.isMember("colorMode"));
    EXPECT_TRUE(printerJson.isMember("duplex"));
    EXPECT_TRUE(userVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_OnlyUserFields_PrinterOptionsEmpty, TestSize.Level1)
{
    std::string vendorOptions = "{\"user_username\":\"admin\",\"user_password\":\"pass123\"}";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    Json::Value userJson;
    PrintJsonUtil::Parse(userVendorOptions, userJson);

    EXPECT_TRUE(userJson.isMember("user_username"));
    EXPECT_TRUE(userJson.isMember("user_password"));
    EXPECT_TRUE(printerVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_EmptyInput_BothEmpty, TestSize.Level1)
{
    std::string vendorOptions = "";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    EXPECT_TRUE(printerVendorOptions.empty());
    EXPECT_TRUE(userVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_InvalidJson_PrinterOptionsKeepsOriginal, TestSize.Level1)
{
    std::string vendorOptions = "invalid json";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    EXPECT_EQ(printerVendorOptions, vendorOptions);
    EXPECT_TRUE(userVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_NumericString_PrinterOptionsKeepsOriginal, TestSize.Level1)
{
    std::string vendorOptions = "123";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    EXPECT_EQ(printerVendorOptions, vendorOptions);
    EXPECT_TRUE(userVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitVendorOptions_JsonArray_PrinterOptionsKeepsOriginal, TestSize.Level1)
{
    std::string vendorOptions = "[]";
    std::string printerVendorOptions;
    std::string userVendorOptions;

    PrintVendorOptionsUtil::SplitVendorOptions(vendorOptions, printerVendorOptions, userVendorOptions);

    EXPECT_EQ(printerVendorOptions, vendorOptions);
    EXPECT_TRUE(userVendorOptions.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_NormalMerge_Succeeds, TestSize.Level1)
{
    std::string printerVendorOptions = "{\"paperSize\":\"A4\",\"colorMode\":\"color\"}";
    std::string userVendorOptions = "{\"user_username\":\"admin\",\"user_password\":\"pass123\"}";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_TRUE(mergedJson.isMember("paperSize"));
    EXPECT_TRUE(mergedJson.isMember("colorMode"));
    EXPECT_TRUE(mergedJson.isMember("user_username"));
    EXPECT_TRUE(mergedJson.isMember("user_password"));
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_UserOptionsEmpty_ReturnsPrinterOptions, TestSize.Level1)
{
    std::string printerVendorOptions = "{\"paperSize\":\"A4\"}";
    std::string userVendorOptions = "";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_TRUE(mergedJson.isMember("paperSize"));
    EXPECT_FALSE(mergedJson.isMember("user_username"));
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_PrinterOptionsEmpty_ReturnsUserOptions, TestSize.Level1)
{
    std::string printerVendorOptions = "";
    std::string userVendorOptions = "{\"user_username\":\"admin\"}";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_FALSE(mergedJson.isMember("paperSize"));
    EXPECT_TRUE(mergedJson.isMember("user_username"));
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_BothEmpty_ReturnsEmpty, TestSize.Level1)
{
    std::string printerVendorOptions = "";
    std::string userVendorOptions = "";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    EXPECT_TRUE(merged.empty());
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_InvalidPrinterJson_ReturnsUserOptions, TestSize.Level1)
{
    std::string printerVendorOptions = "invalid";
    std::string userVendorOptions = "{\"user_username\":\"admin\"}";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_TRUE(mergedJson.isMember("user_username"));
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_InvalidUserJson_ReturnsPrinterOptions, TestSize.Level1)
{
    std::string printerVendorOptions = "{\"paperSize\":\"A4\"}";
    std::string userVendorOptions = "invalid";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_TRUE(mergedJson.isMember("paperSize"));
}

HWTEST_F(PrintVendorOptionsUtilTest, MergeVendorOptions_UserFieldOverridesGlobalField, TestSize.Level1)
{
    std::string printerVendorOptions = "{\"paperSize\":\"A4\",\"colorMode\":\"color\"}";
    std::string userVendorOptions = "{\"user_username\":\"admin\",\"paperSize\":\"A5\"}";

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value mergedJson;
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_TRUE(mergedJson.isMember("paperSize"));
    EXPECT_TRUE(mergedJson.isMember("colorMode"));
    EXPECT_TRUE(mergedJson.isMember("user_username"));
    EXPECT_EQ(mergedJson["paperSize"].asString(), "A5");
}

HWTEST_F(PrintVendorOptionsUtilTest, SplitAndMergeRoundTrip_RestoresOriginal, TestSize.Level1)
{
    std::string original = "{\"paperSize\":\"A4\",\"colorMode\":\"color\",\"user_username\":\"admin\",\"user_password\":\"pass123\"}";

    std::string printerVendorOptions;
    std::string userVendorOptions;
    PrintVendorOptionsUtil::SplitVendorOptions(original, printerVendorOptions, userVendorOptions);

    std::string merged = PrintVendorOptionsUtil::MergeVendorOptions(printerVendorOptions, userVendorOptions);

    Json::Value originalJson;
    Json::Value mergedJson;
    PrintJsonUtil::Parse(original, originalJson);
    PrintJsonUtil::Parse(merged, mergedJson);

    EXPECT_EQ(originalJson.getMemberNames().size(), mergedJson.getMemberNames().size());
    for (const auto &key : originalJson.getMemberNames()) {
        EXPECT_TRUE(mergedJson.isMember(key));
        EXPECT_EQ(originalJson[key], mergedJson[key]);
    }
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_MixedFields_ClassifiedCorrectly, TestSize.Level1)
{
    Json::Value vendorJson;
    vendorJson["paperSize"] = "A4";
    vendorJson["copies"] = 3;
    vendorJson["user_username"] = "testuser";
    vendorJson["user_password"] = "testpass";

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.isMember("paperSize"));
    EXPECT_TRUE(printerFields.isMember("copies"));
    EXPECT_FALSE(printerFields.isMember("user_username"));
    EXPECT_FALSE(printerFields.isMember("user_password"));

    EXPECT_FALSE(userFields.isMember("paperSize"));
    EXPECT_FALSE(userFields.isMember("copies"));
    EXPECT_TRUE(userFields.isMember("user_username"));
    EXPECT_TRUE(userFields.isMember("user_password"));

    EXPECT_EQ(printerFields["paperSize"].asString(), "A4");
    EXPECT_EQ(printerFields["copies"].asInt(), 3);
    EXPECT_EQ(userFields["user_username"].asString(), "testuser");
    EXPECT_EQ(userFields["user_password"].asString(), "testpass");
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_OnlyPrinterFields_UserFieldsEmpty, TestSize.Level1)
{
    Json::Value vendorJson;
    vendorJson["paperSize"] = "A4";
    vendorJson["copies"] = 3;
    vendorJson["duplex"] = true;

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.isMember("paperSize"));
    EXPECT_TRUE(printerFields.isMember("copies"));
    EXPECT_TRUE(printerFields.isMember("duplex"));
    EXPECT_EQ(printerFields.getMemberNames().size(), 3);

    EXPECT_TRUE(userFields.empty());
    EXPECT_EQ(userFields.getMemberNames().size(), 0);
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_OnlyUserFields_PrinterFieldsEmpty, TestSize.Level1)
{
    Json::Value vendorJson;
    vendorJson["user_username"] = "testuser";
    vendorJson["user_password"] = "testpass";
    vendorJson["user_preference"] = "dark";

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.empty());
    EXPECT_EQ(printerFields.getMemberNames().size(), 0);

    EXPECT_TRUE(userFields.isMember("user_username"));
    EXPECT_TRUE(userFields.isMember("user_password"));
    EXPECT_TRUE(userFields.isMember("user_preference"));
    EXPECT_EQ(userFields.getMemberNames().size(), 3);
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_EmptyJson_BothFieldsEmpty, TestSize.Level1)
{
    Json::Value vendorJson;
    vendorJson = Json::Value(Json::objectValue);

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.empty());
    EXPECT_TRUE(userFields.empty());
    EXPECT_EQ(printerFields.getMemberNames().size(), 0);
    EXPECT_EQ(userFields.getMemberNames().size(), 0);
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_NestedObjectValues_ClassifiedCorrectly, TestSize.Level1)
{
    Json::Value vendorJson;
    Json::Value printerSettings;
    printerSettings["density"] = 5;
    printerSettings["quality"] = "high";
    vendorJson["settings"] = printerSettings;

    Json::Value userSettings;
    userSettings["theme"] = "dark";
    userSettings["language"] = "en";
    vendorJson["user_settings"] = userSettings;

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.isMember("settings"));
    EXPECT_FALSE(printerFields.isMember("user_settings"));

    EXPECT_FALSE(userFields.isMember("settings"));
    EXPECT_TRUE(userFields.isMember("user_settings"));

    EXPECT_TRUE(printerFields["settings"].isObject());
    EXPECT_TRUE(userFields["user_settings"].isObject());
    EXPECT_EQ(printerFields["settings"]["density"].asInt(), 5);
    EXPECT_EQ(userFields["user_settings"]["theme"].asString(), "dark");
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_ArrayValues_ClassifiedCorrectly, TestSize.Level1)
{
    Json::Value vendorJson;
    Json::Value papers;
    papers.append("A4");
    papers.append("A5");
    papers.append("Letter");
    vendorJson["supportedPapers"] = papers;

    Json::Value userPapers;
    userPapers.append("user_A4");
    userPapers.append("user_A5");
    vendorJson["user_favoritePapers"] = userPapers;

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_TRUE(printerFields.isMember("supportedPapers"));
    EXPECT_FALSE(printerFields.isMember("user_favoritePapers"));

    EXPECT_FALSE(userFields.isMember("supportedPapers"));
    EXPECT_TRUE(userFields.isMember("user_favoritePapers"));

    EXPECT_TRUE(printerFields["supportedPapers"].isArray());
    EXPECT_TRUE(userFields["user_favoritePapers"].isArray());
    EXPECT_EQ(printerFields["supportedPapers"].size(), 3);
    EXPECT_EQ(userFields["user_favoritePapers"].size(), 2);
}
HWTEST_F(PrintVendorOptionsUtilTest, ClassifyFields_SpecialKeyNames_ClassifiedCorrectly, TestSize.Level1)
{
    Json::Value vendorJson;
    vendorJson["user_"] = "exact_user_prefix";
    vendorJson["user_123"] = "user_numeric_suffix";
    vendorJson["printer.user"] = "printer_with_user_keyword";
    vendorJson["user_username"] = "uppercase_user";

    Json::Value printerFields;
    Json::Value userFields;
    PrintVendorOptionsUtil::ClassifyFields(vendorJson, printerFields, userFields);

    EXPECT_FALSE(printerFields.isMember("user_"));
    EXPECT_FALSE(printerFields.isMember("user_123"));
    EXPECT_TRUE(printerFields.isMember("printer.user"));
    EXPECT_TRUE(printerFields.isMember("user_username"));

    EXPECT_TRUE(userFields.isMember("user_"));
    EXPECT_TRUE(userFields.isMember("user_123"));
    EXPECT_FALSE(userFields.isMember("printer.user"));
    EXPECT_FALSE(userFields.isMember("user_username"));
}

}  // namespace Print
}  // namespace OHOS