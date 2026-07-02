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
#include "iservice_registry.h"
#define private public
#include "print_utils.h"
#undef private
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "print_json_util.h"
#include "json/reader.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintUtilsExtTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintUtilsExtTest::SetUpTestCase(void) {}
void PrintUtilsExtTest::TearDownTestCase(void) {}

// ==================== ExtractIpv4 Test ====================
/**
 * @tc.name: ExtractIpv4_001
 * @tc.desc: Verify ExtractIpv4 with valid IPv4 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv4_001, TestSize.Level2)
{
    std::string str = "ipp://192.168.1.100:631/ipp/print";
    std::string ip;
    size_t startPos;
    EXPECT_TRUE(PrintUtils::ExtractIpv4(str, ip, startPos));
    EXPECT_EQ(ip, "192.168.1.100");
    EXPECT_EQ(startPos, 6);
}

/**
 * @tc.name: ExtractIpv4_002
 * @tc.desc: Verify ExtractIpv4 with no IPv4 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv4_002, TestSize.Level2)
{
    std::string str = "ipp://localhost:631/ipp/print";
    std::string ip;
    size_t startPos;
    EXPECT_FALSE(PrintUtils::ExtractIpv4(str, ip, startPos));
}

/**
 * @tc.name: ExtractIpv4_003
 * @tc.desc: Verify ExtractIpv4 with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv4_003, TestSize.Level2)
{
    std::string str = "";
    std::string ip;
    size_t startPos;
    EXPECT_FALSE(PrintUtils::ExtractIpv4(str, ip, startPos));
}

/**
 * @tc.name: ExtractIpv4_004
 * @tc.desc: Verify ExtractIpv4 with multiple IPv4 addresses.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv4_004, TestSize.Level2)
{
    std::string str = "192.168.1.1 and 10.0.0.1";
    std::string ip;
    size_t startPos;
    EXPECT_TRUE(PrintUtils::ExtractIpv4(str, ip, startPos));
    EXPECT_EQ(ip, "192.168.1.1");
    EXPECT_EQ(startPos, 0);
}

// ==================== ExtractIpv6 Test ====================
/**
 * @tc.name: ExtractIpv6_001
 * @tc.desc: Verify ExtractIpv6 with valid IPv6 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv6_001, TestSize.Level2)
{
    std::string str = "ipp://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:631/ipp/print";
    std::string ip;
    size_t startPos;
    EXPECT_TRUE(PrintUtils::ExtractIpv6(str, ip, startPos));
    EXPECT_EQ(ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

/**
 * @tc.name: ExtractIpv6_002
 * @tc.desc: Verify ExtractIpv6 with no IPv6 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv6_002, TestSize.Level2)
{
    std::string str = "ipp://192.168.1.1:631/ipp/print";
    std::string ip;
    size_t startPos;
    EXPECT_FALSE(PrintUtils::ExtractIpv6(str, ip, startPos));
}

/**
 * @tc.name: ExtractIpv6_003
 * @tc.desc: Verify ExtractIpv6 with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractIpv6_003, TestSize.Level2)
{
    std::string str = "";
    std::string ip;
    size_t startPos;
    EXPECT_FALSE(PrintUtils::ExtractIpv6(str, ip, startPos));
}

// ==================== AnonymizeIpv4 Test ====================
/**
 * @tc.name: AnonymizeIpv4_001
 * @tc.desc: Verify AnonymizeIpv4 with valid IPv4 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv4_001, TestSize.Level2)
{
    std::string ip = "192.168.1.100";
    std::string result = PrintUtils::AnonymizeIpv4(ip);
    EXPECT_EQ(result, "192.168.1.xxx");
}

/**
 * @tc.name: AnonymizeIpv4_002
 * @tc.desc: Verify AnonymizeIpv4 with no dot.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv4_002, TestSize.Level2)
{
    std::string ip = "1921681100";
    std::string result = PrintUtils::AnonymizeIpv4(ip);
    EXPECT_EQ(result, ip);
}

/**
 * @tc.name: AnonymizeIpv4_003
 * @tc.desc: Verify AnonymizeIpv4 with different valid addresses.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv4_003, TestSize.Level2)
{
    EXPECT_EQ(PrintUtils::AnonymizeIpv4("10.0.0.1"), "10.0.0.xxx");
    EXPECT_EQ(PrintUtils::AnonymizeIpv4("172.16.254.1"), "172.16.254.xxx");
    EXPECT_EQ(PrintUtils::AnonymizeIpv4("255.255.255.255"), "255.255.255.xxx");
}

/**
 * @tc.name: AnonymizeIpv4_004
 * @tc.desc: Verify AnonymizeIpv4 with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv4_004, TestSize.Level2)
{
    std::string ip = "";
    std::string result = PrintUtils::AnonymizeIpv4(ip);
    EXPECT_EQ(result, "");
}

// ==================== AnonymizeIpv6 Test ====================
/**
 * @tc.name: AnonymizeIpv6_001
 * @tc.desc: Verify AnonymizeIpv6 with valid IPv6 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv6_001, TestSize.Level2)
{
    std::string ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    std::string result = PrintUtils::AnonymizeIpv6(ip);
    EXPECT_TRUE(result.find("2001:0db8:") == 0);
    EXPECT_TRUE(result.find("xxxx") != std::string::npos);
}

/**
 * @tc.name: AnonymizeIpv6_002
 * @tc.desc: Verify AnonymizeIpv6 with no colon.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv6_002, TestSize.Level2)
{
    std::string ip = "20010db885a3";
    std::string result = PrintUtils::AnonymizeIpv6(ip);
    EXPECT_EQ(result, ip);
}

/**
 * @tc.name: AnonymizeIpv6_003
 * @tc.desc: Verify AnonymizeIpv6 with only one colon.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv6_003, TestSize.Level2)
{
    std::string ip = "2001:0db8";
    std::string result = PrintUtils::AnonymizeIpv6(ip);
    EXPECT_EQ(result, ip);
}

/**
 * @tc.name: AnonymizeIpv6_004
 * @tc.desc: Verify AnonymizeIpv6 with only two colons.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv6_004, TestSize.Level2)
{
    std::string ip = "2001:0db8:85a3";
    std::string result = PrintUtils::AnonymizeIpv6(ip);
    EXPECT_EQ(result, ip);
}

/**
 * @tc.name: AnonymizeIpv6_005
 * @tc.desc: Verify AnonymizeIpv6 with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIpv6_005, TestSize.Level2)
{
    std::string ip = "";
    std::string result = PrintUtils::AnonymizeIpv6(ip);
    EXPECT_EQ(result, "");
}

// ==================== AnonymizeUUid Test ====================
/**
 * @tc.name: AnonymizeUUid_002
 * @tc.desc: Verify AnonymizeUUid with no dash.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeUUid_002, TestSize.Level2)
{
    std::string uuid = "550e8400e29b41d4a716446655440000";
    std::string result = PrintUtils::AnonymizeUUid(uuid);
    EXPECT_EQ(result, uuid);
}

/**
 * @tc.name: AnonymizeUUid_003
 * @tc.desc: Verify AnonymizeUUid with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeUUid_003, TestSize.Level2)
{
    std::string uuid = "";
    std::string result = PrintUtils::AnonymizeUUid(uuid);
    EXPECT_EQ(result, "");
}

// ==================== AnonymizePrinterId Test ====================
/**
 * @tc.name: AnonymizePrinterId_001
 * @tc.desc: Verify AnonymizePrinterId with UUID format.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizePrinterId_001, TestSize.Level2)
{
    std::string printerId = "com.sample.ext:550e8400-e29b-41d4-a716-446655440000";
    std::string result = PrintUtils::AnonymizePrinterId(printerId);
    EXPECT_TRUE(result.find("x") != std::string::npos);
}

/**
 * @tc.name: AnonymizePrinterId_003
 * @tc.desc: Verify AnonymizePrinterId with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizePrinterId_003, TestSize.Level2)
{
    std::string printerId = "";
    std::string result = PrintUtils::AnonymizePrinterId(printerId);
    EXPECT_EQ(result, "");
}

// ==================== AnonymizePrinterUri Test ====================
struct AnonymizePrinterUriTestParam {
    std::string inputUri;
    std::string expectedResult;
};

class AnonymizePrinterUriTest : public testing::TestWithParam<AnonymizePrinterUriTestParam> {};

/**
 * @tc.name: AnonymizePrinterUri
 * @tc.desc: Verify AnonymizePrinterUri with various URI formats.
 * @tc.type: FUNC
 */
HWTEST_P(AnonymizePrinterUriTest, AnonymizePrinterUri, TestSize.Level2)
{
    AnonymizePrinterUriTestParam param = GetParam();
    std::string result = PrintUtils::AnonymizePrinterUri(param.inputUri);
    EXPECT_EQ(result, param.expectedResult);
}

INSTANTIATE_TEST_SUITE_P(AnonymizePrinterUriCases, AnonymizePrinterUriTest, testing::Values(
    AnonymizePrinterUriTestParam{"123456789abc", "************"},
    AnonymizePrinterUriTestParam{"", ""},
    AnonymizePrinterUriTestParam{"ipp://49.4.22.46:16631/ipp/print", "ipp://49.4.22.xxx:16631/ipp/print"},
    AnonymizePrinterUriTestParam{"ipp://192.168.1.100:631/ipp/print", "ipp://192.168.1.100:631/ipp/print"},
    AnonymizePrinterUriTestParam{"ipp://[2001:0db8:85a3:0000:0000:0000:0000:0000]:631/print",
        "ipp://[2001:0db8:85xx:xxxx:xxxx:xxxx:xxxx:xxxx]:631/print"},
    AnonymizePrinterUriTestParam{"ipp://localhost:631/ipp/print", "ipp://localhost:631/ipp/print"}
));

// ==================== AnonymizeIp Test ====================
/**
 * @tc.name: AnonymizeIp_001
 * @tc.desc: Verify AnonymizeIp with IPv4 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIp_001, TestSize.Level2)
{
    std::string ip = "192.168.1.100";
    std::string result = PrintUtils::AnonymizeIp(ip);
    EXPECT_EQ(result, "192.168.1.xxx");
}

/**
 * @tc.name: AnonymizeIp_002
 * @tc.desc: Verify AnonymizeIp with IPv6 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIp_002, TestSize.Level2)
{
    std::string ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    std::string result = PrintUtils::AnonymizeIp(ip);
    EXPECT_TRUE(result.find("2001:0db8:") == 0);
}

/**
 * @tc.name: AnonymizeIp_003
 * @tc.desc: Verify AnonymizeIp with neither IPv4 nor IPv6.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIp_003, TestSize.Level2)
{
    std::string ip = "localhost";
    std::string result = PrintUtils::AnonymizeIp(ip);
    EXPECT_EQ(result, ip);
}

/**
 * @tc.name: AnonymizeIp_004
 * @tc.desc: Verify AnonymizeIp with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeIp_004, TestSize.Level2)
{
    std::string ip = "";
    std::string result = PrintUtils::AnonymizeIp(ip);
    EXPECT_EQ(result, "");
}

// ==================== IsPrivateIpv4 Test ====================
struct IsPrivateIpv4TestParam {
    std::string ip;
    bool expected;
};

class IsPrivateIpv4Test : public testing::TestWithParam<IsPrivateIpv4TestParam> {};

/**
 * @tc.name: IsPrivateIpv4
 * @tc.desc: Verify IsPrivateIpv4 with various IP addresses.
 * @tc.type: FUNC
 */
HWTEST_P(IsPrivateIpv4Test, IsPrivateIpv4, TestSize.Level2)
{
    IsPrivateIpv4TestParam param = GetParam();
    bool result = PrintUtils::IsPrivateIpv4(param.ip);
    EXPECT_EQ(result, param.expected);
}

INSTANTIATE_TEST_SUITE_P(IsPrivateIpv4Cases, IsPrivateIpv4Test, testing::Values(
    IsPrivateIpv4TestParam{"", false},
    IsPrivateIpv4TestParam{"10.0", false},
    IsPrivateIpv4TestParam{"123a.123.0.1", false},
    IsPrivateIpv4TestParam{"a123.123.0.1", false},
    IsPrivateIpv4TestParam{"123.a123.0.1", false},
    IsPrivateIpv4TestParam{"123.123a.0.1", false},
    IsPrivateIpv4TestParam{"8.8.8.8", false},
    IsPrivateIpv4TestParam{"10.0.0.1", true},
    IsPrivateIpv4TestParam{"10.255.255.255", true},
    IsPrivateIpv4TestParam{"172.15.255.255", false},
    IsPrivateIpv4TestParam{"172.16.0.1", true},
    IsPrivateIpv4TestParam{"172.31.255.255", true},
    IsPrivateIpv4TestParam{"172.32.0.1", false},
    IsPrivateIpv4TestParam{"192.167.255.255", false},
    IsPrivateIpv4TestParam{"192.168.0.1", true}
));

// ==================== AnonymizeJobOption Test ====================
struct AnonymizeJobOptionTestParam {
    std::string inputOption;
    std::string expectedResult;
};

class AnonymizeJobOptionTest : public testing::TestWithParam<AnonymizeJobOptionTestParam> {};

/**
 * @tc.name: AnonymizeJobOption
 * @tc.desc: Verify AnonymizeJobOption with various options.
 * @tc.type: FUNC
 */
HWTEST_P(AnonymizeJobOptionTest, AnonymizeJobOption, TestSize.Level2)
{
    AnonymizeJobOptionTestParam param = GetParam();
    std::string result = PrintUtils::AnonymizeJobOption(param.inputOption);
    EXPECT_EQ(result, param.expectedResult);
}

INSTANTIATE_TEST_SUITE_P(AnonymizeJobOptionCases, AnonymizeJobOptionTest, testing::Values(
    AnonymizeJobOptionTestParam{"invalid json", ""},
    AnonymizeJobOptionTestParam{"", ""},
    AnonymizeJobOptionTestParam{R"({"jobName":"test.pdf"})", R"({"jobName":"xxx.pdf"})"},
    AnonymizeJobOptionTestParam{R"({"jobDesArr":["test.pdf","0","1"]})", R"({"jobDesArr":["xxx.pdf","0","1"]})"},
    AnonymizeJobOptionTestParam{R"({"jobDesArr":[]})", R"({"jobDesArr":""})"},
    AnonymizeJobOptionTestParam{R"({"jobDesArr":[123]})", R"({"jobDesArr":""})"},
    AnonymizeJobOptionTestParam{R"({"printerId":"com.ext:550e8400-e29b-41d4-a716-446655440000"})",
        R"({"printerId":"com.ext:550e8400-e29b-41d4-a716-x"})"},
    AnonymizeJobOptionTestParam{R"({"printerUri":"ipp://49.4.22.46:16631/ipp/printers"})",
        R"({"printerUri":"ipp://49.4.22.xxx:16631/ipp/printers"})"}
));

// ==================== AnonymizeAlias Test ====================
struct AnonymizeAliasTestParam {
    std::string inputAlias;
    std::string expectedResult;
};

class AnonymizeAliasTest : public testing::TestWithParam<AnonymizeAliasTestParam> {};

/**
 * @tc.name: AnonymizeAlias
 * @tc.desc: Verify AnonymizeAlias with various alias.
 * @tc.type: FUNC
 */
HWTEST_P(AnonymizeAliasTest, AnonymizeAlias, TestSize.Level2)
{
    AnonymizeAliasTestParam param = GetParam();
    Json::Value optionJson;
    optionJson["alias"] = param.inputAlias;
    PrintUtils::AnonymizeAlias(optionJson);
    EXPECT_EQ(optionJson["alias"].asString(), param.expectedResult);
}

INSTANTIATE_TEST_SUITE_P(AnonymizeAliasCases, AnonymizeAliasTest, testing::Values(
    AnonymizeAliasTestParam{"test001", "testxxx"},
    AnonymizeAliasTestParam{"ab", "xxx"},
    AnonymizeAliasTestParam{"abc", "xxx"}
));

// ==================== AnonymizeFileArray Test ====================
struct AnonymizeFileArrayTestParam {
    std::string key;
    std::vector<std::string> inputFiles;
    std::vector<std::string> expectedFiles;
    bool isExceedLimit;
};

class AnonymizeFileArrayTest : public testing::TestWithParam<AnonymizeFileArrayTestParam> {};
/**
 * @tc.name: AnonymizeFileArray
 * @tc.desc: Verify AnonymizeFileArray with various file array.
 * @tc.type: FUNC
 */
HWTEST_P(AnonymizeFileArrayTest, AnonymizeFileArray, TestSize.Level2)
{
    AnonymizeFileArrayTestParam param = GetParam();
    Json::Value optionJson;
    Json::Value filesArr(Json::arrayValue);
    for (const auto& file : param.inputFiles) {
        filesArr.append(file);
    }
    optionJson[param.key] = filesArr;
    PrintUtils::AnonymizeFileArray(optionJson, param.key);
    if (param.isExceedLimit) {
        EXPECT_FALSE(optionJson.isMember(param.key));
    } else {
        Json::Value resultArr = optionJson[param.key];
        EXPECT_EQ(resultArr.size(), static_cast<Json::UInt>(param.expectedFiles.size()));
        for (size_t i = 0; i < param.expectedFiles.size(); i++) {
            EXPECT_EQ(resultArr[static_cast<Json::ArrayIndex>(i)].asString(), param.expectedFiles[i]);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(AnonymizeFileArrayTestCases, AnonymizeFileArrayTest, testing::Values(
    AnonymizeFileArrayTestParam{"files", {"/data/test/file.pdf"}, {"/xxx/xxx.pdf"}, false},
    AnonymizeFileArrayTestParam{"files", {"/data/test/doc.pdf", "/data/test/img.jpg"},
        {"/xxx/xxx.pdf", "/xxx/xxx.jpg"}, false},
    AnonymizeFileArrayTestParam{"fileList", {"/data/test/file.pdf"}, {"/xxx/xxx.pdf"}, false}
));

// ==================== AnonymizeJobName Test ====================
/**
 * @tc.name: AnonymizeJobName_001
 * @tc.desc: Verify AnonymizeJobName with extension.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeJobName_001, TestSize.Level2)
{
    std::string jobName = "document.pdf";
    std::string result = PrintUtils::AnonymizeJobName(jobName);
    EXPECT_EQ(result, "xxx.pdf");
}

/**
 * @tc.name: AnonymizeJobName_002
 * @tc.desc: Verify AnonymizeJobName without extension.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeJobName_002, TestSize.Level2)
{
    std::string jobName = "document";
    std::string result = PrintUtils::AnonymizeJobName(jobName);
    EXPECT_EQ(result, "xxx");
}

/**
 * @tc.name: AnonymizeJobName_003
 * @tc.desc: Verify AnonymizeJobName with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeJobName_003, TestSize.Level2)
{
    std::string jobName = "";
    std::string result = PrintUtils::AnonymizeJobName(jobName);
    EXPECT_EQ(result, "xxx");
}

/**
 * @tc.name: AnonymizeJobName_004
 * @tc.desc: Verify AnonymizeJobName with multiple dots.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, AnonymizeJobName_004, TestSize.Level2)
{
    std::string jobName = "my.document.final.pdf";
    std::string result = PrintUtils::AnonymizeJobName(jobName);
    EXPECT_EQ(result, "xxx.pdf");
}

// ==================== GetEventTypeWithToken Test ====================
/**
 * @tc.name: GetEventTypeWithToken_001
 * @tc.desc: Verify GetEventTypeWithToken with valid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventTypeWithToken_001, TestSize.Level2)
{
    std::string result = PrintUtils::GetEventTypeWithToken(100, 12345, "test_type");
    EXPECT_TRUE(result.find("100") != std::string::npos);
    EXPECT_TRUE(result.find("12345") != std::string::npos);
    EXPECT_TRUE(result.find("test_type") != std::string::npos);
}

/**
 * @tc.name: GetEventTypeWithToken_002
 * @tc.desc: Verify GetEventTypeWithToken with zero userId.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventTypeWithToken_002, TestSize.Level2)
{
    std::string result = PrintUtils::GetEventTypeWithToken(0, 1, "type");
    EXPECT_TRUE(result.find("0") != std::string::npos);
}

/**
 * @tc.name: GetEventTypeWithToken_003
 * @tc.desc: Verify GetEventTypeWithToken with empty type.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventTypeWithToken_003, TestSize.Level2)
{
    std::string result = PrintUtils::GetEventTypeWithToken(100, 12345, "");
    EXPECT_TRUE(result.find("100") != std::string::npos);
}

// ==================== GetEventType Test ====================
/**
 * @tc.name: GetEventType_001
 * @tc.desc: Verify GetEventType with valid type string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventType_001, TestSize.Level2)
{
    std::string type = "block-1234";
    std::string result = PrintUtils::GetEventType(type);
    EXPECT_EQ(result, "1234");
}

/**
 * @tc.name: GetEventType_002
 * @tc.desc: Verify GetEventType without delimiter.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventType_002, TestSize.Level2)
{
    std::string type = "block1234";
    std::string result = PrintUtils::GetEventType(type);
    EXPECT_EQ(result, type);
}

/**
 * @tc.name: GetEventType_003
 * @tc.desc: Verify GetEventType with delimiter at end.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventType_003, TestSize.Level2)
{
    std::string type = "block-";
    std::string result = PrintUtils::GetEventType(type);
    EXPECT_EQ(result, type);
}

/**
 * @tc.name: GetEventType_004
 * @tc.desc: Verify GetEventType with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetEventType_004, TestSize.Level2)
{
    std::string type = "";
    std::string result = PrintUtils::GetEventType(type);
    EXPECT_EQ(result, "");
}

// ==================== GetBundleName Test ====================
/**
 * @tc.name: GetBundleName_001
 * @tc.desc: Verify GetBundleName with valid printerId.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetBundleName_001, TestSize.Level2)
{
    std::string printerId = "com.sample.ext:printer-001";
    std::string result = PrintUtils::GetBundleName(printerId);
    EXPECT_EQ(result, "com.sample.ext");
}

/**
 * @tc.name: GetBundleName_002
 * @tc.desc: Verify GetBundleName without delimiter.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetBundleName_002, TestSize.Level2)
{
    std::string printerId = "com.sample.ext";
    std::string result = PrintUtils::GetBundleName(printerId);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetBundleName_003
 * @tc.desc: Verify GetBundleName with delimiter at end.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetBundleName_003, TestSize.Level2)
{
    std::string printerId = "com.sample.ext:";
    std::string result = PrintUtils::GetBundleName(printerId);
    EXPECT_EQ(result, "com.sample.ext");
}

/**
 * @tc.name: GetBundleName_004
 * @tc.desc: Verify GetBundleName with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetBundleName_004, TestSize.Level2)
{
    std::string printerId = "";
    std::string result = PrintUtils::GetBundleName(printerId);
    EXPECT_EQ(result, "");
}

// ==================== ExtractHostFromUri Test ====================
/**
 * @tc.name: ExtractHostFromUri_001
 * @tc.desc: Verify ExtractHostFromUri with IPv4 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_001, TestSize.Level2)
{
    std::string uri = "ipp://192.168.1.100:631/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "192.168.1.100");
}

/**
 * @tc.name: ExtractHostFromUri_002
 * @tc.desc: Verify ExtractHostFromUri with IPv6 address.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_002, TestSize.Level2)
{
    std::string uri = "ipp://[2001:db8::1]:631/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "2001:db8::1");
}

/**
 * @tc.name: ExtractHostFromUri_003
 * @tc.desc: Verify ExtractHostFromUri with hostname.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_003, TestSize.Level2)
{
    std::string uri = "ipp://printer.example.com:631/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "printer.example.com");
}

/**
 * @tc.name: ExtractHostFromUri_004
 * @tc.desc: Verify ExtractHostFromUri without scheme.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_004, TestSize.Level2)
{
    std::string uri = "192.168.1.100:631/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: ExtractHostFromUri_005
 * @tc.desc: Verify ExtractHostFromUri with userinfo.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_005, TestSize.Level2)
{
    std::string uri = "ipp://user:pass@192.168.1.100:631/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "192.168.1.100");
}

/**
 * @tc.name: ExtractHostFromUri_006
 * @tc.desc: Verify ExtractHostFromUri with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_006, TestSize.Level2)
{
    std::string uri = "";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: ExtractHostFromUri_007
 * @tc.desc: Verify ExtractHostFromUri without port.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ExtractHostFromUri_007, TestSize.Level2)
{
    std::string uri = "ipp://192.168.1.100/ipp/print";
    std::string result = PrintUtils::ExtractHostFromUri(uri);
    EXPECT_EQ(result, "192.168.1.100");
}

// ==================== GetPrintJobId Test ====================
/**
 * @tc.name: GetPrintJobId_001
 * @tc.desc: Verify GetPrintJobId returns non-empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetPrintJobId_001, TestSize.Level2)
{
    std::string result = PrintUtils::GetPrintJobId();
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("_") != std::string::npos);
}

/**
 * @tc.name: GetPrintJobId_002
 * @tc.desc: Verify GetPrintJobId returns unique IDs.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetPrintJobId_002, TestSize.Level2)
{
    std::string id1 = PrintUtils::GetPrintJobId();
    std::string id2 = PrintUtils::GetPrintJobId();
    EXPECT_NE(id1, id2);
}

// ==================== GetJobStateChar Extended Tests ====================
/**
 * @tc.name: GetJobStateChar_003
 * @tc.desc: Verify GetJobStateChar with all job states.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, GetJobStateChar_003, TestSize.Level2)
{
    EXPECT_EQ(PrintUtils::GetJobStateChar(PRINT_JOB_QUEUED), "PRINT_JOB_QUEUED");
    EXPECT_EQ(PrintUtils::GetJobStateChar(PRINT_JOB_RUNNING), "PRINT_JOB_RUNNING");
    EXPECT_EQ(PrintUtils::GetJobStateChar(PRINT_JOB_BLOCKED), "PRINT_JOB_BLOCKED");
    EXPECT_EQ(PrintUtils::GetJobStateChar(PRINT_JOB_COMPLETED), "PRINT_JOB_COMPLETED");
    EXPECT_EQ(PrintUtils::GetJobStateChar(PRINT_JOB_CREATE_FILE_COMPLETED), "PRINT_JOB_CREATE_FILE_COMPLETED");
}

// ==================== DecodeExtensionCid Extended Tests ====================
/**
 * @tc.name: DecodeExtensionCid_003
 * @tc.desc: Verify DecodeExtensionCid with invalid callbackId.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, DecodeExtensionCid_003, TestSize.Level2)
{
    std::string cid = "com.sample.ext:abc";
    std::string extensionId;
    uint32_t callbackId;
    EXPECT_FALSE(PrintUtils::DecodeExtensionCid(cid, extensionId, callbackId));
}

/**
 * @tc.name: DecodeExtensionCid_004
 * @tc.desc: Verify DecodeExtensionCid with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, DecodeExtensionCid_004, TestSize.Level2)
{
    std::string cid = "";
    std::string extensionId;
    uint32_t callbackId;
    EXPECT_FALSE(PrintUtils::DecodeExtensionCid(cid, extensionId, callbackId));
}

// ==================== ToLower Extended Tests ====================
/**
 * @tc.name: ToLower_002
 * @tc.desc: Verify ToLower with mixed case string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ToLower_002, TestSize.Level2)
{
    std::string result = PrintUtils::ToLower("HeLLo WoRLd");
    EXPECT_EQ(result, "hello world");
}

/**
 * @tc.name: ToLower_003
 * @tc.desc: Verify ToLower with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ToLower_003, TestSize.Level2)
{
    std::string result = PrintUtils::ToLower("");
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: ToLower_004
 * @tc.desc: Verify ToLower with already lowercase string.
 * @tc.type: FUNC
 */
HWTEST_F(PrintUtilsExtTest, ToLower_004, TestSize.Level2)
{
    std::string result = PrintUtils::ToLower("already lowercase");
    EXPECT_EQ(result, "already lowercase");
}

}  // namespace Print
}  // namespace OHOS
