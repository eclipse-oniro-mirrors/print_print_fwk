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
#include "ppd_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PpdInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PpdInfoTest::SetUpTestCase(void)
{}

void PpdInfoTest::TearDownTestCase(void)
{}

HWTEST_F(PpdInfoTest, SetAttributeTest, TestSize.Level1)
{
    PpdInfo info;
    info.SetManufacturer("TestManu");
    EXPECT_EQ(info.GetManufacturer(), "TestManu");
    info.SetNickName("TestNick");
    EXPECT_EQ(info.GetNickName(), "TestNick");
    info.SetPpdName("Test.ppd");
    EXPECT_EQ(info.GetPpdName(), "Test.ppd");
    info.SetPpdInfo("Test2", "Nick2", "2.ppd");
    EXPECT_EQ(info.GetManufacturer(), "Test2");
    EXPECT_EQ(info.GetNickName(), "Nick2");
    EXPECT_EQ(info.GetPpdName(), "2.ppd");
    PpdInfo newInfo(info);
    EXPECT_EQ(newInfo.GetManufacturer(), "Test2");
    EXPECT_EQ(newInfo.GetNickName(), "Nick2");
    EXPECT_EQ(newInfo.GetPpdName(), "2.ppd");
}

HWTEST_F(PpdInfoTest, MarshallingAndUnmarshalling_Test, TestSize.Level1)
{
    OHOS::Print::PpdInfo info;
    info.SetPpdInfo("TestManu", "TestNick", "Test.ppd");
    Parcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    auto catchInfo = PpdInfo::Unmarshalling(parcel);
    EXPECT_EQ(catchInfo->GetManufacturer(), "TestManu");
    EXPECT_EQ(catchInfo->GetNickName(), "TestNick");
    EXPECT_EQ(catchInfo->GetPpdName(), "Test.ppd");
}

HWTEST_F(PpdInfoTest, ReadFromParcel_Test, TestSize.Level1)
{
    OHOS::Print::PpdInfo info;
    Parcel parcel;
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    parcel.WriteString("testManu");
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    parcel.WriteString("testManu");
    parcel.WriteString("testNick");
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    parcel.WriteString("testManu");
    parcel.WriteString("testNick");
    parcel.WriteString("Test.ppd");
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    EXPECT_EQ("testManu", info.GetManufacturer());
    EXPECT_EQ("testNick", info.GetNickName());
    EXPECT_EQ("Test.ppd", info.GetPpdName());
}

class PpdInfoCommon {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};
 
struct BuildPpdInfoParam {
    std::string manufacturer;
    std::string nickName;
    std::string ppdName;
};
 
class CheckPpdInfoTest : public PpdInfoCommon,
                        public testing::TestWithParam<BuildPpdInfoParam> {
public:
    using PpdInfoCommon::SetUp;
    using PpdInfoCommon::SetUpTestCase;
    using PpdInfoCommon::TearDown;
    using PpdInfoCommon::TearDownTestCase;
};
 
void TestDumpInfoTemplate(const std::string manufacturer, const std::string nickName,
    const std::string ppdName)
{
    PpdInfo info;
    if (!manufacturer.empty()) {
        info.SetManufacturer(manufacturer);
    }
    if (!nickName.empty()) {
        info.SetNickName(nickName);
    }
    if (!ppdName.empty()) {
        info.SetPpdName(ppdName);
    }
    info.Dump();
}
 
void TestConverJsonInfoTemplate(const std::string manufacturer, const std::string nickName,
    const std::string ppdName)
{
    PpdInfo info;
    bool convertable = true;
    if (!manufacturer.empty()) {
        info.SetManufacturer(manufacturer);
    } else {
        convertable = false;
    }
    if (!nickName.empty()) {
        info.SetNickName(nickName);
    } else {
        convertable = false;
    }
    if (!ppdName.empty()) {
        info.SetPpdName(ppdName);
    } else {
        convertable = false;
    }
    auto jsonInfo = info.ConvertToJson();
    EXPECT_EQ(convertable, info.ConvertFromJson(jsonInfo));
    if (convertable) {
        EXPECT_EQ(info.GetManufacturer(), manufacturer);
        EXPECT_EQ(info.GetNickName(), nickName);
        EXPECT_EQ(info.GetPpdName(), ppdName);
    }
}
 
HWTEST_P(CheckPpdInfoTest, CheckPpdInfoTest_P, TestSize.Level1)
{
    BuildPpdInfoParam param = GetParam();
 
    TestDumpInfoTemplate(
        param.manufacturer, param.nickName, param.ppdName);
    TestConverJsonInfoTemplate(
        param.manufacturer, param.nickName, param.ppdName);
}
 
const static std::string TEST_MANUFACTURER = "testManu";
const static std::string TEST_NICKNAME = "testNick";
const static std::string TEST_PPDNAME = "test.ppd";
INSTANTIATE_TEST_SUITE_P(CheckPpdInfoTest, CheckPpdInfoTest,
    testing::Values(BuildPpdInfoParam{"", "", ""},
        BuildPpdInfoParam{TEST_MANUFACTURER, "", ""},
        BuildPpdInfoParam{"", TEST_NICKNAME, ""},
        BuildPpdInfoParam{"", "", TEST_PPDNAME},
        BuildPpdInfoParam{TEST_MANUFACTURER, TEST_NICKNAME, ""},
        BuildPpdInfoParam{TEST_MANUFACTURER, "", TEST_PPDNAME},
        BuildPpdInfoParam{"", TEST_NICKNAME, TEST_PPDNAME},
        BuildPpdInfoParam{TEST_MANUFACTURER, TEST_NICKNAME, TEST_PPDNAME}));
}  // namespace Print
}  // namespace OHOS