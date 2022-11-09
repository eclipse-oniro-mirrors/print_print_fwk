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

#include "print_extension_info.h"
#include "napi/native_api.h"
#include <gtest/gtest.h>

using namespace testing::ext;

class PrintExtensionInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionInfoTest::SetUpTestCase(void)
{
    // step 2: input testsuit setup step
}

void PrintExtensionInfoTest::TearDownTestCase(void)
{
    // step 2: input testsuit teardown step
}

void PrintExtensionInfoTest::SetUp(void)
{
    // step 3: input testcase setup step
}

void PrintExtensionInfoTest::TearDown(void)
{
    // step 3: input testcase teardown step
}

/**
 * @tc.name: PrintExtensionInfoTest_001
 * @tc.desc: Verify the extensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_001, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetExtensionId("001");
    EXPECT_EQ("001", extensionInfo.GetExtensionId());
}

/**
 * @tc.name: PrintExtensionInfoTest_002
 * @tc.desc: Verify the extensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_002, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetExtensionId("@@@111");
    EXPECT_EQ("@@@111", extensionInfo.GetExtensionId());
}

/**
 * @tc.name: PrintExtensionInfoTest_003
 * @tc.desc: Verify the extensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_003, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetExtensionId("#￥1aa");
    EXPECT_EQ("#￥1aa", extensionInfo.GetExtensionId());
}

/**
 * @tc.name: PrintExtensionInfoTest_004
 * @tc.desc: Verify the extensionId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_004, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetExtensionId("……&**/1a");
    EXPECT_EQ("……&**/1a", extensionInfo.GetExtensionId());
}
/**
 * @tc.name: PrintExtensionInfoTest_005 
 * @tc.desc: Verify the vendorId function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_005, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorId("001");
    EXPECT_EQ("001", extensionInfo.GetVendorId());
}

/**
 * @tc.name: PrintExtensionInfoTest_006
 * @tc.desc: Verify the vendorId function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_006, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorId("@@@111");
    EXPECT_EQ("@@@111", extensionInfo.GetVendorId());
}

/**
 * @tc.name: PrintExtensionInfoTest_007
 * @tc.desc: Verify the vendorId function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_007, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorId("#￥1aa");
    EXPECT_EQ("#￥1aa", extensionInfo.GetVendorId());
}

/**
 * @tc.name: PrintExtensionInfoTest_008
 * @tc.desc: Verify the vendorId function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_008, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorId("……&**/1a");
    EXPECT_EQ("……&**/1a", extensionInfo.GetVendorId());
}

/**
 * @tc.name: PrintExtensionInfoTest_009
 * @tc.desc: Verify the vendorName function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_009, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorName("OpenHarmony");
    EXPECT_EQ("OpenHarmony", extensionInfo.GetVendorName());
}

/**
 * @tc.name: PrintExtensionInfoTest_010
 * @tc.desc: Verify the vendorName function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_010, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorName("OpenHarmony@1a/*");
    EXPECT_EQ("OpenHarmony@1a/*", extensionInfo.GetVendorName());
}

/**
 * @tc.name: PrintExtensionInfoTest_011
 * @tc.desc: Verify the vendorName function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_011, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorName("OpenHarmony￥%……5a1");
    EXPECT_EQ("OpenHarmony￥%……5a1", extensionInfo.GetVendorName());
}

/**
 * @tc.name: PrintExtensionInfoTest_012
 * @tc.desc: Verify the vendorName function.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_012, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorName("OpenHarmony（*…………+.");
    EXPECT_EQ("OpenHarmony（*…………+.", extensionInfo.GetVendorName());
}

/**
 * @tc.name: PrintExtensionInfoTest_013
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_013, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorIcon(0);
    EXPECT_EQ(0, extensionInfo.GetVendorIcon());
}

/**
 * @tc.name: PrintExtensionInfoTest_014
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_014, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorIcon(10000);
    EXPECT_EQ(10000, extensionInfo.GetVendorIcon());
}

/**
 * @tc.name: PrintExtensionInfoTest_015
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_015, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorIcon(10000000);
    EXPECT_EQ(10000000, extensionInfo.GetVendorIcon());
}

/**
 * @tc.name: PrintExtensionInfoTest_016
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_016, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVendorIcon(1000000000);
    EXPECT_EQ(1000000000, extensionInfo.GetVendorIcon());
}

/**
 * @tc.name: PrintExtensionInfoTest_017
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_017, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVersion("v3.0.1");
    EXPECT_EQ("v3.0.1", extensionInfo.GetVersion());
}

/**
 * @tc.name: PrintExtensionInfoTest_018
 * @tc.desc: Verify the vendorIcon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtensionInfoTest_018, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo extensionInfo;
    extensionInfo.SetVersion("2.0.1####");
    EXPECT_EQ("2.0.1####", extensionInfo.GetVersion());
}