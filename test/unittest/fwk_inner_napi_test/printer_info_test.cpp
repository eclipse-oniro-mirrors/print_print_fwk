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

#include "napi/native_api.h"
#include "printer_info.h"
#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrinterInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrinterInfoTest::SetUpTestCase(void) {}

void PrinterInfoTest::TearDownTestCase(void) {}

void PrinterInfoTest::SetUp(void) {}

void PrinterInfoTest::TearDown(void) {}

/**
 * @tc.name: PrinterInfoTest_0001
 * @tc.desc: Verify the id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0001, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    EXPECT_EQ("001", info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0002
 * @tc.desc: Verify the id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0002, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("@@@111");
    EXPECT_EQ("@@@111", info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0003
 * @tc.desc: Verify the id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0003, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("#￥1aa");
    EXPECT_EQ("#￥1aa", info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0004
 * @tc.desc: Verify the id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0004, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("……&**/1a");
    EXPECT_EQ("……&**/1a", info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0005
 * @tc.desc: Verify the name function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0005, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterName("OpenHarmony");
    EXPECT_EQ("OpenHarmony", info.GetPrinterName());
}

/**
 * @tc.name: PrinterInfoTest_0006
 * @tc.desc: Verify the name function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0006, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterName("OpenHarmony@1a/*");
    EXPECT_EQ("OpenHarmony@1a/*", info.GetPrinterName());
}

/**
 * @tc.name: PrinterInfoTest_0007
 * @tc.desc: Verify the name function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0007, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterName("OpenHarmony￥%……5a1");
    EXPECT_EQ("OpenHarmony￥%……5a1", info.GetPrinterName());
}

/**
 * @tc.name: PrinterInfoTest_0008
 * @tc.desc: Verify the name function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0008, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterName("OpenHarmony（*…………+.");
    EXPECT_EQ("OpenHarmony（*…………+.", info.GetPrinterName());
}

/**
 * @tc.name: PrinterInfoTest_0009
 * @tc.desc: Verify the icon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0009, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterIcon(0);
    EXPECT_EQ(0, info.GetPrinterIcon());
}

/**
 * @tc.name: PrinterInfoTest_0010
 * @tc.desc: Verify the icon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0010, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterIcon(10000);
    EXPECT_EQ(10000, info.GetPrinterIcon());
}

/**
 * @tc.name: PrinterInfoTest_0011
 * @tc.desc: Verify the icon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0011, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterIcon(10000000);
    EXPECT_EQ(10000000, info.GetPrinterIcon());
}

/**
 * @tc.name: PrinterInfoTest_0012
 * @tc.desc: Verify the icon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0012, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterIcon(1000000000);
    EXPECT_EQ(1000000000, info.GetPrinterIcon());
}

/**
 * @tc.name: PrinterInfoTest_0013
 * @tc.desc: Verify the state function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0013, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterState(0);
    EXPECT_EQ(0, info.GetPrinterState());
}

/**
 * @tc.name: PrinterInfoTest_0014
 * @tc.desc: Verify the state function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0014, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterState(10000);
    EXPECT_EQ(10000, info.GetPrinterState());
}

/**
 * @tc.name: PrinterInfoTest_0015
 * @tc.desc: Verify the state function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0015, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterState(10000000);
    EXPECT_EQ(10000000, info.GetPrinterState());
}

/**
 * @tc.name: PrinterInfoTest_0016
 * @tc.desc: Verify the state function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0016, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterState(1000000000);
    EXPECT_EQ(1000000000, info.GetPrinterState());
}

/**
 * @tc.name: PrinterInfoTest_0017
 * @tc.desc: Verify the description function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0017, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetDescription("normal");
    EXPECT_EQ("normal", info.GetDescription());
}

/**
 * @tc.name: PrinterInfoTest_0018
 * @tc.desc: Verify the description function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0018, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetDescription("false1a%……");
    EXPECT_EQ("false1a%……", info.GetDescription());
}

/**
 * @tc.name: PrinterInfoTest_0019
 * @tc.desc: Verify the description function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0019, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetDescription("error1￥qq");
    EXPECT_EQ("error1￥qq", info.GetDescription());
}

/**
 * @tc.name: PrinterInfoTest_0020
 * @tc.desc: Verify the description function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0020, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetDescription("success55aa￥%……");
    EXPECT_EQ("success55aa￥%……", info.GetDescription());
}

/**
 * @tc.name: PrinterInfoTest_0021
 * @tc.desc: Verify the option function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0021, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("开始：start1a@#");
    EXPECT_EQ("开始：start1a@#", info.GetOption());
}

/**
 * @tc.name: PrinterInfoTest_0022
 * @tc.desc: Verify the option function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0022, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("find error，stop work");
    EXPECT_EQ("find error，stop work", info.GetOption());
}

/**
 * @tc.name: PrinterInfoTest_0023
 * @tc.desc: Verify the option function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0023, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("乱码：￥%……4aaa");
    EXPECT_EQ("乱码：￥%……4aaa", info.GetOption());
}

/**
 * @tc.name: PrinterInfoTest_0024
 * @tc.desc: Verify the option function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0024, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("运行成功:success");
    EXPECT_EQ("运行成功:success", info.GetOption());
}

/**
 * @tc.name: PrinterInfoTest_0025
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0025, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    OHOS::Print::PrinterCapability capability, getCapabillity;
    info.SetCapability(capability);
    info.GetCapability(getCapabillity);
    EXPECT_EQ(0, getCapabillity.GetColorMode());
}

/**
 * @tc.name: PrinterInfoTest_0025
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0026, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    OHOS::Print::PrinterCapability capability, getCapabillity;
    napi_env env = nullptr;
    info.SetCapability(capability);
    info.GetCapability(getCapabillity);
    EXPECT_EQ(0, getCapabillity.GetDuplexMode());
    OHOS::Print::PrinterInfo(info_);
    OHOS::Print::PrinterInfo info_value = info;
    info.ToJsObject(env);
    info.Dump();
}
} // namespace Print
} // namespace OHOS