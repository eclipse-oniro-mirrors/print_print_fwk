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
#include "printer_info.h"

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
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0001, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.Dump();
}

/**
 * @tc.name: PrinterInfoTest_0002
 * @tc.desc: Verify settings and obtain id function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0002, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    EXPECT_EQ("001", info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0003
 * @tc.desc: Verify settings and obtain name function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0003, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterName("OpenHarmony");
    EXPECT_EQ("OpenHarmony", info.GetPrinterName());
}

/**
 * @tc.name: PrinterInfoTest_0004
 * @tc.desc: Verify settings and obtain icon function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0004, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterIcon(0);
    EXPECT_EQ((uint32_t)0, info.GetPrinterIcon());
}

/**
 * @tc.name: PrinterInfoTest_0005
 * @tc.desc: Verify settings and obtain state function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0005, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterState(0);
    EXPECT_EQ((uint32_t)0, info.GetPrinterState());
}

/**
 * @tc.name: PrinterInfoTest_0006
 * @tc.desc: Verify settings and obtain description function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0006, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetDescription("normal");
    EXPECT_EQ("normal", info.GetDescription());
}

/**
 * @tc.name: PrinterInfoTest_0007
 * @tc.desc: Verify settings and obtain option function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0007, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("运行成功:success");
    EXPECT_EQ("运行成功:success", info.GetOption());
}

/**
 * @tc.name: PrinterInfoTest_0008
 * @tc.desc: Verify settings and obtain capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0008, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    OHOS::Print::PrinterCapability capability, getCapabillity;
    info.SetCapability(capability);
    info.GetCapability(getCapabillity);
    EXPECT_EQ((uint32_t)0, getCapabillity.GetColorMode());
}

/**
 * @tc.name: PrinterInfoTest_0009
 * @tc.desc: Verify settings and obtain hasCapability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0009, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    OHOS::Print::PrinterCapability capability;
    info.SetCapability(capability);
    EXPECT_EQ(true, info.HasCapability());
}

/**
 * @tc.name: PrinterInfoTest_0010
 * @tc.desc: Verify settings and obtain hasOption function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0010, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetOption("运行成功:success");
    EXPECT_EQ(true, info.HasOption());
}

/**
 * @tc.name: PrinterInfoTest_0011
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0011, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(-1);
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0012
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0012, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0013
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0013, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    info.SetDescription("");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0014
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0014, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    info.SetDescription("description");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0015
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0015, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    info.SetDescription("description");
    OHOS::Print::PrinterCapability capability;
    info.SetCapability(capability);
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0016
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0016, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    info.SetDescription("description");
    OHOS::Print::PrinterCapability capability;
    info.SetCapability(capability);
    info.SetOption("option");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

/**
 * @tc.name: PrinterInfoTest_0017
 * @tc.desc: Verify settings and obtain marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0017, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    info.SetPrinterName("OpenHarmony");
    info.SetPrinterState(0);
    info.SetPrinterIcon(0);
    Parcel parcel;
    info.Marshalling(parcel);
    auto result = OHOS::Print::PrinterInfo::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrinterInfoTest_0018
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0018, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    OHOS::Print::PrinterInfo copyInfo(info);
    EXPECT_EQ(copyInfo.GetPrinterId(), info.GetPrinterId());
}

/**
 * @tc.name: PrinterInfoTest_0019
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterInfoTest, PrinterInfoTest_0019, TestSize.Level1)
{
    OHOS::Print::PrinterInfo info;
    info.SetPrinterId("001");
    OHOS::Print::PrinterInfo copyInfo = info;
    EXPECT_EQ(copyInfo.GetPrinterId(), info.GetPrinterId());
}
} // namespace Print
} // namespace OHOS
