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
#include "printer_capability.h"
#include "print_margin.h"
#include "print_resolution.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrinterCapabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrinterCapabilityTest::SetUpTestCase(void) {}

void PrinterCapabilityTest::TearDownTestCase(void) {}

void PrinterCapabilityTest::SetUp(void) {}

void PrinterCapabilityTest::TearDown(void) {}

/**
 * @tc.name: PrinterCapabilityTest_0002
 * @tc.desc: Verify settings and obtain colorMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0002_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    capability.Reset();
    EXPECT_EQ((uint32_t)0, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0003
 * @tc.desc: Verify settings and obtain hasMargin function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0003_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin;
    capability.SetMinMargin(margin);
    EXPECT_EQ(true, capability.HasMargin());
}

/**
 * @tc.name: PrinterCapabilityTest_0004
 * @tc.desc: Verify settings and obtain hasMargin function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0004_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, copyMargin;
    capability.SetMinMargin(margin);
    capability.GetMinMargin(copyMargin);
    EXPECT_FALSE(copyMargin.HasRight());
}

/**
 * @tc.name: PrinterCapabilityTest_0005
 * @tc.desc: Verify settings and obtain pageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0005_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    PrintPageSize testPagesize;
    testPagesize.SetWidth(1);
    pagesize.emplace_back(testPagesize);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(pagesize.size(), getPagesize.size());
}

/**
 * @tc.name: PrinterCapabilityTest_0006
 * @tc.desc: Verify settings and obtain Resolution function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0006_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintResolution> resolution, getResolution;
    PrintResolution testResolution;
    testResolution.SetHorizontalDpi(1);
    resolution.emplace_back(testResolution);
    capability.SetResolution(resolution);
    capability.GetResolution(getResolution);
    EXPECT_EQ(resolution.size(), getResolution.size());
}

/**
 * @tc.name: PrinterCapabilityTest_0007
 * @tc.desc: Verify settings and obtain hasResolution function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0007_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintResolution> resolution;
    capability.SetResolution(resolution);
    EXPECT_EQ(true, capability.HasResolution());
}

/**
 * @tc.name: PrinterCapabilityTest_0008
 * @tc.desc: Verify settings and obtain colorMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0008_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0009
 * @tc.desc: Verify settings and obtain duplexMode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0009_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetDuplexMode(6);
    EXPECT_EQ((uint32_t)6, capability.GetDuplexMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0010
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0010_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);

    capability.SetMinMargin(margin);
    capability.SetSupportedPageSize(pagesize);
    capability.SetResolution(resolutionList);
    Parcel parcel;
    EXPECT_EQ(capability.Marshalling(parcel), true);
}

/**
 * @tc.name: PrinterCapabilityTest_0011
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0011_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);
    capability.SetSupportedPageSize(pagesize);
    Parcel parcel;
    EXPECT_EQ(capability.Marshalling(parcel), true);
}

/**
 * @tc.name: PrinterCapabilityTest_0012
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0012_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    PrintMargin margin, getMargin;
    std::vector<PrintResolution> resolutionList;
    std::vector<PrintPageSize> pagesize;
    capability.SetColorMode(6);
    capability.SetDuplexMode(6);
    capability.SetMinMargin(margin);
    capability.SetSupportedPageSize(pagesize);
    capability.SetResolution(resolutionList);
    Parcel parcel;
    capability.Marshalling(parcel);
    auto result = OHOS::Print::PrinterCapability::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    capability.Dump();
}

/**
 * @tc.name: PrinterCapabilityTest_0013
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0013_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    PrinterCapability copyCapability(capability);
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0014
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0014_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.SetColorMode(6);
    PrinterCapability copyCapability = capability;
    EXPECT_EQ((uint32_t)6, capability.GetColorMode());
}

/**
 * @tc.name: PrinterCapabilityTest_0015
 * @tc.desc: GetPrinterAttrValue.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0015_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    capability.GetPrinterAttrGroupJson();
    capability.SetPrinterAttrNameAndValue("key1", "value1");
    capability.SetPrinterAttrNameAndValue("key2", "value2");
    EXPECT_STREQ(capability.GetPrinterAttrValue("key1"), "value1");
    EXPECT_STREQ(capability.GetPrinterAttrValue("key"), "");
    capability.ClearCurPrinterAttrGroup();
}

/**
 * @tc.name: PrinterCapabilityTest_00016
 * @tc.desc: Verify set duplicate pageSize function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrinterCapabilityTest, PrinterCapabilityTest_0016_NeedRename, TestSize.Level2)
{
    PrinterCapability capability;
    std::vector<PrintPageSize> pagesize, getPagesize;
    pagesize.emplace_back("page1", "page1", 1, 1);
    pagesize.emplace_back("page2", "page2", 1, 1);
    capability.SetSupportedPageSize(pagesize);
    capability.GetSupportedPageSize(getPagesize);
    EXPECT_EQ(getPagesize.size(), 1);
}
} // namespace Print
} // namespace OHOS
