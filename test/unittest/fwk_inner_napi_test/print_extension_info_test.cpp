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
#include "print_extension_info.h"
#include "printer_capability.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintExtensionInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionInfoTest::SetUpTestCase(void) {}

void PrintExtensionInfoTest::TearDownTestCase(void) {}

void PrintExtensionInfoTest::SetUp(void) {}

void PrintExtensionInfoTest::TearDown(void) {}

/**
 * @tc.name: PrintExtInfoTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.Dump();
    info.~PrintExtensionInfo();
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetExtensionId("id-1234");
    EXPECT_EQ(info.GetExtensionId(), "id-1234");
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVendorId("vid-1234");
    EXPECT_EQ(info.GetExtensionId(), "vid-1234");
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0004, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVendorIcon(1234);
    EXPECT_EQ(info.GetVendorIcon(), (uint32_t)1234);
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVendorName("vendorName");
    EXPECT_EQ(info.GetVendorName(), "vendorName");
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0006, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVersion("1.0.0");
    EXPECT_EQ(info.GetVersion(), "1.0.0");
}


HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVersion("1.0.0");
    OHOS::Print::PrintExtensionInfo copyInfo(info);
    EXPECT_EQ(copyInfo.GetVersion(), info.GetVersion());
}

HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0008, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVersion("1.0.0");
    OHOS::Print::PrintExtensionInfo copyInfo = info;
    EXPECT_EQ(copyInfo.GetVersion(), info.GetVersion());
}

/**
 * @tc.name: PrintExtInfoTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVendorName("vendorName");
    info.SetExtensionId("extensionId:123");
    info.SetVendorId("vendorId");
    info.SetVendorIcon(123);
    info.SetVersion("version");
    Parcel parcel;
    EXPECT_EQ(info.Marshalling(parcel), true);
}

/**
 * @tc.name: PrintExtInfoTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionInfoTest, PrintExtInfoTest_0010, TestSize.Level1)
{
    OHOS::Print::PrintExtensionInfo info;
    info.SetVendorName("vendorName");
    info.SetExtensionId("extensionId:123");
    info.SetVendorId("vendorId");
    info.SetVendorIcon(123);
    info.SetVersion("version");
    Parcel parcel;
    info.Marshalling(parcel);
    auto result = OHOS::Print::PrintExtensionInfo::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}
} // namespace Print
} // namespace OHOS