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

#ifdef IPPOVERUSB_ENABLE
#include <gtest/gtest.h>
#define private public
#include "print_ipp_over_usb_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintIppOverUsbManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintIppOverUsbManagerTest::SetUpTestCase(void)
{}

void PrintIppOverUsbManagerTest::TearDownTestCase(void)
{}

void PrintIppOverUsbManagerTest::SetUp(void)
{}

void PrintIppOverUsbManagerTest::TearDown(void)
{}

/**
 * @tc.name: PrintIppOverUsbManagerTest_002
 * @tc.desc: Verify the ConnectPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIppOverUsbManagerTest, PrintIppOverUsbManagerTest_002, TestSize.Level1)
{
    OHOS::Print::PrintIppOverUsbManager printIppOverUsbManager;
    std::string printerId = "com.ohos.spooler:USB PixLab V1-0159";
    int32_t port = 60000;
    printIppOverUsbManager.ConnectPrinter(printerId, port);
}

/**
 * @tc.name: PrintIppOverUsbManagerTest_003
 * @tc.desc: Verify the ConnectPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIppOverUsbManagerTest, PrintIppOverUsbManagerTest_003, TestSize.Level1)
{
    OHOS::Print::PrintIppOverUsbManager printIppOverUsbManager;
    std::string printerId = "com.ohos.spoolerUSB-PixLab V1-0159";
    int32_t port = 60000;
    printIppOverUsbManager.ConnectPrinter(printerId, port);
}

/**
 * @tc.name: PrintIppOverUsbManagerTest_004
 * @tc.desc: Verify the ConnectPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIppOverUsbManagerTest, PrintIppOverUsbManagerTest_004, TestSize.Level1)
{
    OHOS::Print::PrintIppOverUsbManager printIppOverUsbManager;
    std::string printerId = "com.ohos.test:USB PixLab V1-0159";
    int32_t port = 60000;
    printIppOverUsbManager.ConnectPrinter(printerId, port);
}

/**
 * @tc.name: PrintIppOverUsbManagerTest_005
 * @tc.desc: Verify the ConnectPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIppOverUsbManagerTest, PrintIppOverUsbManagerTest_005, TestSize.Level1)
{
    OHOS::Print::PrintIppOverUsbManager printIppOverUsbManager;
    std::string printerId = "com.ohos.spooler:PixLab V1-0159";
    int32_t port = 60000;
    printIppOverUsbManager.ConnectPrinter(printerId, port);
}

/**
 * @tc.name: PrintIppOverUsbManagerTest_006
 * @tc.desc: Verify the DisConnectPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintIppOverUsbManagerTest, PrintIppOverUsbManagerTest_006, TestSize.Level1)
{
    OHOS::Print::PrintIppOverUsbManager printIppOverUsbManager;
    std::string printerId = "com.ohos.spooler:USB PixLab V1-0159";
    printIppOverUsbManager.DisConnectPrinter(printerId);
}

}  // namespace Print
}  // namespace OHOS

#endif // IPPOVERUSB_ENABLE