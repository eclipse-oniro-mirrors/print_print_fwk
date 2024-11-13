/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "print_ipp_over_usb_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintIppOverUsbManagerTest : public testing::Test  {
public:
    PrintIppOverUsbManager *printIppOverUsbManager;
    void SetUp() override
    {
        printIppOverUsbManager = new PrintIppOverUsbManager();
    }
    void TearDown() override
    {
        delete printIppOverUsbManager;
        printIppOverUsbManager = nullptr;
    }
};
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnFalse_WhenPrinterIdIsEmpty, TestSize.Level0)
{
    int32_t port;
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("", port), false);
}
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnFalse_WhenPortIsNull, TestSize.Level0)
{
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("printerId", nullptr), false);
}
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnTrue_WhenPrinterIdIsValid, TestSize.Level0)
{
    int32_t port;
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("validPrinterId", port), true);
}
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnFalse_WhenPrinterIdIsInvalid, TestSize.Level0)
{
    int32_t port;
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("invalidPrinterId", port), false);
}
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnFalse_WhenPortIsInvalid, TestSize.Level0)
{
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("validPrinterId", -1), false);
}
HWTEST_F(PrintIppOverUsbManagerTest, ConnectPrinter_ShouldReturnTrue_WhenPortIsValid, TestSize.Level0)
{
    int32_t port;
    EXPECT_EQ(printIppOverUsbManager->ConnectPrinter("validPrinterId", 1), true);
}

TEST_F(PrintIppOverUsbManagerTest, DisConnectPrinter_Should_Disconnect_When_PrinterId_Is_Valid)
{
    std::string printerId = "validPrinterId";
    printIppOverUsbManager->DisConnectPrinter(printerId);
    EXPECT_NO_THROW(printIppOverUsbManager->DisConnectPrinter(printerId));
}

TEST_F(PrintIppOverUsbManagerTest, DisConnectPrinter_Should_Throw_Exception_When_PrinterId_Is_Invalid)
{
    // Arrange
    std::string printerId = "invalidPrinterId";
    // Act & Assert
    EXPECT_THROW(printIppOverUsbManager->DisConnectPrinter(printerId), std::exception);
}

TEST_F(PrintIppOverUsbManagerTest, DisConnectPrinter_Should_Throw_Exception_When_PrinterId_Is_Empty)
{
    // Arrange
    std::string printerId = "";
    // Act & Assert
    EXPECT_THROW(printIppOverUsbManager->DisConnectPrinter(printerId), std::exception);
}

TEST_F(PrintIppOverUsbManagerTest, DisConnectPrinter_Should_Throw_Exception_When_PrinterId_Is_Null)
{
    // Arrange
    std::string printerId = nullptr;
    // Act & Assert
    EXPECT_THROW(printIppOverUsbManager->DisConnectPrinter(printerId), std::exception);
}
} // namespace OHOS::Print
