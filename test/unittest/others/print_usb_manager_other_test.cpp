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
#include "print_usb_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintUsbManagerTest : public testing::Test {
public:
    PrintUsbManager *printUsbManager;
    USB::UsbDevice usbDevice;
    std::string printerName;
    Operation operation;

    void SetUp() override
    {
        printUsbManager = new PrintUsbManager();
        printerName = "printer";
        operation = Operation::READ;
    }
    void TearDown() override
    {
        delete printUsbManager;
    }
    virtual std::string GetPrinterName(const std::string &name)
    {
        return name;
    }
};

TEST_F(PrintUsbManagerTest, isExistIppOverUsbPrinter_ShouldReturnFalse_WhenPrinterNameIsEmpty)
{
    EXPECT_FALSE(printUsbManager->isExistIppOverUsbPrinter(""));
}

TEST_F(PrintUsbManagerTest, isExistIppOverUsbPrinter_ShouldReturnFalse_WhenPrinterNameIsNull)
{
    EXPECT_FALSE(printUsbManager->isExistIppOverUsbPrinter(nullptr));
}

TEST_F(PrintUsbManagerTest, isExistIppOverUsbPrinter_ShouldReturnTrue_WhenPrinterNameExists)
{
    // Assuming there is a printer named "Printer1" in the system
    EXPECT_TRUE(printUsbManager->isExistIppOverUsbPrinter("Printer1"));
}

TEST_F(PrintUsbManagerTest, isExistIppOverUsbPrinter_ShouldReturnFalse_WhenPrinterNameDoesNotExist)
{
    // Assuming there is no printer named "NonExistingPrinter" in the system
    EXPECT_FALSE(printUsbManager->isExistIppOverUsbPrinter("NonExistingPrinter"));
}

HWTEST_F(PrintUsbManagerTest, isPrintDevice_ShouldReturnFalse_WhenInterfaceCountIsLessThanTwo, TestSize.Level0)
{
    usbDevice.SetConfigCount(1);
    usbDevice.GetConfigs()[0].SetInterfaceCount(1);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetClass(USB_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    EXPECT_FALSE(printUsbManager->isPrintDevice(usbDevice, printerName));
}

HWTEST_F(PrintUsbManagerTest, isPrintDevice_ShouldReturnTrue_WhenInterfaceCountIsGreaterThanOrEqualToTwo, TestSize.Level0)
{
    usbDevice.SetConfigCount(1);
    usbDevice.GetConfigs()[0].SetInterfaceCount(2);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    EXPECT_TRUE(printUsbManager->isPrintDevice(usbDevice, printerName));
}

HWTEST_F(PrintUsbManagerTest, isPrintDevice_ShouldReturnFalse_WhenPrinterNameIsEmpty, TestSize.Level0)
{
    usbDevice.SetConfigCount(1);
    usbDevice.GetConfigs()[0].SetInterfaceCount(2);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    printerName = "";
    EXPECT_FALSE(printUsbManager->isPrintDevice(usbDevice, printerName));
}

HWTEST_F(PrintUsbManagerTest, isPrintDevice_ShouldReturnTrue_WhenPrinterNameIsNotEmpty, TestSize.Level0)
{
    usbDevice.SetConfigCount(1);
    usbDevice.GetConfigs()[0].SetInterfaceCount(2);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[0].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetClass(USB_DEVICE_DEVICE_CLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetSubClass(USB_DEVICE_SUBCLASS_PRINT);
    usbDevice.GetConfigs()[0].GetInterfaces()[1].SetProtocol(USB_DEVICE_PROTOCOL_PRINT);
    printerName = "TestPrinter";
    EXPECT_TRUE(printUsbManager->isPrintDevice(usbDevice, printerName));
}

HWTEST_F(PrintUsbManagerTest, GetProductName_ShouldReturnCorrectName_WhenDeviceHasName, Level0)
{
    usbDevice.name = "TestDevice";
    EXPECT_EQ(printUsbManager->GetProductName(usbDevice), "TestDevice");
}

HWTEST_F(PrintUsbManagerTest, GetProductName_ShouldReturnEmptyString_WhenDeviceHasNoName, Level0)
{
    usbDevice.name = "";
    EXPECT_EQ(printUsbManager->GetProductName(usbDevice), "");
}

HWTEST_F(PrintUsbManagerTest, GetProductName_ShouldReturnCorrectName_WhenDeviceHasLongName, Level0)
{
    usbDevice.name = "ThisIsALongDeviceNameThatExceedsTheMaximumAllowedLengthForTheProductName";
    EXPECT_EQ(printUsbManager->GetProductName(usbDevice), "ThisIsALongDeviceNameThatExceedsTheMaximumAllowedLengthForTheProductName");
}

HWTEST_F(PrintUsbManagerTest, GetProductName_ShouldReturnEmptyString_WhenDeviceIsNull, Level0)
{
    EXPECT_EQ(printUsbManager->GetProductName(nullptr), "");
}

TEST_F(nullTest, QueryPrinterInfoFromStringDescriptor_ShouldReturnEmptyString_WhenInputIsNull)
{
    PrintUsbManager manager;
    std::string result = manager.QueryPrinterInfoFromStringDescriptor(nullptr);
    EXPECT_EQ(result, "");
}

TEST_F(nullTest, QueryPrinterInfoFromStringDescriptor_ShouldReturnNonEmptyString_WhenInputIsNotNull)
{
    PrintUsbManager manager;
    std::string descriptor = "some descriptor";
    std::string result = manager.QueryPrinterInfoFromStringDescriptor(&descriptor);
    EXPECT_NE(result, "");
}

TEST_F(nullTest, QueryPrinterInfoFromStringDescriptor_ShouldReturnSameString_WhenInputIsSameString)
{
    PrintUsbManager manager;
    std::string descriptor = "same descriptor";
    std::string result = manager.QueryPrinterInfoFromStringDescriptor(&descriptor);
    EXPECT_EQ(result, "same descriptor");
}

TEST_F(nullTest, QueryPrinterInfoFromStringDescriptor_ShouldReturnEmptyString_WhenInputIsEmpty)
{
    PrintUsbManager manager;
    std::string descriptor = "";
    std::string result = manager.QueryPrinterInfoFromStringDescriptor(&descriptor);
    EXPECT_EQ(result, "");
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManager_AllocateInterface_ShouldReturnFalse_WhenSurfaceProducerIsNull, TestSize.Level0)
{
    printerName = "printer1";
    usbDevice.surfaceProducer = nullptr;
    EXPECT_EQ(printUsbManager->AllocateInterface(printerName, usbDevice), false);
}
HWTEST_F(PrintUsbManagerTest, PrintUsbManager_AllocateInterface_ShouldReturnTrue_WhenSurfaceProducerIsNotNull, TestSize.Level0)
{
    printerName = "printer1";
    usbDevice.surfaceProducer = new SurfaceProducer();
    EXPECT_EQ(printUsbManager->AllocateInterface(printerName, usbDevice), true);
    delete usbDevice.surfaceProducer;
}
HWTEST_F(PrintUsbManagerTest, PrintUsbManager_AllocateInterface_ShouldReturnFalse_WhenPrinterNameIsEmpty, TestSize.Level0)
{
    printerName = "";
    usbDevice.surfaceProducer = new SurfaceProducer();
    EXPECT_EQ(printUsbManager->AllocateInterface(printerName, usbDevice), false);
    delete usbDevice.surfaceProducer;
}
HWTEST_F(PrintUsbManagerTest, PrintUsbManager_AllocateInterface_ShouldReturnTrue_WhenPrinterNameIsNotEmpty, TestSize.Level0)
{
    printerName = "printer1";
    usbDevice.surfaceProducer = new SurfaceProducer();
    EXPECT_EQ(printUsbManager->AllocateInterface(printerName, usbDevice), true);
    delete usbDevice.surfaceProducer;
}

TEST_F(PrintUsbManagerTest, ConnectUsbPinter_ShouldReturnTrue_WhenPrinterNameIsValid)
{
    // Arrange
    std::string printerName = "validPrinter";
    // Act
    bool result = printUsbManager->ConnectUsbPinter(printerName);
    // Assert
    EXPECT_TRUE(result);
}

TEST_F(PrintUsbManagerTest, ConnectUsbPinter_ShouldReturnFalse_WhenPrinterNameIsInvalid)
{
    // Arrange
    std::string printerName = "invalidPrinter";
    // Act
    bool result = printUsbManager->ConnectUsbPinter(printerName);
    // Assert
    EXPECT_FALSE(result);
}

TEST_F(PrintUsbManagerTest, ConnectUsbPinter_ShouldReturnFalse_WhenPrinterNameIsEmpty)
{
    // Arrange
    std::string printerName = "";
    // Act
    bool result = printUsbManager->ConnectUsbPinter(printerName);
    // Assert
    EXPECT_FALSE(result);
}

TEST_F(PrintUsbManagerTest, ConnectUsbPinter_ShouldReturnFalse_WhenPrinterNameIsNull)
{
    // Arrange
    std::string printerName = nullptr;
    // Act
    bool result = printUsbManager->ConnectUsbPinter(printerName);
    // Assert
    EXPECT_FALSE(result);
}

TEST_F(PrintUsbManagerTest, testDisConnectUsbPinter)
{
    PrintUsbManager printUsbManager;
    std::string printerName = "printer1";
    printUsbManager.DisConnectUsbPinter(printerName);
    EXPECT_EQ(printUsbManager.GetPrinterList().find(printerName), printUsbManager.GetPrinterList().end());
}

TEST_F(PrintUsbManagerTest, testDisConnectUsbPinterWithNonExistentPrinter)
{
    PrintUsbManager printUsbManager;
    std::string printerName = "non_existent_printer";
    printUsbManager.DisConnectUsbPinter(printerName);
    EXPECT_NE(printUsbManager.GetPrinterList().find(printerName), printUsbManager.GetPrinterList().end());
}

HWTEST_F(PrintUsbManagerTest, BulkTransferWrite_ShouldReturnSuccess_WhenSurfaceProducerIsNotNull, TestSize.Level0)
{
    // Arrange
    operation.surfaceProducer = new SurfaceProducer();
    // Act
    int32_t result = printUsbManager->BulkTransferWrite(printerName, operation, nullptr);

    // Assert
    EXPECT_EQ(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferWrite_ShouldReturnFailure_WhenSurfaceProducerIsNull, TestSize.Level0)
{
    // Arrange
    operation.surfaceProducer = nullptr;
    // Act
    int32_t result = printUsbManager->BulkTransferWrite(printerName, operation, nullptr);

    // Assert
    EXPECT_NE(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferWrite_ShouldReturnFailure_WhenOperationIsNull, TestSize.Level0)
{
    // Arrange
    operation = nullptr;
    // Act
    int32_t result = printUsbManager->BulkTransferWrite(printerName, operation, nullptr);

    // Assert
    EXPECT_NE(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferWrite_ShouldReturnFailure_WhenPrinterNameIsEmpty, TestSize.Level0)
{
    // Arrange
    printerName = "";
    // Act
    int32_t result = printUsbManager->BulkTransferWrite(printerName, operation, nullptr);

    // Assert
    EXPECT_NE(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferRead_ShouldReturnSuccess_WhenSurfaceProducerIsNotNull, TestSize.Level0)
{
    // Arrange
    sptr<IBufferProducer> surfaceProducer = new IBufferProducer();
    // Act
    int32_t result = printUsbManager->BulkTransferRead(printerName, operation, surfaceProducer);
    // Assert
    EXPECT_EQ(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferRead_ShouldReturnFailure_WhenSurfaceProducerIsNull, TestSize.Level0)
{
    // Arrange
    sptr<IBufferProducer> surfaceProducer = nullptr;
    // Act
    int32_t result = printUsbManager->BulkTransferRead(printerName, operation, surfaceProducer);
    // Assert
    EXPECT_NE(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferRead_ShouldReturnFailure_WhenOperationIsNotRead, TestSize.Level0)
{
    // Arrange
    sptr<IBufferProducer> surfaceProducer = new IBufferProducer();
    Operation operation = Operation::WRITE;
    // Act
    int32_t result = printUsbManager->BulkTransferRead(printerName, operation, surfaceProducer);
    // Assert
    EXPECT_NE(result, 0);
}

HWTEST_F(PrintUsbManagerTest, BulkTransferRead_ShouldReturnFailure_WhenPrinterNameIsEmpty, TestSize.Level0)
{
    // Arrange
    sptr<IBufferProducer> surfaceProducer = new IBufferProducer();
    std::string printerName = "";
    // Act
    int32_t result = printUsbManager->BulkTransferRead(printerName, operation, surfaceProducer);
    // Assert
    EXPECT_NE(result, 0);
}

TEST_F(nullTest, DealUsbDevStatusChange_ShouldReturnNull_WhenSurfaceProducerIsNull)
{
    PrintUsbManager printUsbManager;
    std::string devStr = "testDevice";
    bool isAttach = false;
    printUsbManager.DealUsbDevStatusChange(devStr, isAttach);
    EXPECT_TRUE(printUsbManager.status);
}

TEST_F(nullTest, DealUsbDevStatusChange_ShouldReturnNonNull_WhenSurfaceProducerIsNotNull)
{
    PrintUsbManager printUsbManager;
    std::string devStr = "testDevice";
    bool isAttach = true;
    printUsbManager.DealUsbDevStatusChange(devStr, isAttach);
    EXPECT_FALSE(printUsbManager.status);
}

HWTEST_F(PrintUsbManagerTest, GetPrinterName_ShouldReturnName_WhenNameIsGiven, Level0)
{
    PrintUsbManager manager;
    std::string expected = "printer";
    EXPECT_EQ(manager.GetPrinterName(expected), expected);
}

HWTEST_F(PrintUsbManagerTest, GetPrinterName_ShouldReturnEmptyString_WhenEmptyStringIsGiven, Level0)
{
    PrintUsbManager manager;
    std::string expected = "";
    EXPECT_EQ(manager.GetPrinterName(expected), expected);
}

HWTEST_F(PrintUsbManagerTest, GetPrinterName_ShouldReturnName_WhenSpecialCharactersAreGiven, Level0)
{
    PrintUsbManager manager;
    std::string expected = "!@#$%^&*()";
    EXPECT_EQ(manager.GetPrinterName(expected), expected);
}

HWTEST_F(PrintUsbManagerTest, GetPrinterName_ShouldReturnName_WhenNumbersAreGiven, Level0)
{
    PrintUsbManager manager;
    std::string expected = "1234567890";
    EXPECT_EQ(manager.GetPrinterName(expected), expected);
}

HWTEST_F(PrintUsbManagerTest, GetPrinterName_ShouldReturnName_WhenNameIsLong, Level0)
{
    PrintUsbManager manager;
    std::string expected = "ThisIsALongNameForAPrinter";
    EXPECT_EQ(manager.GetPrinterName(expected), expected);
}

} // namespace OHOS::Print
