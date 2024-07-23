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
#include "print_usb_manager.h"
#undef private
#include "print_ipp_over_usb_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
static const std::string IPP_PRINTER =
    R"({"busNum":2,"clazz":0,"configs":[{"attributes":192,"id":1,"interfaces":[{"alternateSetting":0,"clazz":7,)"\
    R"("endpoints":[{"address":1,"attributes":2,"direction":0,"interfaceId":0,"interval":0,"maxPacketSize":512,)"\
    R"("number":1,"type":2},{"address":129,"attributes":2,"direction":128,"interfaceId":0,"interval":0,)"\
    R"("maxPacketSize":512,"number":1,"type":2}],"id":0,"name":"","protocol":2,"subClass":1},{"alternateSetting":0,)"\
    R"("clazz":255,"endpoints":[{"address":2,"attributes":2,"direction":0,"interfaceId":1,"interval":0,)"\
    R"("maxPacketSize":512,"number":2,"type":2},{"address":130,"attributes":2,"direction":128,"interfaceId":1,)"\
    R"("interval":0,"maxPacketSize":512,"number":2,"type":2}],"id":1,"name":"","protocol":255,"subClass":255},)"\
    R"({"alternateSetting":0,"clazz":7,"endpoints":[{"address":3,"attributes":2,"direction":0,"interfaceId":2,)"\
    R"("interval":0,"maxPacketSize":512,"number":3,"type":2},{"address":131,"attributes":2,"direction":128,)"\
    R"("interfaceId":2,"interval":0,"maxPacketSize":512,"number":3,"type":2}],"id":2,"name":"","protocol":4,)"\
    R"("subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":4,"attributes":2,"direction":0,)"\
    R"("interfaceId":3,"interval":0,"maxPacketSize":512,"number":4,"type":2},{"address":132,"attributes":2,)"\
    R"("direction":128,"interfaceId":3,"interval":0,"maxPacketSize":512,"number":4,"type":2}],"id":3,"name":"",)"\
    R"("protocol":4,"subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":5,"attributes":2,)"\
    R"("direction":0,"interfaceId":4,"interval":0,"maxPacketSize":512,"number":5,"type":2},{"address":133,)"\
    R"("attributes":2,"direction":128,"interfaceId":4,"interval":0,"maxPacketSize":512,"number":5,"type":2}],)"\
    R"("id":4,"name":"","protocol":4,"subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":6,)"\
    R"("attributes":2,"direction":0,"interfaceId":5,"interval":0,"maxPacketSize":512,"number":6,"type":2},)"\
    R"({"address":134,"attributes":2,"direction":128,"interfaceId":5,"interval":0,"maxPacketSize":512,)"\
    R"("number":6,"type":2}],"id":5,"name":" ","protocol":4,"subClass":1}],"isRemoteWakeup":false,)"\
    R"("isSelfPowered":true,"maxPower":1,"name":" "}],"devAddress":5,"manufacturerName":" ","name":"2-5",)"\
    R"("productId":4293,"productName":" ","protocol":0,"serial":"","subClass":0,"vendorId":4817,"version":"0404"})";

static const std::string NON_IPP_PRINTER =
    R"({"busNum":2,"clazz":0,"configs":[{"attributes":192,"id":1,"interfaces":[{"alternateSetting":0,"clazz":255,)"\
    R"("endpoints":null,"id":0,"name":" ","protocol":255,"subClass":255}],"isRemoteWakeup":false,)"\
    R"("isSelfPowered":true,"maxPower":0,"name":" "}],"devAddress":4,"manufacturerName":"Microchip Tech\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000","name":"2-4","productId":10048,"productName":"Hub Controller\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"\
    R"(\u0000", "protocol":0, "serial":"", "subClass":0, "vendorId":1060, "version":"0002"})";

class PrintUsbManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintUsbManagerTest::SetUpTestCase(void)
{}

void PrintUsbManagerTest::TearDownTestCase(void)
{}

void PrintUsbManagerTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintUsbManagerTest_%{public}d", ++testNo);
}

void PrintUsbManagerTest::TearDown(void)
{}

/**
 * @tc.name: PrintUsbManagerTest_001
 * @tc.desc: Verify the Init function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_001, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    printUsbManager.isInit = true;
    printUsbManager.Init();
    EXPECT_EQ(true, printUsbManager.isInit);
}

/**
 * @tc.name: PrintUsbManagerTest_002
 * @tc.desc: Verify the isExistIppOverUsbPrinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_002, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    OHOS::USB::UsbDevice usbDevice;
    printUsbManager.printDeviceMap[printerName] = usbDevice;
    bool ret = printUsbManager.isExistIppOverUsbPrinter(printerName);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: PrintUsbManagerTest_003
 * @tc.desc: Verify the isPrintDevice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_003, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    OHOS::USB::UsbDevice usbDevice;
    std::string printerName;
    bool ret = printUsbManager.isPrintDevice(usbDevice, printerName);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintUsbManagerTest_004
 * @tc.desc: Verify the RefreshUsbPrinterDevice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_004, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    printUsbManager.RefreshUsbPrinterDevice();
}

/**
 * @tc.name: PrintUsbManagerTest_005
 * @tc.desc: Verify the GetProductName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_005, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    OHOS::USB::UsbDevice usbDevice;
    std::string printerName = printUsbManager.GetProductName(usbDevice);
    EXPECT_EQ("", printerName);
}

/**
 * @tc.name: PrintUsbManagerTest_006
 * @tc.desc: Verify the QueryPrinterInfoFromStringDescriptor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_006, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    OHOS::USB::USBDevicePipe usbDevicePipe;
    uint16_t indexInStringDescriptor = USB_VALUE_DESCRIPTOR_INDEX_PRODUCT_NAME;
    std::string printerInfo =
        printUsbManager.QueryPrinterInfoFromStringDescriptor(usbDevicePipe, indexInStringDescriptor);
    EXPECT_EQ("", printerInfo);
}

/**
 * @tc.name: PrintUsbManagerTest_007
 * @tc.desc: Verify the ConnectUsbPinter function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_007, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    OHOS::USB::USBDevicePipe usbDevicePipe;
    printUsbManager.printPipeMap[printerName] = usbDevicePipe;
    OHOS::USB::UsbDevice usbDevice;
    printUsbManager.printDeviceMap[printerName] = usbDevice;
    bool ret = printUsbManager.ConnectUsbPinter(printerName);
    EXPECT_EQ(ret, true);
    printUsbManager.DisConnectUsbPinter(printerName);
}

/**
 * @tc.name: PrintUsbManagerTest_09
 * @tc.desc: Verify the BulkTransferWrite function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_09, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    std::vector<uint8_t> vectorRequestBuffer;
    int32_t ret =
        printUsbManager.BulkTransferWrite(printerName, Operation::Get_Printer_Attributes, vectorRequestBuffer);
    EXPECT_GT(0, ret);
    ret = printUsbManager.BulkTransferWrite(printerName, Operation::Send_Document, vectorRequestBuffer);
    EXPECT_GT(0, ret);
    ret = printUsbManager.BulkTransferWrite(printerName, Operation::Common, vectorRequestBuffer);
    EXPECT_GT(0, ret);
}

/**
 * @tc.name: PrintUsbManagerTest_010
 * @tc.desc: Verify the BulkTransferRead function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_010, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    std::vector<uint8_t> vectorRequestBuffer;
    int32_t ret = printUsbManager.BulkTransferRead(printerName, Operation::Get_Printer_Attributes, vectorRequestBuffer);
    EXPECT_GT(0, ret);
    ret = printUsbManager.BulkTransferRead(printerName, Operation::Send_Document, vectorRequestBuffer);
    EXPECT_GT(0, ret);
    ret = printUsbManager.BulkTransferRead(printerName, Operation::Common, vectorRequestBuffer);
    EXPECT_GT(0, ret);
}

/**
 * @tc.name: PrintUsbManagerTest_011
 * @tc.desc: Verify the DealUsbDevStatusChange function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_011, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    bool isAttach = true;
    std::string devStr = IPP_PRINTER;
    std::string devStrNull = "";
    printUsbManager.DealUsbDevStatusChange(devStr, isAttach);
    isAttach = false;
    printUsbManager.DealUsbDevStatusChange(devStr, isAttach);
    printUsbManager.DealUsbDevStatusChange(devStrNull, isAttach);
    isAttach = true;
    devStr = NON_IPP_PRINTER;
    printUsbManager.DealUsbDevStatusChange(NON_IPP_PRINTER, isAttach);
}

/**
 * @tc.name: PrintUsbManagerTest_012
 * @tc.desc: Verify the GetPrinterName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_012, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "HUAWEI PixLab V1-0105";
    std::string printerName = printUsbManager.GetPrinterName(name);
    EXPECT_EQ("", printerName);
    OHOS::USB::UsbDevice usbDevice;
    printUsbManager.printDeviceMap[printerName] = usbDevice;
    printUsbManager.GetPrinterName(usbDevice.GetName());
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_013, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "HUAWEI PixLab V1-0105";
    OHOS::USB::USBDevicePipe usbDevicePipe;
    OHOS::USB::UsbDevice usbDevice;
    bool ret = printUsbManager.AllocateInterface(name, usbDevice, usbDevicePipe);
    EXPECT_EQ(false, ret);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_014, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "HUAWEI PixLab V1-0105";
    OHOS::USB::UsbDevice usbDevice;
    printUsbManager.printDeviceMap[name] = usbDevice;
    printUsbManager.DisConnectUsbPinter(name);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_015, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "HUAWEI PixLab V1-0105";
    OHOS::USB::USBDevicePipe usbDevicePipe;
    printUsbManager.printPipeMap[name] = usbDevicePipe;
    printUsbManager.DisConnectUsbPinter(name);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_016, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "";
    printUsbManager.DisConnectUsbPinter(name);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_017, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "";
    OHOS::USB::UsbDevice usbDevice;
    printUsbManager.printDeviceMap[printerName] = usbDevice;
    bool ret = printUsbManager.ConnectUsbPinter(printerName);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_018, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "";
    bool ret = printUsbManager.ConnectUsbPinter(printerName);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_019, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    bool ret = printUsbManager.ConnectUsbPinter(printerName);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_020, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    OHOS::USB::UsbDevice usbDevice;
    std::string printerName = "HUAWEI PixLab V1-0105";
    printUsbManager.isPrintDevice(usbDevice, printerName);
}

HWTEST_F(PrintUsbManagerTest, PrintUsbManagerTest_021, TestSize.Level1)
{
    OHOS::Print::PrintUsbManager printUsbManager;
    std::string name = "";
    OHOS::USB::USBDevicePipe usbDevicePipe;
    OHOS::USB::UsbDevice usbDevice;
    bool ret = printUsbManager.AllocateInterface(name, usbDevice, usbDevicePipe);
    EXPECT_EQ(false, ret);
}
}  // namespace Print
}  // namespace OHOS
#endif // IPPOVERUSB_ENABLE