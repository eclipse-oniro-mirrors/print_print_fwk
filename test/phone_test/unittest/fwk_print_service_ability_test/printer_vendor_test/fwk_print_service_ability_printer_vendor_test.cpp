/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "print_service_ability_test_common.h"

namespace OHOS {
namespace Print {

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0132_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->RemoveVendorPrinterFromDiscovery(vendorName, printerId));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0133_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    PrinterInfo info;
    PrinterInfo info2;
    info.SetPrinterId(printerId);
    std::string globalId = VendorManager::GetGlobalPrinterId(vendorName, printerId);
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_INVALID_PRINTER);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_INVALID_PRINTER);
    EXPECT_TRUE(service->RemoveVendorPrinterFromDiscovery(vendorName, printerId));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_EQ(service->QueryVendorPrinterInfo(globalId, info2), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0134_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string ppdName;
    std::string ppdData;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_FALSE(service->RemoveVendorPrinterFromCups(vendorName, printerId));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    info.SetUri("uri");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    EXPECT_FALSE(service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData));
    info.SetPrinterMake("maker");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData);
    ppdData = "ppd";
    service->AddVendorPrinterToCupsWithPpd(vendorName, printerId, ppdName, ppdData);
    service->RemoveVendorPrinterFromCups(vendorName, printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0136_NeedRename, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    PrinterInfo info;
    info.SetPrinterName(vendorName);
    info.SetPrinterId(printerId);
    PrinterCapability cap;
    info.SetCapability(cap);
    info.SetUri("uri");
    info.SetPrinterMake("maker");
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));

    // Directly insert first printer to added list to set up name conflict
    // (AddVendorPrinterToCupsWithPpd depends on CUPS which is unavailable in UT)
    std::string globalId = PrintUtils::GetGlobalId(vendorName, printerId);
    PrinterInfo addedInfo;
    addedInfo.SetPrinterName(vendorName);
    addedInfo.SetPrinterId(globalId);
    service->printSystemData_.InsertAddedPrinter(globalId, addedInfo);

    std::string printerId1 = "testprinter1";
    PrinterInfo info1;
    info1.SetPrinterName(vendorName);
    info1.SetPrinterId(printerId1);
    PrinterCapability cap1;
    info1.SetCapability(cap1);
    info1.SetUri("uri1");
    info1.SetPrinterMake("maker1");
    EXPECT_TRUE(service->RenamePrinterWhenAdded(info1) == "fwk.driver 1");
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0139_NeedRename, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string vendorName = "fwk.driver";
    std::string printerId = "testprinter";
    std::string ppdName;
    PrinterInfo info;
    info.SetPrinterId(printerId);
    EXPECT_FALSE(service->RemoveVendorPrinterFromCups(vendorName, printerId));
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
    PrinterCapability cap;
    info.SetCapability(cap);
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    info.SetUri("uri");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    info.SetPrinterMake("maker");
    EXPECT_TRUE(service->UpdateVendorPrinterToDiscovery(vendorName, info));
    ppdName = "ppd";
    service->RemoveVendorPrinterFromCups(vendorName, printerId);
    EXPECT_TRUE(service->AddVendorPrinterToDiscovery(vendorName, info));
}

HWTEST_F(PrintServiceAbilityTest, OnVendorStatusUpdate_WhenPrinterNotFound_ShouldReturnFalse, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalPrinterId = "vendor_001:printer_001";
    PrinterVendorStatus status;
    status.state = PRINTER_IDLE;
    bool result = service->OnVendorStatusUpdate(globalPrinterId, status);
    EXPECT_EQ(result, false);
}

HWTEST_F(PrintServiceAbilityTest, OnVendorStatusUpdate_NonIppPrinterUnavailable_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalPrinterId = "vendor_001:printer_001";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("printer_001");
    printerInfo->SetPrinterName("test_printer");
    printerInfo->SetUri("usb://printer_001");
    printerInfo->SetPrinterStatus(PRINTER_IDLE);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, printerInfo);
    PrinterVendorStatus status;
    status.state = PRINTER_UNAVAILABLE;
    bool result = service->OnVendorStatusUpdate(globalPrinterId, status);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, OnVendorStatusUpdate_WhenIppPrinterIdle_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalPrinterId = "vendor_001:printer_001";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("printer_001");
    printerInfo->SetPrinterName("test_printer");
    printerInfo->SetUri("ipp://192.168.1.1:631/printers/printer1");
    printerInfo->SetPrinterStatus(PRINTER_UNAVAILABLE);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, printerInfo);
    PrinterVendorStatus status;
    status.state = PRINTER_IDLE;
    bool result = service->OnVendorStatusUpdate(globalPrinterId, status);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, OnVendorStatusUpdate_WhenIppPrinterUnavailable_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalPrinterId = "vendor_001:printer_001";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("printer_001");
    printerInfo->SetPrinterName("test_printer");
    printerInfo->SetUri("ipp://192.168.1.1:631/printers/printer1");
    printerInfo->SetPrinterStatus(PRINTER_IDLE);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, printerInfo);
    PrinterVendorStatus status;
    status.state = PRINTER_UNAVAILABLE;
    bool result = service->OnVendorStatusUpdate(globalPrinterId, status);
    EXPECT_EQ(result, true);
}

HWTEST_F(PrintServiceAbilityTest, OnVendorStatusUpdate_WhenNonIppPrinterIdle_ShouldReturnTrue, TestSize.Level1)
{
    auto service = PrintServiceAbilityTest::CreateService();
    std::string globalPrinterId = "vendor_001:printer_001";
    auto printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterId("printer_001");
    printerInfo->SetPrinterName("test_printer");
    printerInfo->SetUri("usb://printer_001");
    printerInfo->SetPrinterStatus(PRINTER_UNAVAILABLE);
    service->printSystemData_.GetAddedPrinterMap().Insert(globalPrinterId, printerInfo);
    PrinterVendorStatus status;
    status.state = PRINTER_IDLE;
    bool result = service->OnVendorStatusUpdate(globalPrinterId, status);
    service->HandlePrinterStateChangeRegister(PRINTER_EVENT_TYPE);
    EXPECT_EQ(result, true);
}

}  // namespace Print
}  // namespace OHOS
