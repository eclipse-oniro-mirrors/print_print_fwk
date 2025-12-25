/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "vendormanager_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_log.h"
#include "print_constant.h"
#include "vendor_manager.h"
#include "vendor_driver_base.h"
#include "vendor_wlan_group.h"
#include "vendor_ppd_driver.h"
#include "print_service_ability.h"
#include "print_service_ability_mock_permission.h"


namespace OHOS {
namespace Print {
constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t FOO_MAX_LEN = 64;
static const std::string DEFAULT_VENDOR_NAME = "testVendorName";
static ConnectMethod METHOD_DEFAULT = ID_AUTO;
static const std::string DEFAULT_PROTOCOL = "ipp";
static const int32_t DEFAULT_TIMEOUT = 0;

void TestWlanGroupDiscoverPrinterActions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    VendorManager &vendorManager = PrintServiceAbility::GetInstance()->vendorManager;
    auto vendorWlanGroup = std::static_pointer_cast<VendorWlanGroup>(vendorManager.wlanGroupDriver);

    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    vendorWlanGroup->OnPrinterDiscovered(DEFAULT_VENDOR_NAME, printerInfo);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    vendorWlanGroup->OnUpdatePrinterToDiscovery(DEFAULT_VENDOR_NAME, printerInfo);
    vendorWlanGroup->OnPrinterRemoved(DEFAULT_VENDOR_NAME, printerId);
}

void TestWlanGroupConnectPrinterActions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    VendorManager &vendorManager = PrintServiceAbility::GetInstance()->vendorManager;
    auto vendorWlanGroup = std::static_pointer_cast<VendorWlanGroup>(vendorManager.wlanGroupDriver);

    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printerInfo.SetUri(printerUri);
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    vendorWlanGroup->OnPrinterDiscovered(DEFAULT_VENDOR_NAME, printerInfo);

    vendorWlanGroup->SetConnectingPrinter(METHOD_DEFAULT, printerId);
    vendorWlanGroup->IsGroupDriver(printerId);
    vendorWlanGroup->IsConnectingPrinter(printerId, printerUri);
    // OnQueryCapability has some problem on fuzzFwk when call successfully.
    vendorWlanGroup->OnQueryCapabilityByIp(printerUri, DEFAULT_PROTOCOL);
}
void TestWlanGroupOtherFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    VendorManager &vendorManager = PrintServiceAbility::GetInstance()->vendorManager;
    auto vendorWlanGroup = std::static_pointer_cast<VendorWlanGroup>(vendorManager.wlanGroupDriver);

    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string printerBsuriId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdData = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string vendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);

    // other function
    vendorWlanGroup->OnPrinterPpdQueried(DEFAULT_VENDOR_NAME, printerId, ppdName, ppdData);
    vendorWlanGroup->ConvertGroupDriver(printerId, vendorName);
    vendorWlanGroup->ConvertGroupGlobalPrinterId(printerId);
    vendorWlanGroup->GetGroupPrinterId(printerId);
    vendorWlanGroup->UpdateGroupPrinter(printerId, printerBsuriId);
    vendorWlanGroup->ExtractPrinterIdByPrinterInfo(printerInfo);

    // other function without vendorManager
    vendorWlanGroup->vendorManager = nullptr;
    vendorWlanGroup->parentVendorManager = nullptr;
    vendorWlanGroup->OnPrinterPpdQueried(DEFAULT_VENDOR_NAME, printerId, ppdName, ppdData);
    vendorWlanGroup->ConvertGroupDriver(printerId, vendorName);
    vendorWlanGroup->ConvertGroupGlobalPrinterId(printerId);
    vendorWlanGroup->GetGroupPrinterId(printerId);
    vendorWlanGroup->UpdateGroupPrinter(printerId, printerBsuriId);
    vendorWlanGroup->ExtractPrinterIdByPrinterInfo(printerInfo);
}

void TestWlanGroupWithoutVendorManager(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto vendorWlanGroup = std::make_shared<VendorWlanGroup>(nullptr);
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printerInfo.SetUri(printerUri);
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    vendorWlanGroup->OnPrinterDiscovered(DEFAULT_VENDOR_NAME, printerInfo);
    vendorWlanGroup->OnUpdatePrinterToDiscovery(DEFAULT_VENDOR_NAME, printerInfo);
    vendorWlanGroup->OnPrinterRemoved(DEFAULT_VENDOR_NAME, printerId);

    vendorWlanGroup->SetConnectingPrinter(METHOD_DEFAULT, printerId);
    vendorWlanGroup->IsGroupDriver(printerId);
    vendorWlanGroup->IsConnectingPrinter(printerId, printerUri);
    vendorWlanGroup->OnQueryCapability(printerId, DEFAULT_TIMEOUT);
    vendorWlanGroup->OnQueryCapabilityByIp(printerUri, DEFAULT_PROTOCOL);
}

void TestPpdDriverConnectPrinterActions(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    VendorManager &vendorManager = PrintServiceAbility::GetInstance()->vendorManager;
    auto vendorWlanGroup = std::static_pointer_cast<VendorWlanGroup>(vendorManager.wlanGroupDriver);
    auto vendorPpdDriver = vendorManager.FindDriverByVendorName(VENDOR_PPD_DRIVER);
    if (vendorPpdDriver == nullptr) {
        return;
    }

    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string printerUri = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(printerUri);
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    vendorWlanGroup->OnPrinterDiscovered(DEFAULT_VENDOR_NAME, printerInfo);

    auto propertyKeys = std::vector<std::string>(1, printerInfo.GetPrinterMake());
    vendorPpdDriver->OnQueryProperties(printerId, propertyKeys);
    vendorPpdDriver->OnQueryCapability(printerId, DEFAULT_TIMEOUT);

    vendorPpdDriver->vendorManager = nullptr;
    vendorPpdDriver->OnQueryProperties(printerId, propertyKeys);
    vendorPpdDriver->OnQueryCapability(printerId, DEFAULT_TIMEOUT);
}

void TestPpdDriverOtherFunction(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    VendorManager &vendorManager = PrintServiceAbility::GetInstance()->vendorManager;
    auto vendorWlanGroup = std::static_pointer_cast<VendorWlanGroup>(vendorManager.wlanGroupDriver);
    auto vendorPpdDriver = std::make_shared<VendorPpdDriver>();
    vendorPpdDriver->Init(&vendorManager);

    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string ppdData = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterInfo printerInfo;
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterName(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetUri(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetPrinterMake(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH));
    auto info = make_shared<PrinterInfo>(printerInfo);

    // other function
    std::string vendorName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string key = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value;
    vendorPpdDriver->OnPrinterDiscovered(vendorName, printerInfo);
    vendorPpdDriver->QueryProperty(printerId, key, value);

    // other function without vendorManager
    vendorPpdDriver->vendorManager = nullptr;
    vendorPpdDriver->QueryProperty(printerId, key, value);
}

void TestVendorWlanGroup(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestWlanGroupDiscoverPrinterActions(data, size, dataProvider);
    TestWlanGroupConnectPrinterActions(data, size, dataProvider);
    TestWlanGroupOtherFunction(data, size, dataProvider);
    TestWlanGroupWithoutVendorManager(data, size, dataProvider);
}

void TestVendorPpdDriver(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    TestPpdDriverConnectPrinterActions(data, size, dataProvider);
    TestPpdDriverOtherFunction(data, size, dataProvider);
}

}  // namespace Print
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Print::U32_AT_SIZE || size > OHOS::Print::FOO_MAX_LEN) {
        return 0;
    }

    FuzzedDataProvider dataProvider(data, size);
    OHOS::Print::PrintServiceAbilityMockPermission::MockPermission();
    OHOS::Print::PrintServiceAbility::GetInstance()->vendorManager.Init(
        OHOS::Print::PrintServiceAbility::GetInstance());
    OHOS::Print::TestVendorWlanGroup(data, size, &dataProvider);
    OHOS::Print::TestVendorPpdDriver(data, size, &dataProvider);
    return 0;
}

