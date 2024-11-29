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

#include "vendor_bsuni_driver.h"
#include <dlfcn.h>
#include "parameter.h"
#include "print_log.h"
#include "vendor_helper.h"

using namespace OHOS::Print;
namespace {
std::mutex g_driverMutex;
VendorBsuniDriver *g_driverWrapper = nullptr;
}

void VendorBsuniDriver::SetDriverWrapper(VendorBsuniDriver *driver)
{
    std::lock_guard<std::mutex> lock(g_driverMutex);
    g_driverWrapper = driver;
}

bool VendorBsuniDriver::CheckVendorExtension(Print_VendorExtension *extension)
{
    if (extension == nullptr) {
        PRINT_HILOGW("extension is null");
        return false;
    }
    if (extension->onCreate == nullptr || extension->onDestroy == nullptr || extension->onStartDiscovery == nullptr ||
        extension->onStopDiscovery == nullptr || extension->onConnectPrinter == nullptr ||
        extension->onDisconnectPrinter == nullptr || extension->onQueryCapability == nullptr ||
        extension->onQueryCapabilityByIp == nullptr || extension->onQueryProperties == nullptr) {
        PRINT_HILOGW("invalid extension");
        return false;
    }
    return true;
}
bool VendorBsuniDriver::LoadDriverExtension()
{
    vendorExtension = nullptr;
    if (bsUniDriverHandler != nullptr) {
        dlclose(bsUniDriverHandler);
        bsUniDriverHandler = nullptr;
    }
    const std::string DRIVER_SO_PATH = "print.libbsUniDiscovery.so.path";
    constexpr int BUFFER_SIZE = 96;
    char value[BUFFER_SIZE] = {0};
    GetParameter(DRIVER_SO_PATH.c_str(), "", value, BUFFER_SIZE - 1);
    bsUniDriverHandler = dlopen(value, RTLD_LAZY | RTLD_NODELETE);
    if (bsUniDriverHandler == nullptr) {
        PRINT_HILOGW("dlopen failed");
        return false;
    }
    do {
        typedef Print_VendorExtension *(*GetPrintVendorExtensionFunc)();
        GetPrintVendorExtensionFunc func =
            reinterpret_cast<GetPrintVendorExtensionFunc>(dlsym(bsUniDriverHandler, "GetPrintVendorExtension"));
        if (func == nullptr) {
            PRINT_HILOGW("dlsym  GetPrintVendorExtension failed");
            break;
        }
        Print_VendorExtension *extension = func();
        if (!CheckVendorExtension(extension)) {
            break;
        }
        vendorExtension = extension;
        return true;
    } while (false);
    if (bsUniDriverHandler != nullptr) {
        dlclose(bsUniDriverHandler);
        bsUniDriverHandler = nullptr;
    }
    return false;
}

int32_t VendorBsuniDriver::AddPrinterToDiscovery(const Print_DiscoveryItem *discoveryItem)
{
    PRINT_HILOGI("BsUni callback AddPrinterToDiscovery");
    LogDiscoveryItem(discoveryItem);
    PrinterInfo info;
    if (!UpdatePrinterInfoWithDiscovery(info, discoveryItem)) {
        PRINT_HILOGW("fail to convert discoveryItem to printer info");
        return EXTENSION_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr || g_driverWrapper->vendorManager == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return g_driverWrapper->vendorManager->AddPrinterToDiscovery(g_driverWrapper->GetVendorName(), info);
}

int32_t VendorBsuniDriver::RemovePrinterFromDiscovery(const char *printerId)
{
    PRINT_HILOGI("BsUni callback RemovePrinterFromDiscovery");
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    std::string vendorPrinterId(printerId);
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr || g_driverWrapper->vendorManager == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return g_driverWrapper->vendorManager->RemovePrinterFromDiscovery(g_driverWrapper->GetVendorName(),
                                                                      vendorPrinterId);
}

int32_t VendorBsuniDriver::AddPrinterToCups(const Print_DiscoveryItem *printer,
                                            const Print_PrinterCapability *capability,
                                            const Print_DefaultValue *defaultValue, const char *ppdData)
{
    PRINT_HILOGI("BsUni callback AddPrinterToCups");
    PrinterInfo info;
    if (!UpdatePrinterInfoWithDiscovery(info, printer)) {
        PRINT_HILOGW("update printer info fail");
        return EXTENSION_INVALID_PARAMETER;
    }
    if (!UpdatePrinterInfoWithCapability(info, printer, capability, defaultValue)) {
        PRINT_HILOGW("update printer capability fail");
        return EXTENSION_INVALID_PARAMETER;
    }
    std::string ppdContent;
    if (ppdData != nullptr) {
        ppdContent = std::string(ppdData);
    }
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr || g_driverWrapper->vendorManager == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    std::string vendorName = g_driverWrapper->GetVendorName();
    if (g_driverWrapper->vendorManager->UpdatePrinterToDiscovery(vendorName, info) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("update printer to discovery fail");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return g_driverWrapper->vendorManager->AddPrinterToCupsWithPpd(vendorName, info.GetPrinterId(), ppdContent);
}

int32_t VendorBsuniDriver::RemovePrinterFromCups(const char *printerId)
{
    PRINT_HILOGI("BsUni callback RemovePrinterFromCups");
    if (printerId == nullptr) {
        PRINT_HILOGW("printer id to remove is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    std::string vendorPrinterId(printerId);
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr || g_driverWrapper->vendorManager == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return g_driverWrapper->vendorManager->RemovePrinterFromCups(g_driverWrapper->GetVendorName(), vendorPrinterId);
}

int32_t VendorBsuniDriver::OnCapabilityQueried(const Print_DiscoveryItem *printer,
                                               const Print_PrinterCapability *capability,
                                               const Print_DefaultValue *defaultValue)
{
    PRINT_HILOGI("BsUni callback OnCapabilityQueried");
    LogDiscoveryItem(printer);
    LogPageCapability(capability);
    LogOtherCapability(capability);
    LogDefaultValue(defaultValue);
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return g_driverWrapper->OnPrinterCapabilityQueried(printer, capability, defaultValue);
}

int32_t VendorBsuniDriver::OnPropertiesQueried(const char *printerId, const Print_PropertyList *propertyList)
{
    PRINT_HILOGI("BsUni callback OnPropertiesQueried");
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    LogProperties(propertyList);
    std::string vendorPrinterId(printerId);
    std::lock_guard<std::mutex> lock(g_driverMutex);
    if (g_driverWrapper == nullptr) {
        PRINT_HILOGW("driver released");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return g_driverWrapper->OnPrinterPropertiesQueried(vendorPrinterId, propertyList);
}

VendorBsuniDriver::VendorBsuniDriver() {}

VendorBsuniDriver::~VendorBsuniDriver() {}

bool VendorBsuniDriver::Init(IPrinterVendorManager *manager)
{
    PRINT_HILOGD("Init enter");
    if (!VendorDriverBase::Init(manager)) {
        PRINT_HILOGD("VendorDriverBase init fail");
        return false;
    }
    if (!LoadDriverExtension()) {
        PRINT_HILOGD("Init fail");
        return false;
    }
    PRINT_HILOGD("Init quit");
    return true;
}
void VendorBsuniDriver::UnInit()
{
    SetDriverWrapper(nullptr);
    vendorExtension = nullptr;
    if (bsUniDriverHandler != nullptr) {
        dlclose(bsUniDriverHandler);
        bsUniDriverHandler = nullptr;
    }
    VendorDriverBase::UnInit();
}

void VendorBsuniDriver::OnCreate()
{
    PRINT_HILOGD("OnCreate enter");
    VendorDriverBase::OnCreate();
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return;
    }
    if (vendorExtension->onCreate == nullptr) {
        PRINT_HILOGW("onCreate is null");
        return;
    }
    SetDriverWrapper(this);
    printServiceAbility.addPrinterToDiscovery = AddPrinterToDiscovery;
    printServiceAbility.removePrinterFromDiscovery = RemovePrinterFromDiscovery;
    printServiceAbility.addPrinterToCups = AddPrinterToCups;
    printServiceAbility.removePrinterFromCups = RemovePrinterFromCups;
    printServiceAbility.onCapabilityQueried = OnCapabilityQueried;
    printServiceAbility.onPropertiesQueried = OnPropertiesQueried;
    int32_t result = vendorExtension->onCreate(&printServiceAbility);
    PRINT_HILOGI("OnCreate quit: %{public}d", result);
}
void VendorBsuniDriver::OnDestroy()
{
    PRINT_HILOGD("OnDestroy enter");
    syncWait.Notify();
    VendorDriverBase::OnDestroy();
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return;
    }
    if (vendorExtension->onDestroy == nullptr) {
        PRINT_HILOGW("onDestroy is null");
        return;
    }
    int32_t result = vendorExtension->onDestroy();
    SetDriverWrapper(nullptr);
    PRINT_HILOGI("OnDestroy quit: %{public}d", result);
}

void VendorBsuniDriver::OnStartDiscovery()
{
    PRINT_HILOGD("OnStartDiscovery enter");
    VendorDriverBase::OnStartDiscovery();
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return;
    }
    if (vendorExtension->onStartDiscovery == nullptr) {
        PRINT_HILOGW("onStartDiscovery is null");
        return;
    }
    int32_t result = vendorExtension->onStartDiscovery();
    PRINT_HILOGI("OnStartDiscovery quit: %{public}d", result);
}
void VendorBsuniDriver::OnStopDiscovery()
{
    PRINT_HILOGD("OnStopDiscovery enter");
    VendorDriverBase::OnStopDiscovery();
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return;
    }
    if (vendorExtension->onStopDiscovery == nullptr) {
        PRINT_HILOGW("onStopDiscovery is null");
        return;
    }
    int32_t result = vendorExtension->onStopDiscovery();
    PRINT_HILOGI("OnStopDiscovery quit: %{public}d", result);
}

std::string VendorBsuniDriver::GetVendorName()
{
    return "driver.bsuni";
}

bool VendorBsuniDriver::OnQueryCapability(const std::string &printerId, int timeout)
{
    PRINT_HILOGD("OnQueryCapability enter");
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return false;
    }
    if (vendorExtension->onQueryCapability == nullptr) {
        PRINT_HILOGW("onQueryCapability is null");
        return false;
    }
    int32_t result = vendorExtension->onQueryCapability(printerId.c_str());
    PRINT_HILOGI("OnQueryCapability result: %{public}d", result);
    if (result == 0) {
        syncWait.Wait(timeout);
        PRINT_HILOGD("OnQueryCapability quit");
        return true;
    }
    PRINT_HILOGD("OnQueryCapability quit");
    return false;
}

bool VendorBsuniDriver::OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol)
{
    PRINT_HILOGD("OnQueryCapabilityByIp enter");
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return false;
    }
    if (vendorExtension->onQueryCapabilityByIp == nullptr) {
        PRINT_HILOGW("OnQueryCapabilityByIp is null");
        return false;
    }
    int32_t result = vendorExtension->onQueryCapabilityByIp(printerIp.c_str(), protocol.c_str());
    PRINT_HILOGI("OnQueryCapabilityByIp quit: %{public}d", result);
    return result == 0;
}

bool VendorBsuniDriver::OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys)
{
    PRINT_HILOGD("OnQueryProperties enter");
    bool ret = false;
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return ret;
    }
    if (vendorExtension->onQueryProperties == nullptr) {
        PRINT_HILOGW("onQueryProperties is null");
        return ret;
    }
    Print_StringList propertyKeyList = { 0 };
    if (ConvertStringVectorToStringList(propertyKeys, propertyKeyList)) {
        int32_t result = vendorExtension->onQueryProperties(printerId.c_str(), &propertyKeyList);
        PRINT_HILOGI("OnQueryProperties quit: %{public}d", result);
        if (result == 0) {
            ret = true;
        }
    }
    ReleaseStringList(propertyKeyList);
    PRINT_HILOGD("OnQueryProperties quit");
    return ret;
}

int32_t VendorBsuniDriver::OnPrinterPropertiesQueried(const std::string &printerId,
                                                      const Print_PropertyList *propertyList)
{
    PRINT_HILOGD("OnPrinterPropertiesQueried enter");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    std::string key = PRINTER_PROPERTY_KEY_CUPS_PPD_FILE;
    std::string ppdData = FindPropertyFromPropertyList(propertyList, key);
    if (!ppdData.empty()) {
        PRINT_HILOGI("ppdData queried");
        if (vendorManager->OnPrinterPpdQueried(GetVendorName(), printerId, ppdData)) {
            if (vendorExtension != nullptr && vendorExtension->onConnectPrinter != nullptr) {
                vendorExtension->onConnectPrinter(printerId.c_str());
            }
        }
    }

    key = PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES;
    std::string suppliesData = FindPropertyFromPropertyList(propertyList, key);
    if (!suppliesData.empty()) {
        PRINT_HILOGI("suppliesData queried");
        PRINT_HILOGD("supplies: %{public}s", suppliesData.c_str());
    }

    key = PRINTER_PROPERTY_KEY_DEVICE_STATE;
    std::string stateData = FindPropertyFromPropertyList(propertyList, key);
    if (!stateData.empty()) {
        PRINT_HILOGI("stateData queried");
        Print_PrinterState state = PRINTER_UNAVAILABLE;
        if (ConvertStringToPrinterState(stateData, state)) {
            OnPrinterStateQueried(printerId, state);
        }
    }
    PRINT_HILOGD("OnPrinterPropertiesQueried quit");
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::OnPrinterCapabilityQueried(const Print_DiscoveryItem *printer,
                                                      const Print_PrinterCapability *capability,
                                                      const Print_DefaultValue *defaultValue)
{
    PRINT_HILOGD("OnPrinterCapabilityQueried enter");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto printerInfo = ConvertVendorCapabilityToPrinterInfo(printer, capability, defaultValue);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo);
    std::string printerUri;
    if (printer != nullptr && printer->printerUri != nullptr) {
        printerUri = std::string(printer->printerUri);
    }
    std::string printerId = printerInfo->GetPrinterId();
    std::string globalPrinterId = GetGlobalPrinterId(printerId);
    bool connecting = vendorManager->IsConnectingPrinter(globalPrinterId, printerUri);
    if (connecting) {
        vendorManager->SetConnectingPrinter(ID_AUTO, globalPrinterId);
        PRINT_HILOGD("connecting %{public}s, query propertis", globalPrinterId.c_str());
        std::vector<std::string> keyList;
        keyList.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
        keyList.push_back(PRINTER_PROPERTY_KEY_CUPS_PPD_FILE);
        OnQueryProperties(printerId, keyList);
    }
    syncWait.Notify();
    PRINT_HILOGD("OnPrinterCapabilityQueried quit");
    return EXTENSION_ERROR_NONE;
}
