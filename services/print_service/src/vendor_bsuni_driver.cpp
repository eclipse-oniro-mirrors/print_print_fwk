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
std::mutex g_instanceMutex;
std::weak_ptr<VendorBsuniDriver> g_weakInstance;

static const char* CUPS_ROOT_DIR = "/data/service/el1/public/print_service/cups";
#ifdef ENTERPRISE_ENABLE
static const char* CUPS_ENTERPRISE_ROOT_DIR = "/data/service/el1/public/print_service/cups_enterprise";
#endif  // ENTERPRISE_ENABLE
}  // namespace

void VendorBsuniDriver::SetDriverWrapper(const std::shared_ptr<VendorBsuniDriver>& driver)
{
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    g_weakInstance = driver;
}

std::shared_ptr<VendorBsuniDriver> VendorBsuniDriver::GetActiveInstance()
{
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    return g_weakInstance.lock();
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
    
    auto info = std::make_shared<PrinterInfo>();
    if (!UpdatePrinterInfoWithDiscovery(*info, discoveryItem)) {
        PRINT_HILOGW("fail to convert discoveryItem to printer info");
        return EXTENSION_INVALID_PARAMETER;
    }
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    auto safeOp = [weakDriver, info]() {
        if (auto driver = weakDriver.lock()) {
            driver->OnDiscoveredPrinterAdd(info);
        } else {
            PRINT_HILOGW("driver already destroyed");
        }
    };
    if (!driver->opQueue.Push(safeOp)) {
        PRINT_HILOGW("fail to add discovered printer");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::RemovePrinterFromDiscovery(const char *printerId)
{
    PRINT_HILOGI("BsUni callback RemovePrinterFromDiscovery");
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    auto vendorPrinterId = std::make_shared<std::string>(printerId);
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    auto safeOp = [weakDriver, vendorPrinterId]() {
        if (auto driver = weakDriver.lock()) {
            driver->OnDiscoveredPrinterRemove(vendorPrinterId);
        } else {
            PRINT_HILOGW("driver already destroyed");
        }
    };
    if (!driver->opQueue.Push(safeOp)) {
        PRINT_HILOGW("fail to remove discovered printer");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::AddPrinterToCups(const Print_DiscoveryItem *printer,
    const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue, const char *ppdData)
{
    PRINT_HILOGI("BsUni callback AddPrinterToCups");
    auto info = std::make_shared<PrinterInfo>();
    if (!UpdatePrinterInfoWithDiscovery(*info, printer)) {
        PRINT_HILOGW("update printer info fail");
        return EXTENSION_INVALID_PARAMETER;
    }
    if (!UpdatePrinterInfoWithCapability(*info, printer, capability, defaultValue)) {
        PRINT_HILOGW("update printer capability fail");
        return EXTENSION_INVALID_PARAMETER;
    }
    std::shared_ptr<std::string> ppdContent;
    if (ppdData != nullptr) {
        ppdContent = std::make_shared<std::string>(ppdData);
    }
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    auto safeOp = [weakDriver, info, ppdContent]() {
        if (auto driver = weakDriver.lock()) {
            driver->OnCupsPrinterAdd(info, ppdContent);
        } else {
            PRINT_HILOGW("driver already destroyed");
        }
    };
    if (!driver->opQueue.Push(safeOp)) {
        PRINT_HILOGW("fail to add cups printer");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::RemovePrinterFromCups(const char *printerId)
{
    PRINT_HILOGI("BsUni callback RemovePrinterFromCups");
    if (printerId == nullptr) {
        PRINT_HILOGW("printer id to remove is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    auto vendorPrinterId = std::make_shared<std::string>(printerId);
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    auto safeOp = [weakDriver, vendorPrinterId]() {
        if (auto driver = weakDriver.lock()) {
            driver->OnCupsPrinterRemove(vendorPrinterId);
        } else {
            PRINT_HILOGW("driver already destroyed");
        }
    };
    if (!driver->opQueue.Push(safeOp)) {
        PRINT_HILOGW("fail to remove cups printer");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::OnCapabilityQueried(const Print_DiscoveryItem *printer,
    const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    PRINT_HILOGI("BsUni callback OnCapabilityQueried");
    LogDiscoveryItem(printer);
    LogPageCapability(capability);
    LogOtherCapability(capability);
    LogDefaultValue(defaultValue);
    auto printerInfo = ConvertVendorCapabilityToPrinterInfo(printer, capability, defaultValue);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        if (printer == nullptr || printer->printerId == nullptr) {
            return EXTENSION_INVALID_PARAMETER;
        }
        PrinterInfo info;
        info.SetPrinterId(printer->printerId);
        printerInfo = std::make_shared<PrinterInfo>(info);
    }
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    auto safeOp = [weakDriver, printerInfo]() {
        if (auto driver = weakDriver.lock()) {
            driver->OnPrinterCapabilityQueried(printerInfo);
        } else {
            PRINT_HILOGW("driver already destroyed");
        }
    };
    if (!driver->opQueue.Push(safeOp)) {
        PRINT_HILOGW("fail to queue capability");
        return EXTENSION_ERROR_CALLBACK_FAIL;
    }
    return EXTENSION_ERROR_NONE;
}

int32_t VendorBsuniDriver::OnPropertiesQueried(const char *printerId, const Print_PropertyList *propertyList)
{
    PRINT_HILOGI("BsUni callback OnPropertiesQueried");
    if (printerId == nullptr || propertyList == nullptr) {
        PRINT_HILOGW("printerId is null");
        return EXTENSION_INVALID_PARAMETER;
    }
    LogProperties(propertyList);
    auto vendorPrinterId = std::make_shared<std::string>(printerId);
    auto driver = GetActiveInstance();
    if (!driver) {
        PRINT_HILOGW("driver instance not available or already destroyed");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    auto weakDriver = std::weak_ptr<VendorBsuniDriver>(driver);
    std::string key = PRINTER_PROPERTY_KEY_CUPS_PPD_FILE;
    auto ppdData = FindPropertyFromPropertyList(propertyList, key);
    if (ppdData != nullptr) {
        auto safeOp = [weakDriver, vendorPrinterId, ppdData]() {
            if (auto driver = weakDriver.lock()) {
                driver->OnPpdQueried(vendorPrinterId, ppdData);
            } else {
                PRINT_HILOGW("driver already destroyed");
            }
        };
        if (!driver->opQueue.Push(safeOp)) {
            PRINT_HILOGW("fail to queue ppd");
            return EXTENSION_ERROR_CALLBACK_FAIL;
        }
    }
    key = PRINTER_PROPERTY_KEY_DEVICE_STATE;
    auto stateData = FindPropertyFromPropertyList(propertyList, key);
    if (stateData != nullptr) {
        auto safeOp = [weakDriver, vendorPrinterId, stateData]() {
            if (auto driver = weakDriver.lock()) {
                driver->OnStateQueried(vendorPrinterId, stateData);
            } else {
                PRINT_HILOGW("driver already destroyed");
            }
        };
        if (!driver->opQueue.Push(safeOp)) {
            PRINT_HILOGW("fail to queue state");
            return EXTENSION_ERROR_CALLBACK_FAIL;
        }
    }
    return EXTENSION_ERROR_NONE;
}

VendorBsuniDriver::VendorBsuniDriver()
{}

VendorBsuniDriver::~VendorBsuniDriver()
{
    UnInit();
}

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
    opQueue.Stop();
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
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    if (vendorExtension->onCreate == nullptr) {
        PRINT_HILOGW("onCreate is null");
        return;
    }
    opQueue.Run();
    SetDriverWrapper(shared_from_this());
    printServiceAbility.addPrinterToDiscovery = AddPrinterToDiscovery;
    printServiceAbility.removePrinterFromDiscovery = RemovePrinterFromDiscovery;
    printServiceAbility.addPrinterToCups = AddPrinterToCups;
    printServiceAbility.removePrinterFromCups = RemovePrinterFromCups;
    printServiceAbility.onCapabilityQueried = OnCapabilityQueried;
    printServiceAbility.onPropertiesQueried = OnPropertiesQueried;
    
#ifdef ENTERPRISE_ENABLE
    if (vendorManager->IsEnterprise()) {
        PRINT_HILOGI("vendorManager onCreate in enterprise");
        int32_t result = vendorExtension->onCreate(&printServiceAbility, CUPS_ENTERPRISE_ROOT_DIR);
        PRINT_HILOGI("OnCreate quit: %{public}d", result);
        return;
    }
#endif  // ENTERPRISE_ENABLE
    PRINT_HILOGI("vendorManager onCreate in user");
    int32_t result = vendorExtension->onCreate(&printServiceAbility, CUPS_ROOT_DIR);
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
    opQueue.Stop();
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
    return VENDOR_BSUNI_DRIVER;
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
    Print_StringList propertyKeyList = {0};
    if (ConvertStringVectorToStringList(propertyKeys, propertyKeyList)) {
        int32_t result = vendorExtension->onQueryProperties(printerId.c_str(), &propertyKeyList);
        PRINT_HILOGI("OnQueryProperties quit: %{public}d", result);
        if (result == 0) {
            ret = true;
        }
    }
    ReleaseStringList(propertyKeyList);
    PRINT_HILOGI("OnQueryProperties quit");
    return ret;
}

void VendorBsuniDriver::OnDiscoveredPrinterAdd(std::shared_ptr<PrinterInfo> printerInfo)
{
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    printerInfo->SetOriginId(GetGlobalPrinterId(printerInfo->GetPrinterId()));
    vendorManager->AddPrinterToDiscovery(GetVendorName(), *printerInfo);
}

void VendorBsuniDriver::OnDiscoveredPrinterRemove(std::shared_ptr<std::string> printerId)
{
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    vendorManager->RemovePrinterFromDiscovery(GetVendorName(), *printerId);
}

void VendorBsuniDriver::OnCupsPrinterAdd(std::shared_ptr<PrinterInfo> printerInfo, std::shared_ptr<std::string> ppdData)
{
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    printerInfo->SetOriginId(GetGlobalPrinterId(printerInfo->GetPrinterId()));
    std::string vendorName = GetVendorName();
    if (vendorManager->UpdatePrinterToDiscovery(vendorName, *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("update printer to discovery fail");
        return;
    }
    if (ppdData == nullptr || ppdData->empty()) {
        PRINT_HILOGW("ppdData is null");
        return;
    }
    vendorManager->AddPrinterToCupsWithPpd(vendorName, printerInfo->GetPrinterId(), BSUNI_PPD_NAME, *ppdData);
}

void VendorBsuniDriver::OnCupsPrinterRemove(std::shared_ptr<std::string> printerId)
{
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    vendorManager->RemovePrinterFromCups(GetVendorName(), *printerId);
}

void VendorBsuniDriver::OnPpdQueried(std::shared_ptr<std::string> printerId, std::shared_ptr<std::string> ppdData)
{
    if (printerId == nullptr || ppdData == nullptr || ppdData->empty()) {
        PRINT_HILOGW("invalid parameters");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    PRINT_HILOGI("ppdData queried");
    if (vendorManager->OnPrinterPpdQueried(GetVendorName(), *printerId, BSUNI_PPD_NAME, *ppdData)) {
        if (vendorExtension != nullptr && vendorExtension->onConnectPrinter != nullptr) {
            vendorExtension->onConnectPrinter(printerId->c_str());
        }
    }
}

void VendorBsuniDriver::OnStateQueried(std::shared_ptr<std::string> printerId, std::shared_ptr<std::string> stateData)
{
    if (printerId == nullptr || stateData == nullptr || stateData->empty()) {
        PRINT_HILOGW("invalid parameters");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    PRINT_HILOGI("stateData queried");
    Print_PrinterState state = PRINTER_UNAVAILABLE;
    if (ConvertStringToPrinterState(*stateData, state)) {
        OnPrinterStateQueried(*printerId, state);
    }
}

std::string VendorBsuniDriver::CreateUriByIpAndProtocol(const std::string &ip, const std::string &protocol)
{
    if (protocol == "ipp") {
        return "ipp://" + ip + ":631/ipp/print";
    }
    if (protocol == "lpd") {
        return "lpd://" +ip + ":515";
    }
    if (protocol == "socket") {
        return "socket://" + ip + ":9100";
    }
    return "";
}

void VendorBsuniDriver::OnPrinterCapabilityQueried(std::shared_ptr<PrinterInfo> printerInfo)
{
    PRINT_HILOGD("OnPrinterCapabilityQueried enter");
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return;
    }
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    printerInfo->SetOriginId(GetGlobalPrinterId(printerInfo->GetPrinterId()));
    if (!printerInfo->HasUri()) {
        PRINT_HILOGW("Building printerInfo!");
        std::string connectProtocol = vendorManager->GetConnectingProtocol();
        if (connectProtocol.empty() || connectProtocol == "auto") {
            PRINT_HILOGW("Require Protocol!");
            return;
        }
        std::string connectIp = vendorManager->GetConnectingPrinter();
        if (connectIp.empty() || connectIp != printerInfo->GetPrinterId()) {
            PRINT_HILOGW("Wrong printerIp!");
            return;
        }
        printerInfo->SetPrinterId(connectIp);
        printerInfo->SetPrinterName(connectIp);
        std::string printerUri = CreateUriByIpAndProtocol(connectIp, connectProtocol);
        if (printerUri.empty()) {
            PRINT_HILOGW("create uri failed.");
            return;
        }
        printerInfo->SetUri(printerUri);
        PRINT_HILOGI("Building printerInfo Success!");
    }
    vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo);
    vendorManager->OnPrinterCapabilityQueried(GetVendorName(), *printerInfo);
    syncWait.Notify();
    PRINT_HILOGD("OnPrinterCapabilityQueried quit");
}

#ifdef ENTERPRISE_ENABLE
void VendorBsuniDriver::OnSwitchSpace()
{
    PRINT_HILOGD("OnSwitchSpace enter");
    if (vendorExtension == nullptr) {
        PRINT_HILOGW("vendorExtension is null");
        return;
    }
    if (vendorExtension->onSwitchSpace == nullptr) {
        PRINT_HILOGW("onSwitchSpace is null");
        return;
    }
    if (vendorManager->IsEnterprise()) {
        PRINT_HILOGI("[] OnSwitchSpace in enterprise");
        int32_t result = vendorExtension->onSwitchSpace(CUPS_ENTERPRISE_ROOT_DIR);
        PRINT_HILOGI("onSwitchSpace quit: %{public}d", result);
        return;
    }
    PRINT_HILOGI("[] OnSwitchSpace in user");
    int32_t result = vendorExtension->onSwitchSpace(CUPS_ROOT_DIR);
    PRINT_HILOGI("onSwitchSpace quit: %{public}d", result);
}
#endif // ENTERPRISE_ENABLE