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

#include "vendor_ipp_everywhere.h"
#include "print_log.h"
#include <nlohmann/json.hpp>

using namespace OHOS::Print;
using json = nlohmann::json;

VendorIppEveryWhere::VendorIppEveryWhere() {}

VendorIppEveryWhere::~VendorIppEveryWhere() {}

std::string VendorIppEveryWhere::GetVendorName()
{
    return "driver.ipp.everywhere";
}

bool VendorIppEveryWhere::Init(IPrinterVendorManager *manager)
{
    if (!VendorDriverBase::Init(manager)) {
        PRINT_HILOGD("VendorDriverBase init fail");
        return false;
    }
    return true;
}
void VendorIppEveryWhere::UnInit()
{
    VendorDriverBase::UnInit();
}
void VendorIppEveryWhere::OnCreate()
{
    opQueue.Run();
}
void VendorIppEveryWhere::OnDestroy()
{
    opQueue.Stop();
}
void VendorIppEveryWhere::OnStartDiscovery() {}
void VendorIppEveryWhere::OnStopDiscovery() {}

bool VendorIppEveryWhere::OnQueryCapability(const std::string &printerId, int timeout)
{
    auto op = std::bind(&VendorIppEveryWhere::QueryCapabilityByUri, this, printerId);
    return opQueue.Push(op);
}

bool VendorIppEveryWhere::OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol)
{
    if (protocol != "auto" && protocol != "ipp") {
        PRINT_HILOGW("protocol not support");
        return false;
    }
    PRINT_HILOGI("QueryCapabilityByIp begin");
    std::string uri = "ipp://" + printerIp + ":631/ipp/print";
    auto op = std::bind(&VendorIppEveryWhere::ConnectPrinterByUri, this, uri);
    return opQueue.Push(op);
}

bool VendorIppEveryWhere::OnQueryProperties(const std::string &printerId, const std::vector<std::string> &propertyKeys)
{
    bool ret = false;
    for (auto const &key : propertyKeys) {
        if (key == PRINTER_PROPERTY_KEY_DEVICE_STATE) {
            auto op = std::bind(&VendorIppEveryWhere::QueryPrinterStatusByUri, this, printerId);
            if (opQueue.Push(op)) {
                ret = true;
            }
        }
    }
    return ret;
}

void VendorIppEveryWhere::QueryCapabilityByUri(const std::string &uri)
{
    PRINT_HILOGI("QueryCapabilityByUri enter");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    auto printerInfo = QueryPrinterInfoByUri(uri);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("QueryPrinterInfoByUri fail");
        return;
    }
    PRINT_HILOGI("get printer info success");
    if (vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("UpdatePrinterToDiscovery fail");
        return;
    }
    PRINT_HILOGI("QueryCapabilityByUri quit");
}

void VendorIppEveryWhere::ConnectPrinterByUri(const std::string &uri)
{
    PRINT_HILOGI("ConnectPrinterByUri enter");
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    auto printerInfo = QueryPrinterInfoByUri(uri);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("ConvertCapabilityToInfo fail");
        return;
    }
    PRINT_HILOGI("get printer info success");
    if (vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("UpdatePrinterToDiscovery fail");
        return;
    }
    PRINT_HILOGI("UpdatePrinterToDiscovery success");
    if (vendorManager->AddPrinterToCupsWithPpd(GetVendorName(), printerInfo->GetPrinterId(), "") !=
        EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("AddPrinterToCupsWithPpd fail");
        return;
    }
    PRINT_HILOGI("ConnectPrinterByUri quit");
}

std::shared_ptr<PrinterInfo> VendorIppEveryWhere::QueryPrinterInfoByUri(const std::string &uri)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return nullptr;
    }
    PrinterCapability printerCap;
    if (!vendorManager->QueryPrinterCapabilityByUri(uri, printerCap)) {
        PRINT_HILOGW("QueryPrinterCapabilityByUri fail");
        return nullptr;
    }
    PRINT_HILOGI("QueryPrinterCapabilityByUri success");
    return ConvertCapabilityToInfo(printerCap, uri);
}

std::shared_ptr<PrinterInfo> VendorIppEveryWhere::ConvertCapabilityToInfo(const PrinterCapability &printerCap,
    const std::string &printerUri)
{
    if (!printerCap.HasOption()) {
        PRINT_HILOGW("empty option");
        return nullptr;
    }
    std::string capOption = printerCap.GetOption();
    if (!json::accept(capOption)) {
        PRINT_HILOGW("invalid option");
        return nullptr;
    }
    nlohmann::json capJson = json::parse(capOption, nullptr, false);
    if (capJson.is_discarded()) {
        PRINT_HILOGW("json discarded");
        return nullptr;
    }
    if (!capJson.contains("printerName") || !capJson["printerName"].is_string()) {
        PRINT_HILOGW("printerName invalid");
        return nullptr;
    }
    std::string printerName = capJson["printerName"].get<std::string>();
    if (!capJson.contains("make") || !capJson["make"].is_string()) {
        PRINT_HILOGW("make invalid");
        return nullptr;
    }
    std::string printerMaker = capJson["make"].get<std::string>();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return nullptr;
    }
    printerInfo->SetPrinterName(printerName);
    printerInfo->SetUri(printerUri);
    printerInfo->SetPrinterMake(printerMaker);
    printerInfo->SetPrinterId(printerUri);
    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    printerInfo->SetCapability(printerCap);
    nlohmann::json option;
    option["printerName"] = printerName;
    option["printerUri"] = printerUri;
    option["make"] = printerMaker;
    printerInfo->SetOption(option.dump());
    return printerInfo;
}

void VendorIppEveryWhere::QueryPrinterStatusByUri(const std::string &uri)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return;
    }
    PrinterStatus status = PRINTER_STATUS_UNAVAILABLE;
    if (!vendorManager->QueryPrinterStatusByUri(uri, status)) {
        return;
    }
    OnPrinterStateQueried(uri, static_cast<Print_PrinterState>(status));
}
