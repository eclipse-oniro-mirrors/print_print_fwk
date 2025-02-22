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
#include <json/json.h>
#include "print_json_util.h"

using namespace OHOS::Print;
namespace {
const std::string VENDOR_IPP_START = "ipp://";
const std::string VENDOR_IPP_END = ":631/ipp/print";
}

static const std::string VENDOR_NAME = "driver.ipp.everywhere";

VendorIppEveryWhere::VendorIppEveryWhere() {}

VendorIppEveryWhere::~VendorIppEveryWhere() {}

std::string VendorIppEveryWhere::GetVendorName()
{
    return VENDOR_IPP_EVERYWHERE;
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
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    auto printerInfo = vendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("invalid printerId");
        return false;
    }
    std::string printerUri(printerInfo->GetUri());
    if (printerUri.find(VENDOR_IPP_START) == std::string::npos) {
        PRINT_HILOGW("ipp everywhere not support");
        return false;
    }
    auto op = std::bind(&VendorIppEveryWhere::ConnectPrinterByPrinterIdAndUri, this, printerId, printerUri);
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
    auto printerInfo = QueryPrinterInfoByUri(uri);
    if (!UpdateCapability(printerInfo)) {
        PRINT_HILOGW("update capability fail");
        return;
    }
    PRINT_HILOGI("QueryCapabilityByUri quit");
}

void VendorIppEveryWhere::ConnectPrinterByUri(const std::string &uri)
{
    PRINT_HILOGI("ConnectPrinterByUri enter");
    auto printerInfo = QueryPrinterInfoByUri(uri);
    if (!ConnectPrinter(printerInfo)) {
        PRINT_HILOGW("connect fail");
        return;
    }
    PRINT_HILOGI("ConnectPrinterByUri quit");
}

void VendorIppEveryWhere::ConnectPrinterByPrinterIdAndUri(const std::string &printerId, const std::string &uri)
{
    PRINT_HILOGI("ConnectPrinterByPrinterIdAndUri enter");
    auto printerInfo = QueryPrinterInfoByUri(uri);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("connect fail");
        return;
    }
    printerInfo->SetPrinterId(printerId);
    if (!ConnectPrinter(printerInfo)) {
        PRINT_HILOGW("connect fail");
        return;
    }
    PRINT_HILOGI("ConnectPrinterByPrinterIdAndUri quit");
}

bool VendorIppEveryWhere::UpdateCapability(std::shared_ptr<PrinterInfo> printerInfo)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo fail");
        return false;
    }
    PRINT_HILOGI("get printer info success");
    if (vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("UpdatePrinterToDiscovery fail");
        return false;
    }
    return true;
}

bool VendorIppEveryWhere::ConnectPrinter(std::shared_ptr<PrinterInfo> printerInfo)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printer info fail");
        return false;
    }
    PRINT_HILOGI("get printer info success");
    auto discoveredInfo = vendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerInfo->GetPrinterId());
    if (discoveredInfo != nullptr) {
        printerInfo->SetPrinterName(discoveredInfo->GetPrinterName());
    }
    if (vendorManager->UpdatePrinterToDiscovery(GetVendorName(), *printerInfo) != EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("UpdatePrinterToDiscovery fail");
        return false;
    }
    PRINT_HILOGI("UpdatePrinterToDiscovery success");
    if (vendorManager->AddPrinterToCupsWithPpd(GetVendorName(), printerInfo->GetPrinterId(), "") !=
        EXTENSION_ERROR_NONE) {
        PRINT_HILOGW("AddPrinterToCupsWithPpd fail");
        return false;
    }
    return true;
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
    Json::Value capJson;
    if (!PrintJsonUtil::Parse(capOption, capJson)) {
        PRINT_HILOGW("invalid option");
        return nullptr;
    }
    if (!capJson.isMember("printerName") || !capJson["printerName"].isString()) {
        PRINT_HILOGW("printerName invalid");
        return nullptr;
    }
    std::string printerName = capJson["printerName"].asString();
    if (!capJson.isMember("make") || !capJson["make"].isString()) {
        PRINT_HILOGW("make invalid");
        return nullptr;
    }
    std::string printerMaker = capJson["make"].asString();
    std::shared_ptr<PrinterInfo> printerInfo = std::make_shared<PrinterInfo>();
    printerInfo->SetPrinterName(printerName);
    printerInfo->SetUri(printerUri);
    printerInfo->SetPrinterMake(printerMaker);
    printerInfo->SetPrinterId(printerUri);
    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    printerInfo->SetCapability(printerCap);
    Json::Value option;
    option["printerName"] = printerName;
    option["printerUri"] = printerUri;
    option["make"] = printerMaker;
    printerInfo->SetOption(PrintJsonUtil::WriteString(option));
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

bool VendorIppEveryWhere::ConvertPrinterIdByUri(std::string &uri)
{
    if (uri.empty()) {
        return false;
    }
    auto pos_start = uri.find(VENDOR_IPP_START);
    auto pos_end = uri.find(VENDOR_IPP_END);
    if (pos_start == std::string::npos || uri.length() <= pos_start + VENDOR_IPP_START.length() ||
        pos_end == std::string::npos || pos_end - pos_start <= VENDOR_IPP_START.length()) {
        return false;
    }
    uri = uri.substr(pos_start + VENDOR_IPP_START.length(), pos_end - pos_start - VENDOR_IPP_START.length());
    PRINT_HILOGD("ConvertPrinterIdByUri seccess");
    return true;
}
