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

#include "vendor_wlan_group.h"
#include "print_log.h"
#include "print_utils.h"
#include "file_ex.h"

using namespace OHOS::Print;
namespace {
    const std::string VENDOR_BSUNI_URI_START = "://";
    const std::string VENDOR_BSUNI_URI_END = ":";
    const std::string VENDOR_CONVERTED_PRINTERID = "uuid";
    const std::string VENDOR_BSUNI_GS_PATH = "/system/bin/uni_print_driver/ghostscript/bin/gs";
}

VendorWlanGroup::VendorWlanGroup(VendorManager *vendorManager) : parentVendorManager(vendorManager)
{
    hasGs = FileExists(VENDOR_BSUNI_GS_PATH);
}

std::string VendorWlanGroup::GetVendorName()
{
    return VENDOR_WLAN_GROUP;
}

bool VendorWlanGroup::OnQueryCapability(const std::string &printerId, int timeout)
{
    PRINT_HILOGI("OnQueryCapability enter.");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    auto ppdDriver = parentVendorManager->FindDriverByVendorName(VENDOR_PPD_DRIVER);
    if (ppdDriver != nullptr) {
        printerVendorGroupList_[printerId] = VENDOR_PPD_DRIVER;
        auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
        if (printerInfo != nullptr && ppdDriver->OnQueryProperties(printerId, std::vector<std::string>(1,
            printerInfo->GetPrinterMake()))) {
            if (ppdDriver->OnQueryCapability(printerId, timeout)) {
                PRINT_HILOGI("on query capability on ppd vendor seccess.");
                return true;
            }
        }
        RemovePrinterVendorGroupById(printerId);
    }
    if (IsBsunidriverSupport(printerId)) {
        printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
        auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
        auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
        if (bsuniDriver != nullptr && printerInfo != nullptr &&
            bsuniDriver->OnQueryCapability(ExtractBsUniPrinterIdByPrinterInfo(*printerInfo), timeout)) {
            PRINT_HILOGI("on query capability on bsuni vendor seccess.");
            return true;
        }
        RemovePrinterVendorGroupById(printerId);
    } else {
        printerVendorGroupList_[printerId] = VENDOR_IPP_EVERYWHERE;
        auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
        if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapabilityByIp(printerId, "auto")) {
            PRINT_HILOGI("on query capability on ipp everywhere seccess.");
            return true;
        }
        RemovePrinterVendorGroupById(printerId);
    }
    PRINT_HILOGE("no vendor can query capability.");
    return false;
}

bool VendorWlanGroup::OnQueryCapabilityByIp(const std::string &printerIp, const std::string &protocol)
{
    PRINT_HILOGI("OnQueryCapabilityByIp enter.");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
    printerVendorGroupList_[printerIp] = VENDOR_BSUNI_DRIVER;
    if (bsuniDriver != nullptr && bsuniDriver->OnQueryCapabilityByIp(printerIp, protocol)) {
        PRINT_HILOGI("on query capability by ip on bsuni vendor seccess.");
        return true;
    }
    RemovePrinterVendorGroupById(printerIp);
    printerVendorGroupList_[printerIp] = VENDOR_IPP_EVERYWHERE;
    auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
    if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapabilityByIp(printerIp, protocol)) {
        PRINT_HILOGI("on query capability by ip on ipp everywhere seccess.");
        return true;
    }
    RemovePrinterVendorGroupById(printerIp);
    PRINT_HILOGE("no vendor can query capability by ip.");
    return false;
}

int32_t VendorWlanGroup::OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return vendorManager->AddPrinterToDiscovery(GetVendorName(), ConvertPrinterInfoId(printerInfo));
}

int32_t VendorWlanGroup::OnUpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return vendorManager->UpdatePrinterToDiscovery(GetVendorName(), ConvertPrinterInfoId(printerInfo));
}

int32_t VendorWlanGroup::OnPrinterRemoved(const std::string &vendorName, const std::string &printerId)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    RemovePrinterVendorGroupById(printerId);
    std::string id(VendorManager::ExtractPrinterId(printerId));
    QueryBsUniPrinterIdByUuidPrinterId(id);
    return vendorManager->RemovePrinterFromDiscovery(GetVendorName(), id);
}

bool VendorWlanGroup::IsConnectingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    QueryBsUniPrinterIdByUuidPrinterId(printerId);
    printerId = GetGlobalPrinterId(printerId);
    return vendorManager->IsConnectingPrinter(printerId, uri);
}

void VendorWlanGroup::SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    QueryBsUniPrinterIdByUuidPrinterId(printerId);
    printerId = GetGlobalPrinterId(printerId);
    vendorManager->SetConnectingPrinter(method, printerId);
}

bool VendorWlanGroup::OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                                          const std::string &ppdData)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    std::string id(printerId);
    QueryBsUniPrinterIdByUuidPrinterId(id);
    return vendorManager->OnPrinterPpdQueried(GetVendorName(), id, ppdData);
}


bool VendorWlanGroup::IsGroupDriver(const std::string &bothPrinterId)
{
    if (bothPrinterId.find(VENDOR_CONVERTED_PRINTERID) != std::string::npos) {
        PRINT_HILOGD("printerId has be converted whit uuid, is group driver!.");
        return true;
    }
    std::string printerId(VendorManager::ExtractPrinterId(bothPrinterId));
    auto iter = printerVendorGroupList_.find(printerId);
    return (iter != printerVendorGroupList_.end() && !iter->second.empty());
}

bool VendorWlanGroup::ConvertGroupDriver(std::string &printerId, std::string &vendorName)
{
    printerId = VendorManager::ExtractPrinterId(printerId);
    if (vendorName == VENDOR_BSUNI_DRIVER) {
        QueryBsUniPrinterIdByUuidPrinterId(printerId);
        return false;
    }
    auto iter = printerVendorGroupList_.find(printerId);
    if (iter != printerVendorGroupList_.end() && !iter->second.empty()) {
        vendorName = VENDOR_WLAN_GROUP;
        return true;
    }
    return false;
}

bool VendorWlanGroup::IsBsunidriverSupport(const std::string &printerId)
{
    PRINT_HILOGD("IsBsunidriverSupport enter");
    auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (printerInfo == nullptr) {
        return false;
    }
    std::string supportValue;
    if (printerInfo->HasOption() && nlohmann::json::accept(printerInfo->GetOption())) {
        nlohmann::json option = nlohmann::json::parse(printerInfo->GetOption());
        if (option.contains("bsunidriverSupport") && option["bsunidriverSupport"].is_string()) {
            supportValue = option["bsunidriverSupport"].get<std::string>();
        }
    }
    PRINT_HILOGD("IsBsunidriverSupport bsunidriverSupport=%{public}s", supportValue.c_str());
    if (supportValue == "true") {
        return true;
    } else if (supportValue == "need_gs") {
        return hasGs;
    } else {
        return false;
    }
}

void VendorWlanGroup::RemovePrinterVendorGroupById(const std::string &printerId)
{
    auto iter = printerVendorGroupList_.find(printerId);
    if (iter != printerVendorGroupList_.end()) {
        PRINT_HILOGD("remove printer from vendor group list");
        printerVendorGroupList_.erase(printerId);
    }
}

std::string VendorWlanGroup::ConvertGroupGlobalPrinterId(const std::string &bothPrinterId)
{
    std::string printerId(VendorManager::ExtractPrinterId(bothPrinterId));
    return PrintUtils::GetGlobalId(VendorManager::GetGlobalVendorName(GetVendorName()), printerId);
}

void VendorWlanGroup::QueryBsUniPrinterIdByUuidPrinterId(std::string &bsUniPrinterId)
{
    std::lock_guard<std::mutex> lock(uuidMapMutex);
    auto item = printerIdToUuidMap_.find(bsUniPrinterId);
    if (item != printerIdToUuidMap_.end() && !item->second.empty()) {
        bsUniPrinterId = std::string(item->second);
    }
}

void VendorWlanGroup::UpdateMappedPrinterId(const std::string &bsUniPrinterId, const std::string printerId)
{
    std::lock_guard<std::mutex> lock(uuidMapMutex);
    printerIdToUuidMap_[bsUniPrinterId] = printerId;
}

PrinterInfo VendorWlanGroup::ConvertPrinterInfoId(const PrinterInfo &printerInfo)
{
    PrinterInfo info(printerInfo);
    if (printerInfo.HasOption() && nlohmann::json::accept(std::string(printerInfo.GetOption()))) {
        nlohmann::json option = nlohmann::json::parse(std::string(printerInfo.GetOption()));
        if (option != nullptr && option.contains("printer-uuid") && option["printer-uuid"].is_string()) {
            info.SetPrinterId(std::string(option["printer-uuid"]));
            UpdateMappedPrinterId(printerInfo.GetPrinterId(), std::string(option["printer-uuid"]));
            PRINT_HILOGD("Convert PrinterId with uuid");
            return info;
        }
    }
    return printerInfo;
}

std::string VendorWlanGroup::ExtractBsUniPrinterIdByPrinterInfo(const PrinterInfo &printerInfo)
{
    std::string uri(printerInfo.GetUri());
    if (uri.empty()) {
        return "";
    }
    auto pos_start = uri.find_first_of(VENDOR_BSUNI_URI_START);
    auto pos_end = uri.find_last_of(VENDOR_BSUNI_URI_END);
    if (pos_start == std::string::npos || uri.length() <= pos_start + 1 ||
        pos_end == std::string::npos || uri.length() <= pos_end + 1 ||
        pos_end - pos_start <= VENDOR_BSUNI_URI_START.length()) {
        return "";
    }
    return uri.substr(pos_start + VENDOR_BSUNI_URI_START.length(),
        pos_end - pos_start - VENDOR_BSUNI_URI_START.length());
}
