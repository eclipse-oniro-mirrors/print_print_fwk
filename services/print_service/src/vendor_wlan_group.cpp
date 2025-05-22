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
}

VendorWlanGroup::VendorWlanGroup(VendorManager *vendorManager) : parentVendorManager(vendorManager)
{
    hasGs = FileExists("/system/bin/uni_print_driver/ghostscript/bin/gs");
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
        if (printerInfo != nullptr) {
            ppdDriver->OnPrinterDiscovered(GetVendorName(), *printerInfo);
            std::string ppdName;
            if (ppdDriver->QueryProperty(printerId, PRINTER_PROPERTY_KEY_CUPS_PPD_NAME, ppdName)) {
                if (vendorManager->AddPrinterToCupsWithPpd(GetVendorName(), printerId, ppdName, "") ==
                    EXTENSION_ERROR_NONE) {
                    PRINT_HILOGI("AddPrinterToCupsWithPpd success.");
                    return true;
                }
                PRINT_HILOGI("AddPrinterToCupsWithPpd fail.");
            }
        }
        RemoveGroupPrinterFromVendorGroupList(printerId);
    }
    if (IsBsunidriverSupport(printerId)) {
        printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
        auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
        auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
        if (bsuniDriver != nullptr && printerInfo != nullptr &&
            bsuniDriver->OnQueryCapability(ExtractPrinterIdByPrinterInfo(*printerInfo), timeout)) {
            PRINT_HILOGI("on query capability on bsuni vendor seccess.");
            return true;
        }
        RemoveGroupPrinterFromVendorGroupList(printerId);
    } else {
        printerVendorGroupList_[printerId] = VENDOR_IPP_EVERYWHERE;
        auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
        if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapability(printerId, 0)) {
            PRINT_HILOGI("on query capability on ipp everywhere seccess.");
            return true;
        }
        RemoveGroupPrinterFromVendorGroupList(printerId);
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
    RemoveGroupPrinterFromVendorGroupList(printerIp);
    printerVendorGroupList_[printerIp] = VENDOR_IPP_EVERYWHERE;
    auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
    if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapabilityByIp(printerIp, protocol)) {
        PRINT_HILOGI("on query capability by ip on ipp everywhere seccess.");
        return true;
    }
    RemoveGroupPrinterFromVendorGroupList(printerIp);
    PRINT_HILOGE("no vendor can query capability by ip.");
    return false;
}

int32_t VendorWlanGroup::OnPrinterDiscovered(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    return parentVendorManager->AddPrinterToDiscovery(GetVendorName(), ConvertPrinterInfoId(printerInfo));
}

int32_t VendorWlanGroup::OnUpdatePrinterToDiscovery(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    if (CheckPrinterAddedByIp(printerInfo.GetPrinterId())) {
        PRINT_HILOGI("OnUpdatePrinterToDiscovery PrinterAddedByIp");
        return parentVendorManager->UpdatePrinterToDiscovery(GetVendorName(), ConvertIpPrinterName(printerInfo));
    }
    return parentVendorManager->UpdatePrinterToDiscovery(GetVendorName(), ConvertPrinterInfoId(printerInfo));
}

int32_t VendorWlanGroup::OnPrinterRemoved(const std::string &vendorName, const std::string &printerId)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    std::string groupPrinterId = GetGroupPrinterId(printerId);
    RemoveGroupPrinterFromVendorGroupList(printerId);
    RemovedGroupPrinter(printerId);
    return parentVendorManager->RemovePrinterFromDiscovery(GetVendorName(), groupPrinterId);
}

bool VendorWlanGroup::IsConnectingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    std::string globalPrinterId = GetGlobalPrinterId(groupPrinterId);
    return parentVendorManager->IsConnectingPrinter(globalPrinterId, uri);
}

ConnectMethod VendorWlanGroup::GetConnectingMethod(const std::string &globalPrinterIdOrIp)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return ID_AUTO;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    std::string globalPrinterId = GetGlobalPrinterId(groupPrinterId);
    return parentVendorManager->GetConnectingMethod(globalPrinterId);
}

void VendorWlanGroup::SetConnectingPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    std::string globalPrinterId = GetGlobalPrinterId(groupPrinterId);
    parentVendorManager->SetConnectingPrinter(method, globalPrinterId);
}

bool VendorWlanGroup::OnPrinterPpdQueried(const std::string &vendorName, const std::string &printerId,
                                          const std::string &ppdName, const std::string &ppdData)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    return parentVendorManager->OnPrinterPpdQueried(GetVendorName(), groupPrinterId, ppdName, ppdData);
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
        printerId = GetGroupPrinterId(printerId);
        return false;
    }
    auto iter = printerVendorGroupList_.find(printerId);
    if (iter != printerVendorGroupList_.end() && !iter->second.empty()) {
        vendorName = VENDOR_WLAN_GROUP;
        return true;
    }
    return false;
}

bool VendorWlanGroup::IsBsunidriverSupport(const std::string &groupPrinterId)
{
    PRINT_HILOGD("IsBsunidriverSupport enter");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), groupPrinterId);
    if (printerInfo == nullptr) {
        return false;
    }
    std::string supportValue;
    Json::Value option;
    if (printerInfo->HasOption() && PrintJsonUtil::Parse(printerInfo->GetOption(), option)) {
        if (PrintJsonUtil::IsMember(option, "bsunidriverSupport") && option["bsunidriverSupport"].isString()) {
            supportValue = option["bsunidriverSupport"].asString();
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

void VendorWlanGroup::RemoveGroupPrinterFromVendorGroupList(const std::string &groupPrinterId)
{
    auto iter = printerVendorGroupList_.find(groupPrinterId);
    if (iter != printerVendorGroupList_.end()) {
        PRINT_HILOGD("remove printer from vendor group list");
        printerVendorGroupList_.erase(groupPrinterId);
    }
}

std::string VendorWlanGroup::QueryVendorDriverByGroupPrinterId(const std::string &groupPrinterId)
{
    auto iter = printerVendorGroupList_.find(groupPrinterId);
    if (iter != printerVendorGroupList_.end()) {
        return iter->second;
    }
    PRINT_HILOGE("query printer vendor driver failed");
    return "";
}

std::string VendorWlanGroup::ConvertGroupGlobalPrinterId(const std::string &bothPrinterId)
{
    std::string printerId(VendorManager::ExtractPrinterId(bothPrinterId));
    return PrintUtils::GetGlobalId(VendorManager::GetGlobalVendorName(GetVendorName()), printerId);
}

std::string VendorWlanGroup::GetGroupPrinterId(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(groupPrinterIdMapMutex);
    auto item = groupPrinterIdMap_.find(printerId);
    if (item != groupPrinterIdMap_.end() && !item->second.empty()) {
        return item->second;
    }
    PRINT_HILOGW("groupPrinterId is not exited, use printerId");
    return printerId;
}

bool VendorWlanGroup::CheckPrinterAddedByIp(const std::string &printerId)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    ConnectMethod connectingMethod = parentVendorManager->GetConnectingMethod(printerId);
    PRINT_HILOGI("CheckPrinterAddedByIp connectingMethod : %{public}d", connectingMethod);
    if (connectingMethod == IP_AUTO) {
        return true;
    }
    return false;
}

void VendorWlanGroup::UpdateGroupPrinter(const std::string &printerId, const std::string &groupPrinterId)
{
    std::lock_guard<std::mutex> lock(groupPrinterIdMapMutex);
    auto retPair = groupPrinterIdMap_.try_emplace(printerId, groupPrinterId);
    if (retPair.second) {
        PRINT_HILOGI("add new groupPrinterId");
        return;
    }
    if (retPair.first->second == groupPrinterId) {
        PRINT_HILOGD("not need update groupPrinterId");
        return;
    }
    PRINT_HILOGI("update groupPrinterId");
    parentVendorManager->RemovePrinterFromDiscovery(GetVendorName(), retPair.first->second);
    retPair.first->second = groupPrinterId;
}

bool VendorWlanGroup::HasGroupPrinter(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(groupPrinterIdMapMutex);
    auto item = groupPrinterIdMap_.find(printerId);
    if (item != groupPrinterIdMap_.end()) {
        return true;
    }
    return false;
}

void VendorWlanGroup::RemovedGroupPrinter(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(groupPrinterIdMapMutex);
    groupPrinterIdMap_.erase(printerId);
}

PrinterInfo VendorWlanGroup::ConvertPrinterInfoId(const PrinterInfo &printerInfo)
{
    PrinterInfo info(printerInfo);
    if (info.HasPrinterUuid()) {
        PRINT_HILOGD("convert printerId by uuid: %{private}s", info.GetPrinterUuid().c_str());
        UpdateGroupPrinter(info.GetPrinterId(), info.GetPrinterUuid());
        info.SetPrinterId(info.GetPrinterUuid());
        return info;
    }
    PRINT_HILOGW("uuid is not exited, not convert printerId");
    UpdateGroupPrinter(printerInfo.GetPrinterId(), printerInfo.GetPrinterId());
    return printerInfo;
}

PrinterInfo VendorWlanGroup::ConvertIpPrinterName(const PrinterInfo &printerInfo)
{
    PrinterInfo info(printerInfo);
    PRINT_HILOGI("ConvertIpPrinterName printerId : %{private}s, printerName : %{private}s",
        info.GetPrinterId().c_str(), info.GetPrinterName().c_str());
    info.SetPrinterName(info.GetPrinterId());
    return info;
}

std::string VendorWlanGroup::ExtractPrinterIdByPrinterInfo(const PrinterInfo &printerInfo)
{
    std::string uri(printerInfo.GetUri());
    if (uri.empty()) {
        return "";
    }
    auto pos_start = uri.find_first_of(VENDOR_BSUNI_URI_START);
    auto pos_end = uri.find_last_of(VENDOR_BSUNI_URI_END);
    if (pos_start == std::string::npos || uri.length() <= pos_start + VENDOR_BSUNI_URI_START.length() ||
        pos_end - pos_start <= VENDOR_BSUNI_URI_START.length()) {
        return "";
    }
    std::string printerId = uri.substr(pos_start + VENDOR_BSUNI_URI_START.length(),
        pos_end - pos_start - VENDOR_BSUNI_URI_START.length());
    return printerId;
}

bool VendorWlanGroup::MonitorPrinterStatus(const std::string &groupPrinterId, bool on)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    if (QueryVendorDriverByGroupPrinterId(groupPrinterId) == VENDOR_IPP_EVERYWHERE) {
        auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
        if (ippEverywhereDriver != nullptr) {
            PRINT_HILOGI("start MonitorPrinterStatus by ippEverywhere");
            return ippEverywhereDriver->MonitorPrinterStatus(groupPrinterId, on);
        }
    } else {
        PrinterInfo printerInfo;
        auto ret = parentVendorManager->QueryPrinterInfoByPrinterId(GetVendorName(), groupPrinterId, printerInfo);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("get printerInfo failed.");
            return false;
        }
        auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
        if (bsuniDriver != nullptr) {
            PRINT_HILOGI("start MonitorPrinterStatus by bsuni");
            return bsuniDriver->MonitorPrinterStatus(ExtractPrinterIdByPrinterInfo(printerInfo), on);
        }
    }
    return false;
}

bool VendorWlanGroup::OnPrinterStatusChanged(const std::string &vendorName, const std::string &printerId,
                                             const PrinterVendorStatus &status)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    std::string groupPrinterId = GetGroupPrinterId(printerId);
    return parentVendorManager->OnPrinterStatusChanged(GetVendorName(), groupPrinterId, status);
}

