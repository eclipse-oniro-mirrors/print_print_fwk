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
    if (ConnectByPpdDriver(printerId)) {
        return true;
    } else if (IsBsunidriverSupport(printerId) && ConnectByBsuni(printerId)) {
        return true;
    } else if (ConnectByIppEverywhere(printerId)) {
        return true;
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
    if (ConnectByBsuni(printerIp, protocol)) {
        return true;
    } else if (ConnectByIppEverywhere(printerIp, protocol)) {
        return true;
    }
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

bool VendorWlanGroup::IsQueryingPrinter(const std::string &globalPrinterIdOrIp, const std::string &uri)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null");
        return false;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    std::string globalPrinterId = GetGlobalPrinterId(groupPrinterId);
    return parentVendorManager->IsQueryingPrinter(globalPrinterId, uri);
}

void VendorWlanGroup::SetQueryPrinter(ConnectMethod method, const std::string &globalPrinterIdOrIp)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null");
        return;
    }
    std::string printerId(VendorManager::ExtractPrinterId(globalPrinterIdOrIp));
    std::string groupPrinterId = CheckPrinterAddedByIp(printerId) ? printerId : GetGroupPrinterId(printerId);
    std::string globalPrinterId = GetGlobalPrinterId(groupPrinterId);
    parentVendorManager->SetQueryPrinter(method, globalPrinterId);
}

bool VendorWlanGroup::ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
    const std::string &ppdName)
{
    PRINT_HILOGI("ConnectPrinterByIpAndPpd Enter");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null");
        return false;
    }
    if (ppdName == DEFAULT_PPD_NAME) {
        PRINT_HILOGI("Select IPP EveryWhere");
        return ConnectByIppEverywhere(printerIp, protocol);
    } else {
        PRINT_HILOGI("Querying On Bsuni Driver");
        return ConnectByBsuni(printerIp, protocol);
    }
    PRINT_HILOGE("no vendor can query capability by ip");
    return false;
}

bool VendorWlanGroup::OnPrinterPpdQueried(
    const std::string &vendorName, const std::string &printerId, const std::string &ppdName, const std::string &ppdData)
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
    PRINT_HILOGI("IsBsunidriverSupport enter");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), groupPrinterId);
    if (printerInfo == nullptr) {
        return false;
    }
    return IsBsunidriverSupport(*printerInfo);
}

bool VendorWlanGroup::IsBsunidriverSupport(const PrinterInfo &printerInfo)
{
    std::string supportValue;
    Json::Value option;
    if (printerInfo.HasOption() && PrintJsonUtil::Parse(printerInfo.GetOption(), option)) {
        if (PrintJsonUtil::IsMember(option, "bsunidriverSupport") && option["bsunidriverSupport"].isString()) {
            supportValue = option["bsunidriverSupport"].asString();
        }
    }
    PRINT_HILOGI("IsBsunidriverSupport bsunidriverSupport = %{public}s", supportValue.c_str());
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
        PRINT_HILOGI("[Printer: %{public}s] remove printer from vendor group list",
            PrintUtils::AnonymizePrinterId(groupPrinterId).c_str());
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

bool VendorWlanGroup::TryConnectByPpdDriver(const PrinterInfo &printerInfo)
{
    PrinterInfo info = printerInfo;
    if (parentVendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    auto ppdDriver = parentVendorManager->FindDriverByVendorName(VENDOR_PPD_DRIVER);
    if (ppdDriver == nullptr) {
        PRINT_HILOGW("ppdDriver is null");
        return false;
    }
    std::string printerId = info.GetPrinterId();
    std::string connectingPpdName = parentVendorManager->GetConnectingPpdName();
    std::string ppdName;
    if (connectingPpdName == DEFAULT_PPD_NAME) {
        PRINT_HILOGI("not ppd driver");
        return false;
    } else if (connectingPpdName == "auto") {
        ppdDriver->OnPrinterDiscovered(GetVendorName(), info);
        if (!ppdDriver->QueryProperty(printerId, PRINTER_PROPERTY_KEY_CUPS_PPD_NAME, ppdName)) {
            PRINT_HILOGI("no matched ppd");
            return false;
        }
    } else {
        ppdName = connectingPpdName;
    }
    if (parentVendorManager->AddPrinterToCupsWithPpd(
        GetVendorName(), VendorManager::ExtractPrinterId(printerId), ppdName, "") != EXTENSION_ERROR_NONE) {
        PRINT_HILOGI("AddPrinterToCupsWithPpd fail.");
        return false;
    }
    PRINT_HILOGI("AddPrinterToCupsWithPpd success.");
    return true;
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
        info.GetPrinterId().c_str(),
        info.GetPrinterName().c_str());
    info.SetPrinterName(info.GetPrinterId());
    return info;
}

std::string VendorWlanGroup::ExtractPrinterIdByPrinterInfo(const PrinterInfo &printerInfo)
{
    return PrintUtils::ExtractHostFromUri(printerInfo.GetUri());
}

bool VendorWlanGroup::MonitorPrinterStatus(const std::string &groupPrinterId, bool on)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    if (!VendorDriverBase::MonitorPrinterStatus(groupPrinterId, on)) {
        PRINT_HILOGW("MonitorPrinterStatus fail");
        return false;
    }
    if (QueryVendorDriverByGroupPrinterId(groupPrinterId) == VENDOR_IPP_EVERYWHERE) {
        auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
        if (ippEverywhereDriver == nullptr) {
            PRINT_HILOGW("ippEverywhereDriver is null");
            return false;
        }
        PRINT_HILOGI("start MonitorPrinterStatus by ippEverywhere");
        return ippEverywhereDriver->MonitorPrinterStatus(groupPrinterId, on);
    }
    PRINT_HILOGI("start MonitorPrinterStatus by bsuni");
    return MonitorStatusByBsuniDriver(groupPrinterId, on);
}

bool VendorWlanGroup::MonitorStatusByBsuniDriver(const std::string &groupPrinterId, bool on)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    PrinterInfo printerInfo;
    auto ret = parentVendorManager->QueryPrinterInfoByPrinterId(GetVendorName(), groupPrinterId, printerInfo);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("get printerInfo failed.");
        return false;
    }
    auto printerIp = PrintUtils::ExtractHostFromUri(printerInfo.GetUri());
    if (printerIp.empty()) {
        PRINT_HILOGW("printerIp empty");
        return false;
    }
    if (!on) {
        auto printerList = parentVendorManager->QueryAddedPrintersByIp(printerIp);
        for (auto &globalPrinterId : printerList) {
            auto vendorName = VendorManager::ExtractVendorName(VendorManager::ExtractGlobalVendorName(globalPrinterId));
            if (vendorName != VENDOR_WLAN_GROUP) {
                continue;
            }
            auto printerId = VendorManager::ExtractPrinterId(globalPrinterId);
            if (printerId != groupPrinterId && IsStatusMonitoring(printerId)) {
                PRINT_HILOGI("monitor needed by other printer: %{public}s",
                    PrintUtils::AnonymizePrinterId(printerId).c_str());
                return false;
            }
        }
    }
    auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
    if (bsuniDriver == nullptr) {
        PRINT_HILOGW("bsuniDriver is null");
        return false;
    }
    return bsuniDriver->MonitorPrinterStatus(printerIp, on);
}

bool VendorWlanGroup::OnPrinterStatusChanged(
    const std::string &vendorName, const std::string &printerId, const PrinterVendorStatus &status)
{
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    parentVendorManager->OnPrinterStatusChanged(GetVendorName(), printerId, status);
    std::string groupPrinterId = GetGroupPrinterId(printerId);
    if (groupPrinterId != printerId) {
        parentVendorManager->OnPrinterStatusChanged(GetVendorName(), groupPrinterId, status);
    }
    return true;
}

bool VendorWlanGroup::OnPrinterCapabilityQueried(const std::string &vendorName, const PrinterInfo &printerInfo)
{
    PRINT_HILOGD("OnPrinterCapabilityQueried vendorName: %{public}s", vendorName.c_str());
    if (parentVendorManager == nullptr) {
        PRINT_HILOGW("vendorManager is null");
        return false;
    }
    std::string printerId = printerInfo.GetPrinterId();
    std::string globalPrinterId = GetGlobalPrinterId(printerId);
    bool connecting = IsConnectingPrinter(globalPrinterId, printerInfo.GetUri());
    bool querying = IsQueryingPrinter(globalPrinterId, printerInfo.GetUri());
    if (connecting) {
        PRINT_HILOGD("connecting %{private}s", globalPrinterId.c_str());
        auto method = GetConnectingMethod(printerId);
        PRINT_HILOGI("connecting method %{public}d", static_cast<int>(method));
        if (method == IP_AUTO) {
            printerVendorGroupList_[printerId] = VENDOR_PPD_DRIVER;
            if (TryConnectByPpdDriver(printerInfo)) {
                PRINT_HILOGI("Connect by ppdDriver success.");
                return true;
            }
            RemoveGroupPrinterFromVendorGroupList(printerId);
            printerVendorGroupList_[printerId] = vendorName;
            if (!parentVendorManager->IsBsunidriverSupport(printerInfo)) {
                PRINT_HILOGW("Bsuni Driver not support!");
                return false;
            }
        }
        PRINT_HILOGI("query ppd propertis");
        auto vendorDriver = parentVendorManager->FindDriverByVendorName(vendorName);
        if (vendorDriver == nullptr) {
            PRINT_HILOGW("vendorDriver is null");
            return false;
        }
        std::vector<std::string> keyList;
        keyList.push_back(PRINTER_PROPERTY_KEY_DEVICE_STATE);
        keyList.push_back(PRINTER_PROPERTY_KEY_CUPS_PPD_FILE);
        vendorDriver->OnQueryProperties(printerId, keyList);
    } else if (querying) {
        PRINT_HILOGD("querying %{private}s", globalPrinterId.c_str());
        if (!parentVendorManager->OnQueryCallBackEvent(printerInfo)) {
            PRINT_HILOGW("printerInfo Callback Failed");
            return false;
        }
    }
    return true;
}

bool VendorWlanGroup::ConnectPrinterByIdAndPpd(const std::string &printerId, const std::string &ppdName)
{
    PRINT_HILOGI("ConnectPrinterByIdAndPpd enter.");
    if (parentVendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return false;
    }
    if (ppdName == BSUNI_PPD_NAME) {
        PRINT_HILOGI("Select Bsuni Driver");
        return IsBsunidriverSupport(printerId) && ConnectByBsuni(printerId);
    } else if (ppdName == DEFAULT_PPD_NAME) {
        PRINT_HILOGI("Select IPP EveryWhere");
        return ConnectByIppEverywhere(printerId);
    } else if (ppdName.empty() || ppdName == "auto") {
        PRINT_HILOGI("Auto Connect");
        return OnQueryCapability(printerId, 0);
    } else {
        PRINT_HILOGI("Select PPD Driver");
        return ConnectByPpdDriver(printerId);
    }
    PRINT_HILOGE("ConnectPrinterByIdAndPpd Failed.");
    return false;
}

bool VendorWlanGroup::ConnectByBsuni(const std::string &printerId)
{
    printerVendorGroupList_[printerId] = VENDOR_BSUNI_DRIVER;
    auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
    auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (bsuniDriver != nullptr && printerInfo != nullptr &&
        bsuniDriver->OnQueryCapability(ExtractPrinterIdByPrinterInfo(*printerInfo), 0)) {
        PRINT_HILOGI("on query capability on bsuni vendor seccess.");
        return true;
    }
    RemoveGroupPrinterFromVendorGroupList(printerId);
    return false;
}
 
bool VendorWlanGroup::ConnectByIppEverywhere(const std::string &printerId)
{
    printerVendorGroupList_[printerId] = VENDOR_IPP_EVERYWHERE;
    auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
    if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapability(printerId, 0)) {
        PRINT_HILOGI("on query capability on ipp everywhere success.");
        return true;
    }
    parentVendorManager->AddPrintEvent(GetVendorName(), printerId, CONNECT_PRINT_EVENT_TYPE,
        CONNECT_PRINT_EVENT_IPP_UNAVAILABLE);
    RemoveGroupPrinterFromVendorGroupList(printerId);
    return false;
}
 
bool VendorWlanGroup::ConnectByPpdDriver(const std::string &printerId)
{
    printerVendorGroupList_[printerId] = VENDOR_PPD_DRIVER;
        auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
        if (printerInfo != nullptr && TryConnectByPpdDriver(*printerInfo)) {
            PRINT_HILOGI("Connect by ppdDriver success.");
            return true;
        }
    RemoveGroupPrinterFromVendorGroupList(printerId);
    return false;
}
 
bool VendorWlanGroup::ConnectByBsuni(const std::string &printerIp, const std::string &protocol)
{
    auto bsuniDriver = parentVendorManager->FindDriverByVendorName(VENDOR_BSUNI_DRIVER);
    printerVendorGroupList_[printerIp] = VENDOR_BSUNI_DRIVER;
    if (bsuniDriver != nullptr && bsuniDriver->OnQueryCapabilityByIp(printerIp, protocol)) {
        PRINT_HILOGI("on query capability by ip on bsuni vendor seccess.");
        return true;
    }
    RemoveGroupPrinterFromVendorGroupList(printerIp);
    return false;
}
 
bool VendorWlanGroup::ConnectByIppEverywhere(const std::string &printerIp, const std::string &protocol)
{
    printerVendorGroupList_[printerIp] = VENDOR_IPP_EVERYWHERE;
    auto ippEverywhereDriver = parentVendorManager->FindDriverByVendorName(VENDOR_IPP_EVERYWHERE);
    if (ippEverywhereDriver != nullptr && ippEverywhereDriver->OnQueryCapabilityByIp(printerIp, protocol)) {
        PRINT_HILOGI("on query capability by ip on ipp everywhere seccess.");
        return true;
    }
    RemoveGroupPrinterFromVendorGroupList(printerIp);
    return false;
}