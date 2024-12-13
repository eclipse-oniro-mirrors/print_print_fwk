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

using namespace OHOS::Print;

VendorWlanGroup::VendorWlanGroup(VendorManager *vendorManager) : parentVendorManager(vendorManager) {}

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
        if (bsuniDriver != nullptr && bsuniDriver->OnQueryCapability(printerId, timeout)) {
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
    return vendorManager->AddPrinterToDiscovery(GetVendorName(), printerInfo);
}

int32_t VendorWlanGroup::OnPrinterRemoved(const std::string &vendorName, const std::string &printerId)
{
    if (vendorManager == nullptr) {
        PRINT_HILOGE("VendorManager is null.");
        return EXTENSION_ERROR_CALLBACK_NULL;
    }
    RemovePrinterVendorGroupById(printerId);
    return vendorManager->RemovePrinterFromDiscovery(GetVendorName(), printerId);
}

bool VendorWlanGroup::IsGroupDriver(const std::string &bothPrinterId)
{
    std::string printerId(VendorManager::ExtractPrinterId(bothPrinterId));
    auto iter = printerVendorGroupList_.find(printerId);
    return (iter != printerVendorGroupList_.end() && !iter->second.empty());
}

bool VendorWlanGroup::IsBsunidriverSupport(const std::string &printerId)
{
    PRINT_HILOGD("IsBsunidriverSupport enter");
    auto printerInfo = parentVendorManager->QueryDiscoveredPrinterInfoById(GetVendorName(), printerId);
    if (printerInfo == nullptr) {
        return false;
    }
    if (printerInfo->HasOption() && nlohmann::json::accept(std::string(printerInfo->GetOption()))) {
        nlohmann::json option = nlohmann::json::parse(std::string(printerInfo->GetOption()));
        if (option != nullptr && option.contains("bsunidriverSupport") && option["bsunidriverSupport"].is_string()) {
            PRINT_HILOGD("IsPrivatePpdDriver bsunidriverSupport=%{public}s",
                std::string(option["bsunidriverSupport"]).c_str());
            return std::string(option["bsunidriverSupport"]) == "true";
        }
    }
    return false;
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