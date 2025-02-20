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

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <streambuf>
#include "scan_log.h"
#include "scan_usb_manager.h"
#include "scan_util.h"
#include "scan_system_data.h"
#include "scan_service_ability.h"

namespace {
const std::string SCANNER_LIST_FILE = "/data/service/el1/public/print_service/scanner_list.json";
const std::string SCANNER_LIST_VERSION = "v1";
}  // namespace

namespace OHOS {
namespace Scan {
bool ScanSystemData::CheckJsonObjectValue(const nlohmann::json& object)
{
    const std::vector<std::string> keyList = {"deviceId", "manufacturer", "model", "deviceType",
        "discoverMode", "serialNumber", "deviceName", "uniqueId"};
    for (auto key : keyList) {
        if (!object.contains(key) || !object[key].is_string()) {
            SCAN_HILOGW("can not find %{public}s", key.c_str());
            return false;
        }
    }
    return true;
}

bool ScanSystemData::ParseScannerListJsonV1(nlohmann::json& jsonObject)
{
    if (!jsonObject.contains("scaner_list") || !jsonObject["scaner_list"].is_array()) {
        SCAN_HILOGW("can not find scaner_list");
        return false;
    }
    for (auto &element : jsonObject["scaner_list"].items()) {
        nlohmann::json object = element.value();
        if (!CheckJsonObjectValue(object)) {
            continue;
        }
        ScanDeviceInfo scanDeviceInfo;
        scanDeviceInfo.deviceId = object["deviceId"];
        scanDeviceInfo.manufacturer = object["manufacturer"];
        scanDeviceInfo.model = object["model"];
        scanDeviceInfo.deviceType = object["deviceType"];
        scanDeviceInfo.discoverMode = object["discoverMode"];
        scanDeviceInfo.serialNumber = object["serialNumber"];
        scanDeviceInfo.deviceName = object["deviceName"];
        scanDeviceInfo.uniqueId = object["uniqueId"];
        scanDeviceInfo.uuid = object["uuid"];
        std::string uniqueId = scanDeviceInfo.discoverMode + scanDeviceInfo.uniqueId;
        InsertScannerInfo(uniqueId, scanDeviceInfo);
    }
    return true;
}

bool ScanSystemData::Init()
{
    {
        std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
        addedScannerMap_.clear();
    }
    std::ifstream ifs(SCANNER_LIST_FILE.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        SCAN_HILOGW("open scanner list file fail");
        return false;
    }
    std::string fileData((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (!nlohmann::json::accept(fileData)) {
        SCAN_HILOGW("json accept fail");
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(fileData);
    if (!jsonObject.contains("version") || !jsonObject["version"].is_string()) {
        SCAN_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].get<std::string>();
    SCAN_HILOGI("json version: %{public}s", version.c_str());
    if (version == SCANNER_LIST_VERSION && ParseScannerListJsonV1(jsonObject)) {
        RefreshUsbDeviceId();
        SaveScannerMap();
        return true;
    }
    return false;
}

void ScanSystemData::RefreshUsbDeviceId()
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto usbIt = ScanUsbManager::GetInstance();
    if (usbIt == nullptr) {
        SCAN_HILOGE("usbIt is a nullptr.");
        return;
    }
    usbIt->RefreshUsbDevicePort(usbSnToPortMap_);
    if (usbSnToPortMap_.empty()) {
        SCAN_HILOGW("usbSnToPortMap_ is empty");
        return;
    }
    for (auto &scanDevIt : addedScannerMap_) {
        std::string discoverMode = scanDevIt.second->discoverMode;
        if (discoverMode != "USB") {
            continue;
        }
        std::string serialNumber = scanDevIt.second->serialNumber;
        auto it = usbSnToPortMap_.find(serialNumber);
        if (it == usbSnToPortMap_.end()) {
            continue;
        }
        std::string oldDeviceId = scanDevIt.second->deviceId;
        std::string usbPort = it->second;
        std::string newDeviceId = ReplaceDeviceIdUsbPort(oldDeviceId, usbPort);
        if (newDeviceId == "" || newDeviceId == oldDeviceId) {
            SCAN_HILOGD("cannot update usb deviceId.");
            continue;
        }
        scanDevIt.second->deviceId = newDeviceId;
        ScanDeviceInfoSync syncInfo;
        syncInfo.deviceId = newDeviceId;
        syncInfo.serialNumber = serialNumber;
        syncInfo.oldDeviceId = oldDeviceId;
        syncInfo.discoverMode = "USB";
        auto saPtr = ScanServiceAbility::GetInstance();
        if (saPtr == nullptr) {
            SCAN_HILOGE("saPtr is a nullptr");
            return;
        }
        saPtr->UpdateScannerId(syncInfo);
    }
}

std::string ScanSystemData::ReplaceDeviceIdUsbPort(const std::string& deviceId, const std::string& usbPort)
{
    constexpr int32_t invalidPort = -1;
    int32_t start = invalidPort;
    int32_t end = invalidPort;
    char dash;
    std::istringstream(usbPort) >> start >> dash >> end;
    if (start < 0 || end < 0 || dash != '-') {
        SCAN_HILOGE("usbPort format is error");
        return "";
    }
    std::ostringstream oss;
    char zero = '0';
    constexpr int32_t portWidth = 3;
    oss << std::setw(portWidth) << std::setfill(zero) << start;
    std::string formattedStart = oss.str();
    oss.str("");
    oss << std::setw(portWidth) << std::setfill(zero) << end;
    std::string formattedEnd = oss.str();
    size_t pos1 = deviceId.rfind(':');
    if (pos1 == std::string::npos) {
        SCAN_HILOGE("deviceId format is error");
        return "";
    }
    size_t pos2 = deviceId.rfind(':', pos1 - 1);
    if (pos2 == std::string::npos) {
        SCAN_HILOGE("deviceId format is error");
        return "";
    }
    std::string newDeviceId = deviceId.substr(0, pos2 + 1).append(formattedStart).append(":").append(formattedEnd);
    SCAN_HILOGD("new deviceId = %{private}s", newDeviceId.c_str());
    return newDeviceId;
}

bool ScanSystemData::UpdateScannerIdByUsbDevicePort(const std::string &uniqueId, const std::string &usbDevicePort)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end() && iter->second != nullptr) {
        std::string oldDeviceId = iter->second->deviceId;
        std::string newDeviceId = ReplaceDeviceIdUsbPort(oldDeviceId, usbDevicePort);
        SCAN_HILOGD("newDeviceId : %{private}s", newDeviceId.c_str());
        if (newDeviceId == "" || newDeviceId == oldDeviceId) {
            SCAN_HILOGD("cannot update usb deviceId.");
            return false;
        }
        iter->second->deviceId = newDeviceId;
    } else {
        SCAN_HILOGE("ScanSystemData UpdateScannerIdByUsbDevicePort fail");
        return false;
    }
    return true;
}

void ScanSystemData::InsertScannerInfo(const std::string &uniqueId, const ScanDeviceInfo &scannerInfo)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter == addedScannerMap_.end() || iter->second == nullptr) {
        SCAN_HILOGI("insert new scanner");
        addedScannerMap_[uniqueId] = std::make_shared<ScanDeviceInfo>(scannerInfo);
    } else {
        SCAN_HILOGI("update exist scanner");
        *iter->second = scannerInfo;
    }
}

bool ScanSystemData::DeleteScannerInfo(const std::string &uniqueId)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end()) {
        addedScannerMap_.erase(uniqueId);
    } else {
        SCAN_HILOGE("ScanSystemData delete connected scanner fail");
        return false;
    }
    return true;
}

bool ScanSystemData::UpdateScannerNameByUniqueId(const std::string &uniqueId, const std::string &deviceName)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end() && iter->second != nullptr) {
        iter->second->deviceName = deviceName;
    } else {
        SCAN_HILOGE("ScanSystemData UpdateScannerNameByUniqueId fail");
        return false;
    }
    return true;
}

bool ScanSystemData::UpdateScannerInfoByUniqueId(const std::string &uniqueId, const ScanDeviceInfo &scannerInfo)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end()) {
        *iter->second = scannerInfo;
        return true;
    }
    SCAN_HILOGE("ScanSystemData UpdateScannerInfoByUniqueId not found scannerInfo");
    return false;
}

bool ScanSystemData::QueryScannerNameByUniqueId(const std::string &uniqueId, std::string &deviceName)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end()) {
        deviceName = iter->second->deviceName;
        return true;
    }
    SCAN_HILOGW("QueryScannerNameByUniqueId fail");
    return false;
}

bool ScanSystemData::QueryScannerInfoByUniqueId(const std::string &uniqueId, ScanDeviceInfo &scannerInfo)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    for (auto iter = addedScannerMap_.begin(); iter != addedScannerMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        std::string iterSn = info->discoverMode + info->serialNumber;
        std::string iterUniqueId = info->discoverMode + info->uniqueId;
        if (uniqueId == iterSn || uniqueId == iterUniqueId) {
            *iter->second = scannerInfo;
            return true;
        }
    }
    return false;
}

void ScanSystemData::GetAddedScannerInfoList(std::vector<ScanDeviceInfo> &infoList)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    for (auto iter = addedScannerMap_.begin(); iter != addedScannerMap_.end(); ++iter) {
        if (iter->second != nullptr) {
            infoList.push_back(*(iter->second));
        }
    }
}

bool ScanSystemData::SaveScannerMap()
{
    FILE *file = fopen(SCANNER_LIST_FILE.c_str(), "w+");
    if (file != nullptr) {
        SCAN_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return false;
    }
    nlohmann::json scannerMapJson = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
        for (auto iter = addedScannerMap_.begin(); iter != addedScannerMap_.end(); ++iter) {
            auto info = iter->second;
            if (info == nullptr) {
                continue;
            }
            nlohmann::json scannerJson = nlohmann::json::object();
            scannerJson["deviceId"] = info->deviceId;
            scannerJson["manufacturer"] = info->manufacturer;
            scannerJson["model"] = info->model;
            scannerJson["deviceType"] = info->deviceType;
            scannerJson["discoverMode"] = info->discoverMode;
            scannerJson["serialNumber"] = info->serialNumber;
            scannerJson["deviceName"] = info->deviceName;
            scannerJson["uniqueId"] = info->uniqueId;
            scannerJson["uuid"] = info->uuid;
            scannerMapJson.push_back(scannerJson);
        }
    }
    nlohmann::json jsonObject;
    jsonObject["version"] = SCANNER_LIST_VERSION;
    jsonObject["scaner_list"] = scannerMapJson;
    std::string jsonString = jsonObject.dump();
    size_t jsonLength = jsonString.length();
    size_t writeLength = fwrite(jsonString.c_str(), 1, strlen(jsonString.c_str()), file);
    int fcloseResult = fclose(file);
    if (fcloseResult != 0) {
        SCAN_HILOGE("File Operation Failure.");
        return false;
    }
    SCAN_HILOGI("SaveScannerMap finished");
    if (writeLength < 0) {
        SCAN_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return false;
    }

    return writeLength == jsonLength;
}

bool ScanSystemData::IsContainScanner(const std::string &uniqueId)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    if (addedScannerMap_.find(uniqueId) != addedScannerMap_.end()) {
        SCAN_HILOGI("The map contains the scanner.");
        return true;
    } else {
        SCAN_HILOGW("The scanner is not included in the map.");
        return false;
    }
}

std::pair<std::string, std::string> ScanSystemData::UpdateNetScannerByUuid(const std::string &uuid,
    const std::string& ip)
{
    std::string oldKey;
    std::shared_ptr<ScanDeviceInfo> scannerInfo;
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    for (const auto& [key, info] : addedScannerMap_) {
        if (info != nullptr && info->uuid == uuid) {
            oldKey = key;
            scannerInfo = info;
            break;
        }
    }
    if (oldKey == "" || scannerInfo == nullptr) {
        SCAN_HILOGE("Cannot find scanner by uuid");
        return std::make_pair("", "");
    }
    std::string oldDeviceId = scannerInfo->deviceId;
    std::string newDeviceId = ScanUtil::ReplaceIpAddress(oldDeviceId, ip);
    if (newDeviceId == scannerInfo->deviceId) {
        SCAN_HILOGE("Get new device Id fail.");
        return std::make_pair("", "");
    }
    SCAN_HILOGD("newdeviceId = %{private}s", newDeviceId.c_str());
    addedScannerMap_.erase(oldKey);
    std::string newKey = "TCP" + ip;
    scannerInfo->deviceId = newDeviceId;
    scannerInfo->uniqueId = ip;
    auto it = addedScannerMap_.find(newKey);
    if (it == addedScannerMap_.end()) {
        addedScannerMap_.insert(std::make_pair(newKey, scannerInfo));
    } else {
        it->second = scannerInfo;
    }
    return std::make_pair(oldDeviceId, newDeviceId);
}

}  // namespace Scan
}  // namespace OHOS