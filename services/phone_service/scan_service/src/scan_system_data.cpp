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
#include "scan_service_utils.h"

namespace {
const std::string SCANNER_LIST_FILE = "/data/service/el1/public/print_service/scanner_list.json";
const std::string SCANNER_LIST_VERSION = "v1";
}  // namespace

namespace OHOS {
namespace Scan {
bool ScanSystemData::CheckJsonObjectValue(const Json::Value &object)
{
    const std::vector<std::string> keyList = {
        "deviceId", "manufacturer", "model", "deviceType", "discoverMode", "serialNumber", "deviceName", "uniqueId"};
    for (auto key : keyList) {
        if (!Print::PrintJsonUtil::IsMember(object, key) || !object[key].isString()) {
            SCAN_HILOGW("can not find %{public}s", key.c_str());
            return false;
        }
    }
    return true;
}

void ScanSystemData::ParseScannerJsonV1(ScanDeviceInfo &scanDeviceInfo, Json::Value &object)
{
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "deviceId") && object["deviceId"].isString()) {
        scanDeviceInfo.deviceId = object["deviceId"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "manufacturer") && object["manufacturer"].isString()) {
        scanDeviceInfo.manufacturer = object["manufacturer"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "model") && object["model"].isString()) {
        scanDeviceInfo.model = object["model"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "deviceType") && object["deviceType"].isString()) {
        scanDeviceInfo.deviceType = object["deviceType"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "discoverMode") && object["discoverMode"].isString()) {
        scanDeviceInfo.discoverMode = object["discoverMode"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "serialNumber") && object["serialNumber"].isString()) {
        scanDeviceInfo.serialNumber = object["serialNumber"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "deviceName") && object["deviceName"].isString()) {
        scanDeviceInfo.deviceName = object["deviceName"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "uniqueId") && object["uniqueId"].isString()) {
        scanDeviceInfo.uniqueId = object["uniqueId"].asString();
    }
    if (OHOS::Print::PrintJsonUtil::IsMember(object, "uuid") && object["uuid"].isString()) {
        scanDeviceInfo.uuid = object["uuid"].asString();
    }
}

bool ScanSystemData::ParseScannerListJsonV1(Json::Value &jsonObject)
{
    if (!Print::PrintJsonUtil::IsMember(jsonObject, "scaner_list") || !jsonObject["scaner_list"].isArray()) {
        SCAN_HILOGW("can not find scaner_list");
        return false;
    }
    uint32_t jsonSize = jsonObject["scaner_list"].size();
    if (jsonSize > MAX_SCANNER_SIZE) {
        PRINT_HILOGE("scanner list size is illegal.");
        return false;
    }
    for (uint32_t i = 0; i < jsonSize; i++) {
        Json::Value object = jsonObject["scaner_list"][i];
        if (!CheckJsonObjectValue(object)) {
            continue;
        }
        ScanDeviceInfo scanDeviceInfo;
        ParseScannerJsonV1(scanDeviceInfo, object);
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
    Json::Value jsonObject;
    if (!Print::PrintJsonUtil::ParseFromStream(ifs, jsonObject)) {
        SCAN_HILOGW("json accept fail");
        return false;
    }
    ifs.close();
    if (!Print::PrintJsonUtil::IsMember(jsonObject, "version") || !jsonObject["version"].isString()) {
        SCAN_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].asString();
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
    for (auto &scanDevIt : addedScannerMap_) {
        std::string discoverMode = scanDevIt.second->discoverMode;
        if (discoverMode != ScannerDiscoveryMode::USB_MODE) {
            continue;
        }
        std::string serialNumber = scanDevIt.second->serialNumber;
        auto usbPort = DelayedSingleton<ScanUsbManager>::GetInstance()->GetPortBySerialNumber(serialNumber);
        if (usbPort == "") {
            continue;
        }
        std::string oldDeviceId = scanDevIt.second->deviceId;
        std::string newDeviceId = ScanServiceUtils::ReplaceDeviceIdUsbPort(oldDeviceId, usbPort);
        if (newDeviceId == "" || newDeviceId == oldDeviceId) {
            SCAN_HILOGD("cannot update usb deviceId.");
            continue;
        }
        scanDevIt.second->deviceId = newDeviceId;
        ScanDeviceInfoSync syncInfo;
        syncInfo.deviceId = newDeviceId;
        syncInfo.serialNumber = serialNumber;
        syncInfo.oldDeviceId = oldDeviceId;
        syncInfo.discoverMode = ScannerDiscoveryMode::USB_MODE;
        auto saPtr = ScanServiceAbility::GetInstance();
        if (saPtr == nullptr) {
            SCAN_HILOGE("saPtr is a nullptr");
            return;
        }
        saPtr->UpdateScannerId(syncInfo);
    }
}

bool ScanSystemData::UpdateScannerIdByUsbDevicePort(const std::string &uniqueId, const std::string &usbDevicePort)
{
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    auto iter = addedScannerMap_.find(uniqueId);
    if (iter != addedScannerMap_.end() && iter->second != nullptr) {
        std::string oldDeviceId = iter->second->deviceId;
        std::string newDeviceId = ScanServiceUtils::ReplaceDeviceIdUsbPort(oldDeviceId, usbDevicePort);
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
        SCAN_HILOGW("ScanSystemData UpdateScannerNameByUniqueId fail");
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
    SCAN_HILOGD("ScanSystemData UpdateScannerInfoByUniqueId not found scannerInfo");
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
            scannerInfo = *info;
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
    if (file == nullptr) {
        SCAN_HILOGW("Failed to open file errno: %{public}u", errno);
        return false;
    }
    Json::Value scannerMapJson;
    {
        std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
        for (auto iter = addedScannerMap_.begin(); iter != addedScannerMap_.end(); ++iter) {
            auto info = iter->second;
            if (info == nullptr) {
                continue;
            }
            Json::Value scannerJson;
            scannerJson["deviceId"] = info->deviceId;
            scannerJson["manufacturer"] = info->manufacturer;
            scannerJson["model"] = info->model;
            scannerJson["deviceType"] = info->deviceType;
            scannerJson["discoverMode"] = info->discoverMode;
            scannerJson["serialNumber"] = info->serialNumber;
            scannerJson["deviceName"] = info->deviceName;
            scannerJson["uniqueId"] = info->uniqueId;
            scannerJson["uuid"] = info->uuid;
            scannerMapJson.append(scannerJson);
        }
    }
    Json::Value jsonObject;
    jsonObject["version"] = SCANNER_LIST_VERSION;
    jsonObject["scaner_list"] = scannerMapJson;
    std::string jsonString = Print::PrintJsonUtil::WriteString(jsonObject);
    size_t jsonLength = jsonString.length();
    size_t writeLength = fwrite(jsonString.c_str(), 1, jsonLength, file);
    int fcloseResult = fclose(file);
    if (fcloseResult != 0) {
        SCAN_HILOGE("File Operation Failure.");
        return false;
    }
    SCAN_HILOGI("SaveScannerMap finished");
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

std::optional<std::pair<std::string, std::string>> ScanSystemData::UpdateNetScannerByUuid(const std::string &uuid,
    const std::string &ip)
{
    std::string oldKey;
    std::shared_ptr<ScanDeviceInfo> scannerInfo;
    std::lock_guard<std::mutex> autoLock(addedScannerMapLock_);
    for (const auto &[key, info] : addedScannerMap_) {
        if (info != nullptr && !info->uuid.empty() && info->uuid == uuid) {
            oldKey = key;
            scannerInfo = info;
            break;
        }
    }
    if (oldKey == "" || scannerInfo == nullptr) {
        SCAN_HILOGW("Cannot find scanner by uuid");
        return std::nullopt;
    }
    std::string oldDeviceId = scannerInfo->deviceId;
    std::string newDeviceId = ScanUtil::ReplaceIpAddress(oldDeviceId, ip);
    if (newDeviceId == scannerInfo->deviceId) {
        SCAN_HILOGE("Get new device Id fail.");
        return std::nullopt;
    }
    SCAN_HILOGD("newdeviceId = %{private}s", newDeviceId.c_str());
    addedScannerMap_.erase(oldKey);
    std::string newKey = ScannerDiscoveryMode::TCP_MODE + ip;
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