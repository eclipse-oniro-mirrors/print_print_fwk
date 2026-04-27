/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include "securec.h"
#include "scan_log.h"
#include "scan_constant.h"
#include "scan_discover_data.h"
#include "escl_driver_manager.h"
#include "escl_scanner_status.h"
#include "sane_manager_client.h"
#include "sane_option_descriptor.h"
#include "sane_control_param.h"
#include "scan_util.h"

namespace OHOS::Scan {
static const char* AIRSCAN_TARGET = "/system/lib64/libsane-airscan.z.so";
static const char* AIRSCAN_LINKPATH = "/data/service/el1/public/print_service/sane/backend/libsane-airscan.z.so";
static const char* CONFIG_FILE_PATH = "/data/service/el1/public/print_service/sane/config/airscan_dll.conf";
static const char* CONFIG_FILE_CONTENT = "airscan";
static const char* CONFIG_DIR_PATH = "/data/service/el1/public/print_service/sane/config";
static const int32_t MAX_PORT_NUMBER = 65535;

int32_t EsclDriverManager::InitializeEsclScannerDriver()
{
    if (!CreateSoftLink()) {
        SCAN_HILOGE("CreateSoftLink fail");
        return E_SCAN_SERVER_FAILURE;
    }
    if (!CreateAirscanConfigFile()) {
        SCAN_HILOGE("CreateAirscanConfigFile fail");
        return E_SCAN_SERVER_FAILURE;
    }
    return E_SCAN_NONE;
}

bool EsclDriverManager::CreateSoftLink()
{
    struct stat st;
    if (stat(AIRSCAN_LINKPATH, &st) == 0) {
        SCAN_HILOGD("Symbolic link already exists");
        return true;
    }
    if (access(AIRSCAN_TARGET, F_OK) != 0) {
        SCAN_HILOGE("Target file does not exist, errno = %{public}d", errno);
        return false;
    }
    if (symlink(AIRSCAN_TARGET, AIRSCAN_LINKPATH) != 0) {
        SCAN_HILOGE("Failed to create a symbolic link, errno = %{public}d", errno);
        return false;
    }
    return true;
}

bool EsclDriverManager::CreateAirscanConfigFile()
{
    struct stat st;
    if (stat(CONFIG_FILE_PATH, &st) == 0) {
        SCAN_HILOGD("airscan config file already exists");
        return true;
    }
    if (stat(CONFIG_DIR_PATH, &st) != 0) {
        SCAN_HILOGE("The parent directory does not exist, errno = %{public}d", errno);
        return false;
    }
    std::ofstream file(CONFIG_FILE_PATH);
    if (!file.is_open()) {
        SCAN_HILOGE("Failed to create file");
        return false;
    }
    file << CONFIG_FILE_CONTENT;
    file.close();
    if (file.fail()) {
        SCAN_HILOGE("Failed to write CONFIG_FILE_CONTENT to file");
        return false;
    }
    mode_t configFileMode = 0550;
    if (chmod(CONFIG_FILE_PATH, configFileMode) != 0) {
        SCAN_HILOGE("Failed to set file permissions, errno = %{public}d", errno);
        return false;
    }
    return true;
}

bool EsclDriverManager::GenerateEsclScannerInfo(const ScanDeviceInfoTCP& rawInfo, ScanDeviceInfo& info)
{
    constexpr int32_t MAX_DEVICE_ID_LENGTH = 1024;
    char deviceId[MAX_DEVICE_ID_LENGTH] = {0};
    if (sprintf_s(deviceId, sizeof(deviceId), "airscan:eSCL:scanner:http://%s:%s/eSCL/",
        rawInfo.addr.c_str(), rawInfo.port.c_str()) < 0) {
        SCAN_HILOGE("GenerateEsclScannerInfo sprintf_s fail");
        return false;
    }
    info.deviceName = rawInfo.deviceName;
    info.deviceId = std::string(deviceId);
    info.uniqueId = rawInfo.addr;
    info.discoverMode = ScannerDiscoveryMode::TCP_MODE;
    return true;
}

void EsclDriverManager::AddEsclScannerInfo(std::vector<ScanDeviceInfo>& discoveredScanners)
{
    const auto& esclInfos = ScannerDiscoverData::GetInstance().GetAllEsclDevices();
    
    std::unordered_set<std::string> existingIds;
    for (const auto& scanner : discoveredScanners) {
        existingIds.insert(scanner.uniqueId);
    }
    
    for (const auto& [uniqueId, esclInfo] : esclInfos) {
        if (existingIds.find(uniqueId) == existingIds.end()) {
            discoveredScanners.push_back(esclInfo);
        }
    }
}

bool EsclDriverManager::IsEsclScanner(const std::string& scannerId)
{
    return scannerId.find("airscan") != std::string::npos;
}

bool EsclDriverManager::ExtractIpAndPort(const std::string& scannerId, std::string& ipAddress, int32_t& portNumber)
{
    size_t httpPos = scannerId.find("//");
    if (httpPos == std::string::npos) {
        SCAN_HILOGE("Failed to find '//' in scannerId");
        return false;
    }
    size_t hostStart = httpPos + 2;
    size_t colonPos = scannerId.find(':', hostStart);
    size_t slashPos = scannerId.find('/', hostStart);
    if (colonPos == std::string::npos || slashPos == std::string::npos || colonPos >= slashPos) {
        SCAN_HILOGE("Invalid scannerId format, cannot extract ip and port");
        return false;
    }
    ipAddress = scannerId.substr(hostStart, colonPos - hostStart);
    std::string portStr = scannerId.substr(colonPos + 1, slashPos - colonPos - 1);
    if (!ScanUtil::ConvertToInt(portStr, portNumber)) {
        SCAN_HILOGE("Failed to convert port string to integer");
        return false;
    }
    if (portNumber <= 0 || portNumber > MAX_PORT_NUMBER) {
        SCAN_HILOGE("Invalid port number: %{public}d", portNumber);
        return false;
    }
    return true;
}

bool EsclDriverManager::IsAdfMode(const std::string& scannerId)
{
    bool isAdfMode = false;
    SaneControlParam controlParam;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    SaneOutParam outParam;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status == SANE_STATUS_GOOD) {
        for (int32_t optionIndex = 1; optionIndex < outParam.valueNumber_; optionIndex++) {
            SaneOptionDescriptor saneDesc;
            status = SaneManagerClient::GetInstance()->SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
            if (status != SANE_STATUS_GOOD) {
                continue;
            }
            if (saneDesc.optionTitle_ != "Scan source") {
                continue;
            }
            controlParam.action_ = SANE_ACTION_GET_VALUE;
            controlParam.valueType_ = SCAN_VALUE_STR;
            controlParam.option_ = optionIndex;
            status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
            if (status == SANE_STATUS_GOOD) {
                isAdfMode = (outParam.valueStr_ == "Automatic Document Feeder" ||
                    outParam.valueStr_ == "ADF" ||
                    outParam.valueStr_ == "ADF Duplex" ||
                    outParam.valueStr_ == "ADF Front" ||
                    outParam.valueStr_ == "ADF Back");
                SCAN_HILOGI("Scan source: %{public}s, isAdfMode: %{public}d",
                    outParam.valueStr_.c_str(), isAdfMode);
            }
            break;
        }
    }
    return isAdfMode;
}

bool EsclDriverManager::IsAdfEmpty(const std::string& ipAddress, int32_t portNumber)
{
    std::map<std::string, std::string> statusMap;
    if (!EsclScannerStatus::QueryScannerStatus(ipAddress, portNumber, statusMap)) {
        SCAN_HILOGE("Failed to query scanner status");
        return false;
    }
    auto adfStateIt = statusMap.find("scan:AdfState");
    if (adfStateIt != statusMap.end()) {
        SCAN_HILOGI("ADF State: %{public}s", adfStateIt->second.c_str());
        return (adfStateIt->second == "ScannerAdfEmpty");
    }
    SCAN_HILOGE("scan:AdfState not found in status map");
    return false;
}

} // namespace OHOS::Scan
