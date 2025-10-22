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
#include "securec.h"
#include "scan_log.h"
#include "scan_constant.h"
#include "escl_driver_manager.h"

namespace OHOS::Scan {
static const char* AIRSCAN_TARGET = "/system/lib64/libsane-airscan.z.so";
static const char* AIRSCAN_LINKPATH = "/data/service/el1/public/print_service/sane/backend/libsane-airscan.z.so";
static const char* CONFIG_FILE_PATH = "/data/service/el1/public/print_service/sane/config/airscan_dll.conf";
static const char* CONFIG_FILE_CONTENT = "airscan";
static const char* CONFIG_DIR_PATH = "/data/service/el1/public/print_service/sane/config";

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
} // namespace OHOS::Scan
