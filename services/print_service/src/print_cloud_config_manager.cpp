/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "print_cloud_config_manager.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_utils.h"

#include <securec.h>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace OHOS::Print {

const std::string SYSTEM_PRINTER_DIR = "/system/etc/com.ohos.spooler/PRINTER/";
const std::string DATA_PRINTER_DIR =
    "/data/service/el1/public/update/param_service/install/system/etc/com.ohos.spooler/PRINTER/";
const std::string VERSION_FILE_NAME = "version.txt";
const std::string CLOUD_CONFIG_FILE_NAME = "bsuni_output_format.json";
const std::string VERSION_KEY = "version";

PrintCloudConfigManager &PrintCloudConfigManager::GetInstance()
{
    static PrintCloudConfigManager instance;
    return instance;
}

std::string PrintCloudConfigManager::GetCloudConfigFilePath()
{
    std::string dataVersion = GetVersionFromDir(DATA_PRINTER_DIR);
    std::string sysVersion = GetVersionFromDir(SYSTEM_PRINTER_DIR);
    if (dataVersion.empty() && sysVersion.empty()) {
        PRINT_HILOGW("both version files not found");
        return "";
    }
    if (dataVersion.empty()) {
        PRINT_HILOGI("data version not found, use system dir");
        return SYSTEM_PRINTER_DIR + CLOUD_CONFIG_FILE_NAME;
    }
    if (sysVersion.empty()) {
        PRINT_HILOGI("system version not found, use data dir");
        return DATA_PRINTER_DIR + CLOUD_CONFIG_FILE_NAME;
    }

    if (CompareVersion(dataVersion, sysVersion) >= 0) {
        PRINT_HILOGI("data version >= system version, use data dir");
        return DATA_PRINTER_DIR + CLOUD_CONFIG_FILE_NAME;
    }
    PRINT_HILOGI("data version < system version, use system dir");
    return SYSTEM_PRINTER_DIR + CLOUD_CONFIG_FILE_NAME;
}

int PrintCloudConfigManager::CompareVersion(const std::string &v1, const std::string &v2)
{
    std::vector<int> parts1;
    std::vector<int> parts2;
    ParseVersionSegments(v1, parts1);
    ParseVersionSegments(v2, parts2);
    size_t maxLen = std::max(parts1.size(), parts2.size());
    for (size_t i = 0; i < maxLen; i++) {
        int a = (i < parts1.size()) ? parts1[i] : 0;
        int b = (i < parts2.size()) ? parts2[i] : 0;
        if (a != b) {
            return (a > b) ? 1 : -1;
        }
    }
    return 0;
}

void PrintCloudConfigManager::ParseVersionSegments(const std::string &v, std::vector<int> &parts)
{
    std::stringstream ss(v);
    std::string seg;
    while (std::getline(ss, seg, '.')) {
        int n = 0;
        for (char c : seg) {
            if (c < '0' || c > '9') {
                break;
            }
            n = n * DECIMAL_BASE + (c - '0');
        }
        parts.push_back(n);
    }
}

std::string PrintCloudConfigManager::GetVersionFromDir(const std::string &dir)
{
    if (dir.empty()) {
        return "";
    }
    std::string versionPath = dir + VERSION_FILE_NAME;
    if (!PrintUtils::IsPathValid(versionPath)) {
        PRINT_HILOGW("version path is invalid: %{public}s", versionPath.c_str());
        return "";
    }
    std::ifstream file(versionPath);
    if (!file.is_open()) {
        PRINT_HILOGW("version file not found: %{public}s", versionPath.c_str());
        return "";
    }
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, pos);
        size_t keyEnd = key.find_last_not_of(" \t\r\n");
        if (keyEnd == std::string::npos) {
            continue;
        }
        key = key.substr(0, keyEnd + 1);
        if (key != VERSION_KEY) {
            continue;
        }
        std::string value = line.substr(pos + 1);
        size_t valStart = value.find_first_not_of(" \t");
        size_t valEnd = value.find_last_not_of(" \t\r\n");
        if (valStart == std::string::npos) {
            file.close();
            return "";
        }
        std::string version = value.substr(valStart, valEnd - valStart + 1);
        file.close();
        return version;
    }
    file.close();
    PRINT_HILOGW("version key not found in: %{public}s", versionPath.c_str());
    return "";
}

std::string PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(const std::string &printerMake)
{
    if (printerMake.empty()) {
        PRINT_HILOGW("printerMake is empty");
        return "";
    }

    std::string filePath = GetCloudConfigFilePath();
    PRINT_HILOGI("GetCloudConfigFilePath result: %{public}s", filePath.c_str());
    if (filePath.empty()) {
        PRINT_HILOGW("cloud config file path is empty");
        return "";
    }

    std::string cloudConfigContent;
    if (!LoadCloudConfigFile(filePath, cloudConfigContent)) {
        PRINT_HILOGW("load cloud config file failed");
        return "";
    }

    if (cloudConfigContent.empty()) {
        PRINT_HILOGW("cloud config content is empty");
        return "";
    }

    Json::Value root;
    if (!PrintJsonUtil::Parse(cloudConfigContent, root)) {
        PRINT_HILOGW("parse cloud config json failed");
        return "";
    }

    if (!root.isArray()) {
        PRINT_HILOGW("cloud config root is not array");
        return "";
    }
    for (const auto &item : root) {
        if (!item.isMember("bsuniOutputFormat") || !item["bsuniOutputFormat"].isString() ||
            !item.isMember("printerMakes") || !item["printerMakes"].isArray()) {
            PRINT_HILOGE("bsuniOutputFormat or printerMakes is missing or invalid type");
            continue;
        }
        std::string formatValue = item["bsuniOutputFormat"].asString();
        Json::Value printerMakes = item["printerMakes"];
        for (const auto &make : printerMakes) {
            if (make.isString() && make.asString() == printerMake) {
                PRINT_HILOGI("printerMake %{public}s matched, output format: %{public}s",
                    printerMake.c_str(), formatValue.c_str());
                return formatValue;
            }
        }
    }

    PRINT_HILOGI("printerMake %{public}s not found in cloud config", printerMake.c_str());
    return "";
}

bool PrintCloudConfigManager::LoadCloudConfigFile(const std::string &filePath, std::string &cloudConfigContent)
{
    if (!PrintUtils::IsPathValid(filePath)) {
        PRINT_HILOGE("Invalid cloud config file path!");
        return false;
    }
    std::ifstream file(filePath);
    if (!file.is_open()) {
        PRINT_HILOGE("Failed to open file: %{public}s, error: %{public}s", filePath.c_str(), strerror(errno));
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    cloudConfigContent = buffer.str();
    file.close();

    PRINT_HILOGI("load cloud config file success, content length: %{public}zu", cloudConfigContent.size());
    return true;
}
} // namespace OHOS::Print
