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

#include "config_policy_utils.h"

#include <securec.h>
#include <fstream>
#include <sstream>

namespace OHOS::Print {

constexpr const char CFG_FILE[] = "etc/com.ohos.spooler/PRINTER/bsuni_output_format.json";

PrintCloudConfigManager &PrintCloudConfigManager::GetInstance()
{
    static PrintCloudConfigManager instance;
    return instance;
}

std::string PrintCloudConfigManager::GetCloudConfigFilePath()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string cfgPath = "";
    char buf[MAX_PATH_LEN] = {0};
    char *path = GetOneCfgFile(CFG_FILE, buf, MAX_PATH_LEN);
    if (path != nullptr && *path != '\0') {
        cfgPath = path;
    }

    PRINT_HILOGI("GetCloudConfigFilePath result: %{public}s", cfgPath.c_str());
    return dirPath;
}

std::string PrintCloudConfigManager::MatchPrinterMakeInCloudConfig(const std::string &printerMake)
{
    if (printerMake.empty()) {
        PRINT_HILOGW("printerMake is empty");
        return "";
    }

    std::string filePath = GetCloudConfigFilePath();
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
