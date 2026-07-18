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

#ifndef PRINT_CLOUD_CONFIG_MANAGER_H
#define PRINT_CLOUD_CONFIG_MANAGER_H

#include <string>
#include <mutex>

namespace OHOS::Print {

class PrintCloudConfigManagerBase {
public:
    virtual std::string GetCloudConfigFilePath() = 0;
    virtual std::string MatchPrinterMakeInCloudConfig(const std::string &printerMake) = 0;
    virtual bool LoadCloudConfigFile(const std::string &filePath, std::string &cloudConfigContent) = 0;
};

class PrintCloudConfigManager : public PrintCloudConfigManagerBase {
public:
    static PrintCloudConfigManager &GetInstance();

    std::string GetCloudConfigFilePath() override;
    std::string MatchPrinterMakeInCloudConfig(const std::string &printerMake) override;
    bool LoadCloudConfigFile(const std::string &filePath, std::string &cloudConfigContent) override;

private:
    PrintCloudConfigManager() = default;
    ~PrintCloudConfigManager() = default;
    PrintCloudConfigManager(const PrintCloudConfigManager &) = delete;
    PrintCloudConfigManager &operator=(const PrintCloudConfigManager &) = delete;

    std::mutex mutex_;
};

} // namespace OHOS::Print
#endif // PRINT_CLOUD_CONFIG_MANAGER_H
