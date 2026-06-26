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

class PrintCloudConfigManager {
public:
    static PrintCloudConfigManager &GetInstance();

#ifdef UNIT_TEST
    static void SetInstance(PrintCloudConfigManager *instance);
    static void ResetInstance();
#endif // UNIT_TEST

    virtual std::string GetCloudConfigFilePath();
    virtual std::string MatchPrinterMakeInCloudConfig(const std::string &printerMake);
    virtual bool LoadCloudConfigFile(const std::string &filePath, std::string &cloudConfigContent);

#ifdef UNIT_TEST
protected:
#else
private:
#endif // UNIT_TEST
    PrintCloudConfigManager() = default;
    ~PrintCloudConfigManager() = default;
    PrintCloudConfigManager(const PrintCloudConfigManager &) = delete;
    PrintCloudConfigManager &operator=(const PrintCloudConfigManager &) = delete;

    std::mutex mutex_;

#ifdef UNIT_TEST
    static PrintCloudConfigManager *instance_;
    static std::mutex instanceLock_;
#endif // UNIT_TEST
};

} // namespace OHOS::Print
#endif // PRINT_CLOUD_CONFIG_MANAGER_H
