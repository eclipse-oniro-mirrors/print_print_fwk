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

#ifndef MOCK_PRINT_CLOUD_CONFIG_MANAGER_H
#define MOCK_PRINT_CLOUD_CONFIG_MANAGER_H

#include <gmock/gmock.h>
#include <string>
#include "print_cloud_config_manager.h"

namespace OHOS::Print {

class MockPrintCloudConfigManager : public PrintCloudConfigManager {
public:
    MOCK_METHOD(std::string, GetCloudConfigFilePath, (), (override));
    MOCK_METHOD(std::string, MatchPrinterMakeInCloudConfig, (const std::string &printerMake), (override));
    MOCK_METHOD(bool, LoadCloudConfigFile, (const std::string &filePath, std::string &cloudConfigContent), (override));
};

} // namespace OHOS::Print

#endif // MOCK_PRINT_CLOUD_CONFIG_MANAGER_H
