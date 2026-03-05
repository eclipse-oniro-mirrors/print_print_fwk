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

#ifndef PRINT_RESOURCE_MANAGER_H
#define PRINT_RESOURCE_MANAGER_H

#include <mutex>
#include <string>
#include <memory>
#include "resource_manager.h"
#include "image_source.h"
#include "pixel_map.h"
#include "res_config.h"

namespace OHOS::Print {

class PrintResourceManager {
public:
    static PrintResourceManager& GetInstance();

    std::string GetStringByName(const std::string& name);
    std::shared_ptr<Media::PixelMap> GetPixelMapByName(const std::string& name);

private:
    PrintResourceManager();
    ~PrintResourceManager() = default;
    PrintResourceManager(const PrintResourceManager&) = delete;
    PrintResourceManager& operator=(const PrintResourceManager&) = delete;

    void RefreshResConfig();

    std::mutex resConfigMutex_;
    std::unique_ptr<Global::Resource::ResConfig> resConfig_;
    std::unique_ptr<Global::Resource::ResourceManager> resourceManager_;
    const std::string resourcePath_ = "/system/app/Spooler/Spooler.hap";
};

} // namespace OHOS::Print

#endif // PRINT_RESOURCE_MANAGER_H
