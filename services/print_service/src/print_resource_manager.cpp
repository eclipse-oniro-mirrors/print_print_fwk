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

#include "print_resource_manager.h"
#include "print_log.h"
#include "locale_config.h"
#include "image_source.h"
#include "pixel_map.h"

namespace OHOS::Print {

PrintResourceManager::PrintResourceManager()
    : resConfig_(Global::Resource::CreateResConfig()),
      resourceManager_(Global::Resource::GetSystemResourceManagerNoSandBox())
{
    if (!resConfig_) {
        PRINT_HILOGE("resConfig_ is null");
        return;
    }
    if (!resourceManager_) {
        PRINT_HILOGE("resourceManager_ is null");
        return;
    }
    bool addResult = resourceManager_->AddResource(resourcePath_.c_str());
    if (!addResult) {
        PRINT_HILOGE("AddResource failed");
    }
}

PrintResourceManager& PrintResourceManager::GetInstance()
{
    static PrintResourceManager instance;
    return instance;
}

void PrintResourceManager::RefreshResConfig()
{
    std::string language = OHOS::Global::I18n::LocaleConfig::GetSystemLanguage();
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language, status);
    if (status != U_ZERO_ERROR) {
        PRINT_HILOGE("Locale forLanguageTag failed, status: %{public}d", status);
        return;
    }
    std::lock_guard<std::mutex> lock(resConfigMutex_);
    resConfig_->SetLocaleInfo(locale.getLanguage(), locale.getScript(), locale.getCountry());
    if (!resourceManager_) {
        PRINT_HILOGE("resourceManager_ is null");
        return;
    }
    resourceManager_->UpdateResConfig(*resConfig_);
}

std::string PrintResourceManager::GetStringByName(const std::string& name)
{
    RefreshResConfig();
    std::string result;
    if (!resourceManager_) {
        PRINT_HILOGE("resourceManager_ is null");
        return "";
    }
    Global::Resource::RState rstate = resourceManager_->GetStringByName(name.c_str(), result);
    if (rstate != Global::Resource::RState::SUCCESS) {
        PRINT_HILOGE("GetStringByName failed, result: %{public}d", rstate);
    }
    PRINT_HILOGD("GetStringByName: name: %{public}s, result: %{public}s", name.c_str(), result.c_str());
    return result;
}

std::shared_ptr<Media::PixelMap> PrintResourceManager::GetPixelMapByName(const std::string& name)
{
    RefreshResConfig();
    if (!resourceManager_) {
        PRINT_HILOGE("resourceManager_ is null");
        return nullptr;
    }

    size_t len = 0;
    std::unique_ptr<uint8_t[]> data;
    Global::Resource::RState rstate = resourceManager_->GetMediaDataByName(name.c_str(), len, data);
    if (rstate != Global::Resource::RState::SUCCESS || len == 0 || !data) {
        PRINT_HILOGE("GetMediaDataByName failed, name: %{public}s, result: %{public}d, len: %{public}zu",
            name.c_str(), rstate, len);
        return nullptr;
    }

    Media::SourceOptions opts;
    uint32_t errorCode = 0;
    auto imageSource = Media::ImageSource::CreateImageSource(data.get(), len, opts, errorCode);
    if (!imageSource || errorCode != 0) {
        PRINT_HILOGE("CreateImageSource failed, name: %{public}s, errorCode: %{public}u", name.c_str(), errorCode);
        return nullptr;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(0, decodeOpts, errorCode);
    if (!pixelMap || errorCode != 0) {
        PRINT_HILOGE("CreatePixelMap failed, name: %{public}s, errorCode: %{public}u", name.c_str(), errorCode);
        return nullptr;
    }

    return pixelMap;
}

} // namespace OHOS::Print
