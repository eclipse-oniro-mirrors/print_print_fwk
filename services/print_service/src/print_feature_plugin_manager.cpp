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

#include "print_feature_plugin_manager.h"

#include "print_failure_ai_notifier.h"
#include "print_log.h"

namespace OHOS::Print {

namespace {
constexpr const char *REMOTE_PLUGIN_NAME = "libprint_feature_remote.z.so";
constexpr const char *AI_NOTIFIER_PLUGIN_NAME = "libprint_feature_ai_notifier.z.so";

#if (defined(__aarch64__) || defined(__x86_64__))
constexpr const char *SYSTEM_LIB_DIR = "/system/lib64/";
#else
constexpr const char *SYSTEM_LIB_DIR = "/system/lib/";
#endif

std::string ResolveSystemPluginPath(const char *pluginName)
{
    return std::string(SYSTEM_LIB_DIR) + pluginName;
}
constexpr const char *REMOTE_CREATE_SYMBOL = "CreateRemotePrintFeature";
constexpr const char *REMOTE_DESTROY_SYMBOL = "DestroyRemotePrintFeature";
constexpr const char *AI_NOTIFIER_CREATE_SYMBOL = "CreatePrintFailureAiNotifier";
constexpr const char *AI_NOTIFIER_DESTROY_SYMBOL = "DestroyPrintFailureAiNotifier";
constexpr const char *MANAGER_LOG_TAG = "PrintFeaturePluginManager";

using CreateFeatureFn = IPrintFeature *(*)();
using DestroyFeatureFn = void (*)(IPrintFeature *);
}

PrintFeaturePluginManager &PrintFeaturePluginManager::GetInstance()
{
    static PrintFeaturePluginManager instance;
    return instance;
}

PrintFeaturePluginManager::PrintFeaturePluginManager()
{
    features_[PrintFeatureType::REMOTE_PRINTER_MANAGER] = {
        ResolveSystemPluginPath(REMOTE_PLUGIN_NAME), REMOTE_CREATE_SYMBOL, REMOTE_DESTROY_SYMBOL, nullptr, nullptr};
    features_[PrintFeatureType::AI_NOTIFIER] = {
        ResolveSystemPluginPath(AI_NOTIFIER_PLUGIN_NAME), AI_NOTIFIER_CREATE_SYMBOL, AI_NOTIFIER_DESTROY_SYMBOL,
        nullptr, nullptr};
}

PrintFeaturePluginManager::~PrintFeaturePluginManager()
{
    UnloadAll();
}

bool PrintFeaturePluginManager::EnsureLoaderCreated(FeatureEntry &entry,
    const std::string &featureName)
{
    if (entry.loader != nullptr) {
        return true;
    }
    entry.loader = std::make_unique<PrintFeaturePluginLoader>(featureName, entry.libPath,
        entry.createSymbol, entry.destroySymbol);
    return entry.loader != nullptr;
}

std::unique_ptr<IPrintFeature, PrintFeatureDeleter> PrintFeaturePluginManager::CreateFeatureFromLoader(
    PrintFeaturePluginLoader &loader)
{
    auto createFn = reinterpret_cast<CreateFeatureFn>(loader.GetSymbol(loader.GetCreateSymbol()));
    auto destroyFn = reinterpret_cast<DestroyFeatureFn>(loader.GetSymbol(loader.GetDestroySymbol()));
    if (createFn == nullptr || destroyFn == nullptr) {
        return nullptr;
    }

    IPrintFeature *feature = createFn();
    if (feature == nullptr) {
        PRINT_HILOGE("[%{public}s] CreatePrintFeature returned null", MANAGER_LOG_TAG);
        return nullptr;
    }
    return std::unique_ptr<IPrintFeature, PrintFeatureDeleter>(feature, PrintFeatureDeleter(destroyFn));
}

std::unique_ptr<IPrintFeature, PrintFeatureDeleter> PrintFeaturePluginManager::CreateLoadedFeature(
    PrintFeaturePluginLoader &loader, const std::string &featureName)
{
    if (!loader.Load()) {
        PRINT_HILOGE("[%{public}s] failed to load %{public}s", MANAGER_LOG_TAG, featureName.c_str());
        return nullptr;
    }

    auto loadedFeature = CreateFeatureFromLoader(loader);
    if (loadedFeature == nullptr) {
        PRINT_HILOGE("[%{public}s] create feature failed %{public}s", MANAGER_LOG_TAG, featureName.c_str());
        loader.Unload();
        return nullptr;
    }
    return loadedFeature;
}

IPrintFeature *PrintFeaturePluginManager::GetFeature(PrintFeatureType type)
{
    FeatureEntry *entryPtr = nullptr;
    std::string featureName;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = features_.find(type);
        if (it == features_.end()) {
            PRINT_HILOGE("[%{public}s] unsupported feature type", MANAGER_LOG_TAG);
            return nullptr;
        }
        entryPtr = &it->second;
        if (entryPtr->impl != nullptr) {
            return entryPtr->impl.get();
        }
        featureName = std::to_string(static_cast<int32_t>(type));
        if (!EnsureLoaderCreated(*entryPtr, featureName)) {
            return nullptr;
        }
    }

    auto loadedFeature = CreateLoadedFeature(*entryPtr->loader, featureName);
    if (loadedFeature == nullptr) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (entryPtr->impl != nullptr) {
        return entryPtr->impl.get();
    }
    entryPtr->impl = std::move(loadedFeature);
    return entryPtr->impl.get();
}

void PrintFeaturePluginManager::UnloadAll()
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &pair : features_) {
        FeatureEntry &entry = pair.second;
        entry.impl.reset();
        if (entry.loader != nullptr) {
            entry.loader->Unload();
            entry.loader.reset();
        }
    }
    PrintFailureAiNotifier::GetInstance().Reset();
}

} // namespace OHOS::Print
