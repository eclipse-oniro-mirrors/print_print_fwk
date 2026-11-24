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

#include <chrono>

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
constexpr int32_t PLUGIN_UNLOAD_TIMEOUT_MS = 5000;

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

PrintFeaturePluginManager::FeatureUseGuard::FeatureUseGuard(
    PrintFeaturePluginManager *mgr, PrintFeatureType type, IPrintFeature *feature)
    : mgr_(mgr), type_(type), feature_(feature)
{
}

PrintFeaturePluginManager::FeatureUseGuard::~FeatureUseGuard()
{
    Release();
}

PrintFeaturePluginManager::FeatureUseGuard::FeatureUseGuard(FeatureUseGuard &&other) noexcept
    : mgr_(other.mgr_), type_(other.type_), feature_(other.feature_)
{
    other.mgr_ = nullptr;
    other.feature_ = nullptr;
}

PrintFeaturePluginManager::FeatureUseGuard &PrintFeaturePluginManager::FeatureUseGuard::operator=(
    FeatureUseGuard &&other) noexcept
{
    if (this != &other) {
        Release();
        mgr_ = other.mgr_;
        type_ = other.type_;
        feature_ = other.feature_;
        other.mgr_ = nullptr;
        other.feature_ = nullptr;
    }
    return *this;
}

void PrintFeaturePluginManager::FeatureUseGuard::Release()
{
    if (mgr_ == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mgr_->mutex_);
        auto it = mgr_->activeCounts_.find(type_);
        if (it != mgr_->activeCounts_.end() && it->second > 0) {
            --(it->second);
        }
    }
    mgr_->unloadCv_.notify_all();
    mgr_ = nullptr;
    feature_ = nullptr;
}

PrintFeaturePluginManager::FeatureUseGuard PrintFeaturePluginManager::AcquireFeature(PrintFeatureType type)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = features_.find(type);
    if (it == features_.end()) {
        PRINT_HILOGE("[%{public}s] unsupported feature type", MANAGER_LOG_TAG);
        return FeatureUseGuard();
    }

    FeatureEntry &entry = it->second;
    if (unloading_) {
        PRINT_HILOGW("[%{public}s] feature is unloading", MANAGER_LOG_TAG);
        return FeatureUseGuard();
    }

    if (entry.impl != nullptr) {
        ++activeCounts_[type];
        return FeatureUseGuard(this, type, entry.impl.get());
    }

    std::string featureName = std::to_string(static_cast<int32_t>(type));
    if (!EnsureLoaderCreated(entry, featureName)) {
        return FeatureUseGuard();
    }

    auto loadedFeature = CreateLoadedFeature(*entry.loader, featureName);
    if (loadedFeature == nullptr) {
        return FeatureUseGuard();
    }

    entry.impl = std::move(loadedFeature);
    ++activeCounts_[type];
    return FeatureUseGuard(this, type, entry.impl.get());
}

bool PrintFeaturePluginManager::IsFeatureLoaded(PrintFeatureType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = features_.find(type);
    if (it == features_.end()) {
        return false;
    }
    return it->second.impl != nullptr;
}

void PrintFeaturePluginManager::UnloadAll()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        unloading_ = true;
    }

    {
        std::unique_lock<std::mutex> lock(mutex_);
        bool idle = unloadCv_.wait_for(lock, std::chrono::milliseconds(PLUGIN_UNLOAD_TIMEOUT_MS),
            [this] {
                for (auto &pair : activeCounts_) {
                    if (pair.second > 0) {
                        return false;
                    }
                }
                return true;
            });
        if (!idle) {
            PRINT_HILOGW("[%{public}s] timeout waiting for feature usage idle", MANAGER_LOG_TAG);
        }
    }

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
        unloading_ = false;
    }
    PrintFailureAiNotifier::GetInstance().Reset();
}

} // namespace OHOS::Print
