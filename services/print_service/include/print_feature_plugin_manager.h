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

#ifndef PRINT_FEATURE_PLUGIN_MANAGER_H
#define PRINT_FEATURE_PLUGIN_MANAGER_H

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <cstring>

#include "i_print_feature.h"
#include "print_feature_plugin_loader.h"
#include "print_feature_type.h"

namespace OHOS::Print {

class PrintFeaturePluginManager {
public:
    static PrintFeaturePluginManager &GetInstance();

    class FeatureUseGuard {
    public:
        FeatureUseGuard() = default;
        FeatureUseGuard(PrintFeaturePluginManager *mgr, PrintFeatureType type, IPrintFeature *feature);
        ~FeatureUseGuard();
        FeatureUseGuard(FeatureUseGuard &&other) noexcept;
        FeatureUseGuard &operator=(FeatureUseGuard &&other) noexcept;
        FeatureUseGuard(const FeatureUseGuard &) = delete;
        FeatureUseGuard &operator=(const FeatureUseGuard &) = delete;

        explicit operator bool() const { return feature_ != nullptr; }
        IPrintFeature *Get() const { return feature_; }

    private:
        void Release();

        PrintFeaturePluginManager *mgr_ = nullptr;
        PrintFeatureType type_ = static_cast<PrintFeatureType>(-1);
        IPrintFeature *feature_ = nullptr;
    };

    FeatureUseGuard AcquireFeature(PrintFeatureType type);
    bool IsFeatureLoaded(PrintFeatureType type);
    void UnloadAll();

private:
    PrintFeaturePluginManager();
    ~PrintFeaturePluginManager();

    struct FeatureEntry {
        std::string libPath;
        std::string createSymbol;
        std::string destroySymbol;
        std::unique_ptr<PrintFeaturePluginLoader> loader;
        std::unique_ptr<IPrintFeature, PrintFeatureDeleter> impl;
    };

    bool EnsureLoaderCreated(FeatureEntry &entry, const std::string &featureName);
    std::unique_ptr<IPrintFeature, PrintFeatureDeleter> CreateFeatureFromLoader(PrintFeaturePluginLoader &loader);
    std::unique_ptr<IPrintFeature, PrintFeatureDeleter> CreateLoadedFeature(
        PrintFeaturePluginLoader &loader, const std::string &featureName);

    std::mutex mutex_;
    std::condition_variable unloadCv_;
    std::map<PrintFeatureType, FeatureEntry> features_;
    std::map<PrintFeatureType, int32_t> activeCounts_;
    bool unloading_ = false;
};

} // namespace OHOS::Print
#endif // PRINT_FEATURE_PLUGIN_MANAGER_H
