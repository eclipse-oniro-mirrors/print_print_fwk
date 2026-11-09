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

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "i_print_feature.h"
#include "print_feature_plugin_loader.h"
#include "print_feature_type.h"

namespace OHOS::Print {

class PrintFeaturePluginManager {
public:
    static PrintFeaturePluginManager &GetInstance();

    IPrintFeature *GetFeature(PrintFeatureType type);
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
    std::map<PrintFeatureType, FeatureEntry> features_;
};

} // namespace OHOS::Print
#endif // PRINT_FEATURE_PLUGIN_MANAGER_H
