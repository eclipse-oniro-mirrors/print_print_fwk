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

#ifndef PRINT_FEATURE_PLUGIN_LOADER_H
#define PRINT_FEATURE_PLUGIN_LOADER_H

#include <mutex>
#include <string>

#include "i_print_feature.h"

namespace OHOS::Print {

struct PrintFeatureDeleter {
    using DestroyFn = void (*)(IPrintFeature *);
    PrintFeatureDeleter() = default;
    explicit PrintFeatureDeleter(DestroyFn fn) : destroyFn(fn) {}

    void operator()(IPrintFeature *ptr) const
    {
        if (ptr != nullptr && destroyFn != nullptr) {
            destroyFn(ptr);
        }
    }

    DestroyFn destroyFn = nullptr;
};

class PrintFeaturePluginLoader {
public:
    PrintFeaturePluginLoader(const std::string &featureName, const std::string &libPath);
    PrintFeaturePluginLoader(const std::string &featureName, const std::string &libPath,
        const std::string &createSymbol, const std::string &destroySymbol);
    ~PrintFeaturePluginLoader();

    bool IsLoaded() const;
    bool Load();
    void Unload();
    void *GetSymbol(const std::string &symbolName);
    const std::string &GetCreateSymbol() const;
    const std::string &GetDestroySymbol() const;

private:
    std::string featureName_;
    std::string libPath_;
    std::string createSymbol_;
    std::string destroySymbol_;
    void *handle_ = nullptr;
    std::mutex mutex_;
};

} // namespace OHOS::Print
#endif // PRINT_FEATURE_PLUGIN_LOADER_H
