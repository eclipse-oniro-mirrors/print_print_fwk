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

#include "print_feature_plugin_loader.h"

#include <dlfcn.h>
#include <climits>
#include <cstring>
#include <unistd.h>

#include "print_log.h"

namespace OHOS::Print {

namespace {
constexpr const char *DEFAULT_CREATE_SYMBOL = "CreatePrintFeature";
constexpr const char *DEFAULT_DESTROY_SYMBOL = "DestroyPrintFeature";
}

PrintFeaturePluginLoader::PrintFeaturePluginLoader(const std::string &featureName, const std::string &libPath)
    : featureName_(featureName), libPath_(libPath),
      createSymbol_(DEFAULT_CREATE_SYMBOL), destroySymbol_(DEFAULT_DESTROY_SYMBOL)
{
}

PrintFeaturePluginLoader::PrintFeaturePluginLoader(const std::string &featureName, const std::string &libPath,
    const std::string &createSymbol, const std::string &destroySymbol)
    : featureName_(featureName), libPath_(libPath), createSymbol_(createSymbol), destroySymbol_(destroySymbol)
{
}

PrintFeaturePluginLoader::~PrintFeaturePluginLoader()
{
    Unload();
}

bool PrintFeaturePluginLoader::IsLoaded() const
{
    return handle_ != nullptr;
}

static std::string ResolveRealPath(const std::string &libPath)
{
    char resolvedPath[PATH_MAX] = {0};
    if (realpath(libPath.c_str(), resolvedPath) == nullptr) {
        PRINT_HILOGE("[%{public}s] resolve realpath failed: %{public}s", libPath.c_str(), strerror(errno));
        return "";
    }
    return std::string(resolvedPath);
}

static void *OpenPluginLibrary(const std::string &realPath, const std::string &featureName)
{
    void *handle = dlopen(realPath.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        PRINT_HILOGE("[%{public}s] dlopen failed: %{public}s", featureName.c_str(), dlerror());
        return nullptr;
    }
    return handle;
}

bool PrintFeaturePluginLoader::Load()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle_ != nullptr) {
        return true;
    }

    std::string realPath = ResolveRealPath(libPath_);
    if (realPath.empty()) {
        return false;
    }

    handle_ = OpenPluginLibrary(realPath, featureName_);
    if (handle_ == nullptr) {
        return false;
    }

    PRINT_HILOGI("[%{public}s] plugin loaded: %{public}s", featureName_.c_str(), realPath.c_str());
    return true;
}

void PrintFeaturePluginLoader::Unload()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle_ == nullptr) {
        return;
    }

    if (dlclose(handle_) != 0) {
        PRINT_HILOGE("[%{public}s] dlclose failed: %{public}s", featureName_.c_str(), dlerror());
    }
    handle_ = nullptr;
    PRINT_HILOGI("[%{public}s] plugin unloaded", featureName_.c_str());
}

void *PrintFeaturePluginLoader::GetSymbol(const std::string &symbolName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle_ == nullptr) {
        PRINT_HILOGE("[%{public}s] library not loaded when resolving %{public}s",
            featureName_.c_str(), symbolName.c_str());
        return nullptr;
    }

    dlerror(); // clear previous error state
    void *symbol = dlsym(handle_, symbolName.c_str());
    const char *err = dlerror();
    if (err != nullptr) {
        PRINT_HILOGE("[%{public}s] dlsym %{public}s failed: %{public}s",
            featureName_.c_str(), symbolName.c_str(), err);
        return nullptr;
    }
    return symbol;
}

const std::string &PrintFeaturePluginLoader::GetCreateSymbol() const
{
    return createSymbol_;
}

const std::string &PrintFeaturePluginLoader::GetDestroySymbol() const
{
    return destroySymbol_;
}

} // namespace OHOS::Print
