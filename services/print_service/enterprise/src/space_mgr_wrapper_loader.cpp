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

#include "space_mgr_wrapper_loader.h"

#include <climits>
#include <dlfcn.h>

#include "print_log.h"

namespace OHOS::Print {
namespace {
constexpr const char *LIBRARY_PATH = "/system/lib64/libspace_mgr_wrapper.z.so";
constexpr const char *FACTORY_SYMBOL = "GetSpaceMgrWrapperApi";
constexpr uint32_t EXPECTED_ABI_VERSION = 1;
} // namespace

SpaceMgrWrapperLoader::~SpaceMgrWrapperLoader()
{
    Unload();
}

bool SpaceMgrWrapperLoader::Load()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (api_ != nullptr && handle_ != nullptr) {
        return true;
    }

    PRINT_HILOGI("SpaceMgrWrapperLoader Load: start");
    void *libHandle = OpenLibrary();
    if (libHandle == nullptr) {
        return false;
    }

    const SpaceMgrWrapperApi *api = ResolveApi(libHandle);
    if (api == nullptr) {
        dlclose(libHandle);
        return false;
    }

    handle_ = libHandle;
    api_ = api;
    PRINT_HILOGI("SpaceMgrWrapper loaded");
    return true;
}

void *SpaceMgrWrapperLoader::OpenLibrary() const
{
    char real[PATH_MAX] = {};
    if (realpath(LIBRARY_PATH, real) == nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: realpath failed for %{public}s, errno:%{public}d",
            LIBRARY_PATH, errno);
        return nullptr;
    }

    void *libHandle = dlopen(real, RTLD_LAZY | RTLD_NODELETE);
    if (libHandle == nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: dlopen failed for %{public}s: %{public}s", real, dlerror());
    }
    return libHandle;
}

const SpaceMgrWrapperApi *SpaceMgrWrapperLoader::ResolveApi(void *libHandle) const
{
    using FactoryFn = const SpaceMgrWrapperApi *(*)();
    auto factory = reinterpret_cast<FactoryFn>(dlsym(libHandle, FACTORY_SYMBOL));
    const char *dlsymErr = dlerror();
    if (dlsymErr != nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: dlsym(%{public}s) failed: %{public}s", FACTORY_SYMBOL, dlsymErr);
        return nullptr;
    }

    const SpaceMgrWrapperApi *api = factory();
    if (!ValidateApi(api)) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: vtable validation failed");
        return nullptr;
    }
    return api;
}

void SpaceMgrWrapperLoader::Unload()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    api_ = nullptr;
}

bool SpaceMgrWrapperLoader::ValidateApi(const SpaceMgrWrapperApi *api) const
{
    if (api == nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader ValidateApi: api is null");
        return false;
    }
    if (api->abiVersion != EXPECTED_ABI_VERSION) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: abiVersion mismatch, expected %{public}u, got %{public}u",
            EXPECTED_ABI_VERSION, api->abiVersion);
        return false;
    }
    if (api->isEnterpriseWorkspace == nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: vtable contains null function pointer");
        return false;
    }
    return true;
}

int32_t SpaceMgrWrapperLoader::IsEnterpriseWorkspace(int32_t workspaceId, bool &isEnterprise)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (api_ == nullptr) {
        PRINT_HILOGE("SpaceMgrWrapperLoader: not loaded");
        return SPACE_MGR_WRAPPER_ERR_INTERNAL;
    }
    bool result = false;
    int32_t ret = api_->isEnterpriseWorkspace(workspaceId, &result);
    if (ret == SPACE_MGR_WRAPPER_OK) {
        isEnterprise = result;
    }
    return ret;
}

} // namespace OHOS::Print
