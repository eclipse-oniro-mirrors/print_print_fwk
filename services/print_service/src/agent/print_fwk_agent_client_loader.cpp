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

#include "agent/print_fwk_agent_client_loader.h"

#include <climits>
#include <dlfcn.h>
#include <string>

#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
namespace {
constexpr const char *CLIENT_LIBRARY_PATH =
    "/system/lib64/libprint_fwk_agent_client.z.so";
constexpr const char *FACTORY_SYMBOL = "GetPrintFwkAgentClientApi";
constexpr uint32_t EXPECTED_ABI_VERSION = 1;
} // namespace

PrintFwkAgentClientLoader::~PrintFwkAgentClientLoader()
{
    Unload();
}

bool PrintFwkAgentClientLoader::Load()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (api_ != nullptr && handle_ != nullptr) {
        return true;
    }

    PRINT_HILOGI("client_loader Load: start");
    void *libHandle = OpenClientLibrary();
    if (libHandle == nullptr) {
        return false;
    }

    const PrintFwkAgentClientApi *api = ResolveClientApi(libHandle);
    if (api == nullptr) {
        dlclose(libHandle);
        return false;
    }

    PrintFwkAgentClient *client = api->create();
    if (client == nullptr) {
        PRINT_HILOGE(
            "print_fwk_agent_client_loader: create() returned null");
        dlclose(libHandle);
        return false;
    }

    libHandle_ = libHandle;
    api_ = api;
    handle_ = client;
    PRINT_HILOGI("print_fwk_agent_client loaded");
    return true;
}

void *PrintFwkAgentClientLoader::OpenClientLibrary() const
{
    char real[PATH_MAX] = {};
    if (realpath(CLIENT_LIBRARY_PATH, real) == nullptr) {
        PRINT_HILOGE("print_fwk_agent_client_loader: realpath failed "
            "for %{public}s, errno:%{public}d", CLIENT_LIBRARY_PATH, errno);
        return nullptr;
    }

    void *libHandle = dlopen(real, RTLD_LAZY | RTLD_NODELETE);
    if (libHandle == nullptr) {
        PRINT_HILOGE("print_fwk_agent_client_loader: dlopen failed for "
            "%{public}s: %{public}s", real, dlerror());
    }
    return libHandle;
}

const PrintFwkAgentClientApi *PrintFwkAgentClientLoader::ResolveClientApi(void *libHandle) const
{
    using FactoryFn = const PrintFwkAgentClientApi *(*)();
    auto factory = reinterpret_cast<FactoryFn>(dlsym(libHandle, FACTORY_SYMBOL));
    const char *dlsymErr = dlerror();
    if (dlsymErr != nullptr) {
        PRINT_HILOGE("print_fwk_agent_client_loader: dlsym(%{public}s) "
            "failed: %{public}s", FACTORY_SYMBOL, dlsymErr);
        return nullptr;
    }

    const PrintFwkAgentClientApi *api = factory();
    if (!ValidateApi(api)) {
        PRINT_HILOGE(
            "print_fwk_agent_client_loader: vtable validation failed");
        return nullptr;
    }
    return api;
}

void PrintFwkAgentClientLoader::Unload()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (api_ && handle_) {
        api_->destroy(handle_);
        handle_ = nullptr;
    }
    if (libHandle_) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
    }
    api_ = nullptr;
}

bool PrintFwkAgentClientLoader::ValidateApi(
    const PrintFwkAgentClientApi *api) const
{
    if (api == nullptr) {
        PRINT_HILOGE("client_loader ValidateApi: api is null");
        return false;
    }
    if (api->abiVersion != EXPECTED_ABI_VERSION) {
        PRINT_HILOGE(
            "print_fwk_agent_client_loader: abiVersion mismatch, "
            "expected %{public}u, got %{public}u", EXPECTED_ABI_VERSION, api->abiVersion);
        return false;
    }
    if (api->create == nullptr || api->destroy == nullptr ||
        api->addPrinter == nullptr || api->removePrinter == nullptr ||
        api->ensureBackendReady == nullptr || api->isBackendOnline == nullptr ||
        api->backendKeepaliveTick == nullptr) {
        PRINT_HILOGE(
            "print_fwk_agent_client_loader: vtable contains null "
            "function pointer");
        return false;
    }
    return true;
}

int32_t PrintFwkAgentClientLoader::AddPrinter(
    const PrintAddPrinterParam &params, PrintAgentAddDoneCb doneCb,
    PrintAgentProgressCb progressCb, void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsLoaded()) {
        PRINT_HILOGE("client_loader AddPrinter: loader not loaded");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = api_->addPrinter(handle_, &params, doneCb, progressCb, userData);
    const int32_t mapped = MapError(ret);
    PRINT_HILOGI("client_loader AddPrinter: ret=%{public}d", mapped);
    return mapped;
}

int32_t PrintFwkAgentClientLoader::RemovePrinter(const std::string &name,
    const std::string &backendType, PrintAgentRemoveDoneCb doneCb, void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsLoaded()) {
        PRINT_HILOGE("print_fwk_agent_client_loader: RemovePrinter "
            "called but loader not loaded");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = api_->removePrinter(handle_, name.c_str(), backendType.c_str(), doneCb, userData);
    const int32_t mapped = MapError(ret);
    PRINT_HILOGI(
        "client_loader RemovePrinter: name=%{public}s, ret=%{public}d", name.c_str(), mapped);
    return mapped;
}

int32_t PrintFwkAgentClientLoader::EnsureBackendReady()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsLoaded()) {
        PRINT_HILOGE("client_loader EnsureBackendReady: loader not loaded");
        return E_PRINT_AGENT_BACKEND_RESUME_FAILED;
    }
    int32_t ret = api_->ensureBackendReady(handle_);
    if (ret == PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT) {
        return E_PRINT_AGENT_BACKEND_RESUME_TIMEOUT;
    }
    return MapError(ret);
}

bool PrintFwkAgentClientLoader::IsBackendOnline()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsLoaded()) {
        PRINT_HILOGE("client_loader IsBackendOnline: loader not loaded");
        return false;
    }
    return api_->isBackendOnline(handle_);
}

void PrintFwkAgentClientLoader::BackendKeepaliveTick()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsLoaded()) {
        PRINT_HILOGE("client_loader BackendKeepaliveTick: loader not loaded");
        return;
    }
    api_->backendKeepaliveTick(handle_);
}

void PrintFwkAgentClientLoader::SetApiForTest(const PrintFwkAgentClientApi *api,
    PrintFwkAgentClient *client)
{
    std::lock_guard<std::mutex> lock(mutex_);
    api_ = api;
    handle_ = client;
}

int32_t PrintFwkAgentClientLoader::MapError(int32_t e)
{
    switch (e) {
        case PRINT_FWK_AGENT_CLIENT_OK:
            return E_PRINT_NONE;
        case PRINT_FWK_AGENT_CLIENT_ERR_PARAM:
            return E_PRINT_INVALID_PARAMETER;
        case PRINT_FWK_AGENT_CLIENT_ERR_SERVER:
            return E_PRINT_SERVER_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS:
            return E_PRINT_INVALID_PRINTER;
        case PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND:
            return E_PRINT_INVALID_PRINTER;
        case PRINT_FWK_AGENT_CLIENT_ERR_RPC:
            return E_PRINT_RPC_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_UNIMPLEMENTED:
            return E_PRINT_INVALID_PARAMETER;
        case PRINT_FWK_AGENT_CLIENT_ERR_BACKEND_CONFIG:
            return E_PRINT_RPC_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR:
            return E_PRINT_SERVER_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED:
            return E_PRINT_SERVER_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY:
            return E_PRINT_SERVER_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT:
            return E_PRINT_RPC_FAILURE;
        case PRINT_FWK_AGENT_CLIENT_BACKEND_STOPPED:
            return E_PRINT_AGENT_BACKEND_STOPPED;
        case PRINT_FWK_AGENT_CLIENT_BACKEND_RESUME_FAILED:
            return E_PRINT_AGENT_BACKEND_RESUME_FAILED;
        default:
            return E_PRINT_RPC_FAILURE;
    }
}

} // namespace OHOS::Print
