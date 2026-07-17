/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <securec.h>
#include <dlfcn.h>
#include "print_log.h"
#include "print_constant.h"
#include "parameter.h"
#include "smb_library.h"
namespace OHOS::Print {
static constexpr int32_t INVALID_EVENT = -1;
const char* LIB_SMB2_SO_PATH = "print.libsmb2.so.path";

template <typename FuncPtr>
static bool LoadOneSymbol(void *handle, const char *name, FuncPtr &funcPtr)
{
    void *sym = dlsym(handle, name);
    if (sym == nullptr) {
        PRINT_HILOGE("dlsym %{public}s failed: %{public}s", name, dlerror());
        return false;
    }
    if (memcpy_s(&funcPtr, sizeof(FuncPtr), &sym, sizeof(void*)) != EOK) {
        PRINT_HILOGE("memcpy_s %{public}s failed", name);
        return false;
    }
    return true;
}

#define CHECK_LOAD_SYMBOL(handle, name, funcPtr) \
    if (!LoadOneSymbol((handle), (name), (funcPtr))) { \
        PRINT_HILOGE("%{public}s load %{public}s failed", __func__, (name)); \
        return false; \
    }

SmbLibrary::SmbLibrary() :smbLibHandle_(nullptr), smb2_init_context_(nullptr),
    smb2_close_context_(nullptr), smb2_destroy_context_(nullptr),
    smb2_connect_share_(nullptr), smb2_disconnect_share_(nullptr), smb2_set_user_(nullptr),
    smb2_set_password_(nullptr), smb2_set_domain_(nullptr), smb2_get_error_(nullptr),
    smb2_set_security_mode_(nullptr), smb2_set_timeout_(nullptr), smb2_share_enum_async_(nullptr),
    smb2_free_data_(nullptr), smb2_get_fd_(nullptr), smb2_which_events_(nullptr),
    smb2_service_(nullptr)
{
    InitializeLibrary();
}

SmbLibrary::~SmbLibrary()
{
    CleanupLibrary();
}

bool SmbLibrary::InitializeLibrary()
{
    if (smbLibHandle_ != nullptr) {
        return true;
    }
    char value[PATH_MAX] = {0};
    GetParameter(LIB_SMB2_SO_PATH, "", value, PATH_MAX - 1);
    char realValue[PATH_MAX] = {};
    if (realpath(value, realValue) == nullptr) {
        PRINT_HILOGE("The realSmbLibFile is null, errno:%{public}d", errno);
        return false;
    }
    smbLibHandle_ = dlopen(realValue, RTLD_LAZY);
    if (!smbLibHandle_) {
        PRINT_HILOGE("Failed to load SMB library: %{public}s", dlerror());
        return false;
    }
    if (!LoadSymbols()) {
        CleanupLibrary();
        return false;
    }
    PRINT_HILOGI("SMB library initialized successfully");
    return true;
}

bool SmbLibrary::LoadSymbols()
{
    dlerror();
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_init_context", smb2_init_context_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_close_context", smb2_close_context_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_destroy_context", smb2_destroy_context_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_connect_share", smb2_connect_share_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_disconnect_share", smb2_disconnect_share_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_set_user", smb2_set_user_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_set_password", smb2_set_password_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_set_domain", smb2_set_domain_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_get_error", smb2_get_error_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_set_security_mode", smb2_set_security_mode_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_set_timeout", smb2_set_timeout_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_share_enum_async", smb2_share_enum_async_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_free_data", smb2_free_data_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_get_fd", smb2_get_fd_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_which_events", smb2_which_events_);
    CHECK_LOAD_SYMBOL(smbLibHandle_, "smb2_service", smb2_service_);
    return true;
}

void SmbLibrary::CleanupLibrary()
{
    if (smbLibHandle_ != nullptr) {
        dlclose(smbLibHandle_);
        smbLibHandle_ = nullptr;
        smb2_init_context_ = nullptr;
        smb2_close_context_ = nullptr;
        smb2_destroy_context_ = nullptr;
        smb2_connect_share_ = nullptr;
        smb2_disconnect_share_ = nullptr;
        smb2_set_user_ = nullptr;
        smb2_set_password_ = nullptr;
        smb2_set_domain_ = nullptr;
        smb2_get_error_ = nullptr;
        smb2_set_security_mode_ = nullptr;
        smb2_set_timeout_ = nullptr;
        smb2_share_enum_async_ = nullptr;
        smb2_free_data_ = nullptr;
        smb2_get_fd_ = nullptr;
        smb2_which_events_ = nullptr;
        smb2_service_ = nullptr;
        PRINT_HILOGI("SMB library cleaned up");
    }
}

struct smb2_context* SmbLibrary::CreateContext() const
{
    if (!smb2_init_context_) {
        PRINT_HILOGE("smb2_init_context_ is null");
        return nullptr;
    }
    return smb2_init_context_();
}

void SmbLibrary::CloseContext(struct smb2_context* ctx) const
{
    if (!smb2_close_context_) {
        PRINT_HILOGE("smb2_close_context_ is null");
        return;
    }
    smb2_close_context_(ctx);
}

void SmbLibrary::DestroyContext(struct smb2_context* ctx) const
{
    if (!smb2_destroy_context_) {
        PRINT_HILOGE("smb2_destroy_context_ is null");
        return;
    }
    smb2_destroy_context_(ctx);
}

const char* SmbLibrary::GetSmbError(struct smb2_context* ctx) const
{
    if (!smb2_get_error_) {
        PRINT_HILOGE("smb2_get_error_ is null");
        return "SMB library not initialized";
    }
    return smb2_get_error_(ctx);
}

int32_t SmbLibrary::ConnectShare(struct smb2_context* ctx, const char* server,
    const char* share, const char* user) const
{
    if (!smb2_connect_share_) {
        PRINT_HILOGE("smb2_connect_share_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return smb2_connect_share_(ctx, server, share, user);
}

int32_t SmbLibrary::DisconnectShare(struct smb2_context* ctx) const
{
    if (!smb2_disconnect_share_) {
        PRINT_HILOGE("smb2_disconnect_share_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return smb2_disconnect_share_(ctx);
}

int32_t SmbLibrary::ShareEnumAsync(struct smb2_context* ctx, int32_t level,
    void (*callback)(struct smb2_context*, int32_t, void*, void*), void* privateData) const
{
    if (!smb2_share_enum_async_) {
        PRINT_HILOGE("smb2_share_enum_async_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return smb2_share_enum_async_(ctx, static_cast<enum SHARE_INFO_enum>(level), callback, privateData);
}

void SmbLibrary::FreeData(struct smb2_context* ctx, void* data) const
{
    if (!smb2_free_data_) {
        PRINT_HILOGE("smb2_free_data_ is null");
        return;
    }
    smb2_free_data_(ctx, data);
}

int32_t SmbLibrary::GetFd(struct smb2_context* ctx) const
{
    if (!smb2_get_fd_) {
        PRINT_HILOGE("smb2_get_fd_ is null");
        return INVALID_FD;
    }
    return smb2_get_fd_(ctx);
}

int32_t SmbLibrary::WhichEvents(struct smb2_context* ctx) const
{
    if (!smb2_which_events_) {
        PRINT_HILOGE("smb2_which_events_ is null");
        return INVALID_EVENT;
    }
    return smb2_which_events_(ctx);
}

int32_t SmbLibrary::Service(struct smb2_context* ctx, int32_t revents) const
{
    if (!smb2_service_) {
        PRINT_HILOGE("smb2_service_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return smb2_service_(ctx, revents);
}

void SmbLibrary::SetUser(struct smb2_context* ctx, const char* user) const
{
    if (!smb2_set_user_) {
        PRINT_HILOGE("smb2_set_user_ is null");
        return;
    }
    smb2_set_user_(ctx, user);
}

void SmbLibrary::SetPassword(struct smb2_context* ctx, const char* password) const
{
    if (!smb2_set_password_) {
        PRINT_HILOGE("smb2_set_password_ is null");
        return;
    }
    smb2_set_password_(ctx, password);
}

void SmbLibrary::SetSecurityMode(struct smb2_context* ctx, uint16_t mode) const
{
    if (!smb2_set_security_mode_) {
        PRINT_HILOGE("smb2_set_security_mode_ is null");
        return;
    }
    smb2_set_security_mode_(ctx, mode);
}

void SmbLibrary::SetTimeout(struct smb2_context* ctx, int32_t timeout) const
{
    if (!smb2_set_timeout_) {
        PRINT_HILOGE("smb2_set_timeout_ is null");
        return;
    }
    smb2_set_timeout_(ctx, timeout);
}
}  // namespace OHOS::Print