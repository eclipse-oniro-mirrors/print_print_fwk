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
#include <dlfcn.h>
#include "print_log.h"
#include "print_constant.h"
#include "parameter.h"
#include "smb_library.h"
namespace OHOS::Print {
static constexpr int32_t INVALID_EVENT = -1;
const char* LIB_SMB2_SO_PATH = "print.libsmb2.so.path";
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
    std::lock_guard<std::mutex> lock(mutex_);
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
        PRINT_HILOGE("Failed to load SMB library: %s", dlerror());
        return false;
    }
    dlerror();
    smb2_init_context_ = reinterpret_cast<smb2_init_context_t>(dlsym(smbLibHandle_, "smb2_init_context"));
    smb2_close_context_ = reinterpret_cast<smb2_close_context_t>(dlsym(smbLibHandle_, "smb2_close_context"));
    smb2_destroy_context_ = reinterpret_cast<smb2_destroy_context_t>(dlsym(smbLibHandle_, "smb2_destroy_context"));
    smb2_connect_share_ = reinterpret_cast<smb2_connect_share_t>(dlsym(smbLibHandle_, "smb2_connect_share"));
    smb2_disconnect_share_ = reinterpret_cast<smb2_disconnect_share_t>(dlsym(smbLibHandle_, "smb2_disconnect_share"));
    smb2_set_user_ = reinterpret_cast<smb2_set_user_t>(dlsym(smbLibHandle_, "smb2_set_user"));
    smb2_set_password_ = reinterpret_cast<smb2_set_password_t>(dlsym(smbLibHandle_, "smb2_set_password"));
    smb2_set_domain_ = reinterpret_cast<smb2_set_domain_t>(dlsym(smbLibHandle_, "smb2_set_domain"));
    smb2_get_error_ = reinterpret_cast<smb2_get_error_t>(dlsym(smbLibHandle_, "smb2_get_error"));
    smb2_set_security_mode_ = reinterpret_cast<smb2_set_security_mode_t>(dlsym(smbLibHandle_,
        "smb2_set_security_mode"));
    smb2_set_timeout_ = reinterpret_cast<smb2_set_timeout_t>(dlsym(smbLibHandle_, "smb2_set_timeout"));
    smb2_share_enum_async_ = reinterpret_cast<smb2_share_enum_async_t>(dlsym(smbLibHandle_, "smb2_share_enum_async"));
    smb2_free_data_ = reinterpret_cast<smb2_free_data_t>(dlsym(smbLibHandle_, "smb2_free_data"));
    smb2_get_fd_ = reinterpret_cast<smb2_get_fd_t>(dlsym(smbLibHandle_, "smb2_get_fd"));
    smb2_which_events_ = reinterpret_cast<smb2_which_events_t>(dlsym(smbLibHandle_, "smb2_which_events"));
    smb2_service_ = reinterpret_cast<smb2_service_t>(dlsym(smbLibHandle_, "smb2_service"));
    if (!smb2_init_context_ || !smb2_close_context_ || !smb2_destroy_context_ ||
        !smb2_connect_share_ || !smb2_disconnect_share_ || !smb2_set_user_ ||
        !smb2_set_password_ || !smb2_set_domain_ || !smb2_get_error_ || !smb2_set_security_mode_ ||
        !smb2_set_timeout_ || !smb2_share_enum_async_ || !smb2_free_data_ ||
        !smb2_get_fd_ || !smb2_which_events_ || !smb2_service_) {
        PRINT_HILOGE("Failed to load required SMB functions");
        CleanupLibrary();
        return false;
    }
    PRINT_HILOGI("SMB library initialized successfully");
    return true;
}

void SmbLibrary::CleanupLibrary()
{
    std::lock_guard<std::mutex> lock(mutex_);
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
    smb2_init_context_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_init_context_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_init_context_ is null");
        return nullptr;
    }
    return fn();
}

void SmbLibrary::CloseContext(struct smb2_context* ctx) const
{
    smb2_close_context_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_close_context_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_close_context_ is null");
        return;
    }
    fn(ctx);
}

void SmbLibrary::DestroyContext(struct smb2_context* ctx) const
{
    smb2_destroy_context_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_destroy_context_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_destroy_context_ is null");
        return;
    }
    fn(ctx);
}

const char* SmbLibrary::GetSmbError(struct smb2_context* ctx) const
{
    smb2_get_error_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_get_error_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_get_error_ is null");
        return "SMB library not initialized";
    }
    return fn(ctx);
}

int32_t SmbLibrary::ConnectShare(struct smb2_context* ctx, const char* server,
    const char* share, const char* user) const
{
    smb2_connect_share_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_connect_share_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_connect_share_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return fn(ctx, server, share, user);
}

int32_t SmbLibrary::DisconnectShare(struct smb2_context* ctx) const
{
    smb2_disconnect_share_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_disconnect_share_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_disconnect_share_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return fn(ctx);
}

int32_t SmbLibrary::ShareEnumAsync(struct smb2_context* ctx, int32_t level,
    void (*callback)(struct smb2_context*, int32_t, void*, void*), void* privateData) const
{
    smb2_share_enum_async_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_share_enum_async_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_share_enum_async_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return fn(ctx, level, callback, privateData);
}

void SmbLibrary::FreeData(struct smb2_context* ctx, void* data) const
{
    smb2_free_data_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_free_data_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_free_data_ is null");
        return;
    }
    fn(ctx, data);
}

int32_t SmbLibrary::GetFd(struct smb2_context* ctx) const
{
    smb2_get_fd_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_get_fd_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_get_fd_ is null");
        return INVALID_FD;
    }
    return fn(ctx);
}

int32_t SmbLibrary::WhichEvents(struct smb2_context* ctx) const
{
    smb2_which_events_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_which_events_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_which_events_ is null");
        return INVALID_EVENT;
    }
    return fn(ctx);
}

int32_t SmbLibrary::Service(struct smb2_context* ctx, int32_t revents) const
{
    smb2_service_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_service_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_service_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    return fn(ctx, revents);
}

void SmbLibrary::SetUser(struct smb2_context* ctx, const char* user) const
{
    smb2_set_user_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_set_user_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_set_user_ is null");
        return;
    }
    fn(ctx, user);
}

void SmbLibrary::SetPassword(struct smb2_context* ctx, const char* password) const
{
    smb2_set_password_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_set_password_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_set_password_ is null");
        return;
    }
    fn(ctx, password);
}

void SmbLibrary::SetSecurityMode(struct smb2_context* ctx, uint16_t mode) const
{
    smb2_set_security_mode_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_set_security_mode_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_set_security_mode_ is null");
        return;
    }
    fn(ctx, mode);
}

void SmbLibrary::SetTimeout(struct smb2_context* ctx, int32_t timeout) const
{
    smb2_set_timeout_t fn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fn = smb2_set_timeout_;
    }
    if (!fn) {
        PRINT_HILOGE("smb2_set_timeout_ is null");
        return;
    }
    fn(ctx, timeout);
}
}  // namespace OHOS::Print
