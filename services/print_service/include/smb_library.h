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
#ifndef SMB_LIBRARY_H
#define SMB_LIBRARY_H

#include <memory>
#include <mutex>
#include <string>
#include "print_log.h"
#include "singleton.h"

namespace OHOS::Print {
struct smb2_context;
class SmbLibrary : public DelayedSingleton<SmbLibrary> {
public:
    SmbLibrary();
    ~SmbLibrary();
    struct smb2_context* CreateContext() const;
    void DestroyContext(struct smb2_context* ctx) const;
    const char* GetSmbError(struct smb2_context* ctx) const;
    int32_t ConnectShare(struct smb2_context* ctx, const char* server,
        const char* share, const char* user) const;
    int32_t DisconnectShare(struct smb2_context* ctx) const;
    int32_t ShareEnumAsync(struct smb2_context* ctx, int level,
        void (*callback)(struct smb2_context*, int, void*, void*), void* privateData) const;
    void FreeData(struct smb2_context* ctx, void* data) const;
    int32_t GetFd(struct smb2_context* ctx) const;
    int32_t WhichEvents(struct smb2_context* ctx) const;
    int32_t Service(struct smb2_context* ctx, int revents) const;
    void SetUser(struct smb2_context* ctx, const char* user) const;
    void SetPassword(struct smb2_context* ctx, const char* password) const;
    void SetSecurityMode(struct smb2_context* ctx, uint16_t mode) const;
    void SetTimeout(struct smb2_context* ctx, int timeout) const;
    
private:
    bool InitializeLibrary();
    void CleanupLibrary();
    void* smbLibHandle_;
    using smb2_init_context_t = struct smb2_context* (*)();
    using smb2_destroy_context_t = void (*)(struct smb2_context*);
    using smb2_connect_share_t = int (*)(struct smb2_context*, const char*, const char*, const char*);
    using smb2_disconnect_share_t = int (*)(struct smb2_context*);
    using smb2_set_user_t = void (*)(struct smb2_context*, const char*);
    using smb2_set_password_t = void (*)(struct smb2_context*, const char*);
    using smb2_set_domain_t = void (*)(struct smb2_context*, const char*);
    using smb2_get_error_t = const char* (*)(struct smb2_context*);
    using smb2_set_security_mode_t = void (*)(struct smb2_context*, uint16_t);
    using smb2_set_timeout_t = void (*)(struct smb2_context*, int);
    using smb2_share_enum_async_t = int (*)(struct smb2_context*, int,
        void (*)(struct smb2_context*, int, void*, void*), void*);
    using smb2_free_data_t = void (*)(struct smb2_context*, void*);
    using smb2_get_fd_t = int (*)(struct smb2_context*);
    using smb2_which_events_t = int (*)(struct smb2_context*);
    using smb2_service_t = int (*)(struct smb2_context*, int);

    smb2_init_context_t smb2_init_context_;
    smb2_destroy_context_t smb2_destroy_context_;
    smb2_connect_share_t smb2_connect_share_;
    smb2_disconnect_share_t smb2_disconnect_share_;
    smb2_set_user_t smb2_set_user_;
    smb2_set_password_t smb2_set_password_;
    smb2_set_domain_t smb2_set_domain_;
    smb2_get_error_t smb2_get_error_;
    smb2_set_security_mode_t smb2_set_security_mode_;
    smb2_set_timeout_t smb2_set_timeout_;
    smb2_share_enum_async_t smb2_share_enum_async_;
    smb2_free_data_t smb2_free_data_;
    smb2_get_fd_t smb2_get_fd_;
    smb2_which_events_t smb2_which_events_;
    smb2_service_t smb2_service_;
};

// import from libsmb2-dcerpc.h
struct dcerpc_utf16 {
    uint32_t max_count;
    uint32_t offset;
    uint32_t actual_count;
    struct smb2_utf16 *utf16;
    const char *utf8;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_0 {
    struct dcerpc_utf16 netname;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_0_carray {
    uint32_t max_count;
    struct srvsvc_SHARE_INFO_0 *share_info_0;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_0_CONTAINER {
    uint32_t EntriesRead;
    struct srvsvc_SHARE_INFO_0_carray *Buffer;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_1 {
    struct dcerpc_utf16 netname;
    uint32_t type;
    struct dcerpc_utf16 remark;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_1_carray {
    uint32_t max_count;
    struct srvsvc_SHARE_INFO_1 *share_info_1;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_INFO_1_CONTAINER {
    uint32_t EntriesRead;
    struct srvsvc_SHARE_INFO_1_carray *Buffer;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_ENUM_UNION {
    uint32_t Level;
    union {
        struct srvsvc_SHARE_INFO_0_CONTAINER Level0;
        struct srvsvc_SHARE_INFO_1_CONTAINER Level1;
    };
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_SHARE_ENUM_STRUCT {
    uint32_t Level;
    struct srvsvc_SHARE_ENUM_UNION ShareInfo;
};

// import from libsmb2-dcerpc-srvsvc.h
struct srvsvc_NetrShareEnum_rep {
    uint32_t status;
    struct srvsvc_SHARE_ENUM_STRUCT ses;
    uint32_t total_entries;
    uint32_t resume_handle;
};
} // namespace OHOS::Print
#endif  // SMB_LIBRARY_H
