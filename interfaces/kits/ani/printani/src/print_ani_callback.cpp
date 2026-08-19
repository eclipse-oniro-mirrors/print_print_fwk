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

#include "print_ani_callback.h"
#include "print_job_helper.h"
#include "print_attributes_helper.h"
#include "print_log.h"
#include "print_base_ani_util.h"
#include "ani_printer_info_helper.h"
#include "print_callback_ani_util.h"

namespace OHOS::Print {
PrintAniCallback::PrintAniCallback(ani_env *env, ani_object aniCallback)
{
    if (env == nullptr || aniCallback == nullptr) {
        PRINT_HILOGE("nullptr error");
        return;
    }
    ani_vm *vm = nullptr;
    PRINT_CALL_RETURN_VOID(env, env->GetVM(&vm));
    aniVm_ = vm;
    PRINT_CALL_RETURN_VOID(env, env->GlobalReference_Create(reinterpret_cast<ani_ref>(aniCallback), &aniCallback_));
}

PrintAniCallback::~PrintAniCallback()
{
    if (aniCallback_ != nullptr && aniVm_ != nullptr) {
        ani_env *env = nullptr;
        bool isAttached = false;
        if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
            ani_options aniArgs { 0, nullptr };
            if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) == ANI_OK) {
                isAttached = true;
            } else {
                PRINT_HILOGE("Failed to attach thread, global reference leaked.");
                aniVm_ = nullptr;
                aniCallback_ = nullptr;
                return;
            }
        }
        ani_status delStatus = env->GlobalReference_Delete(aniCallback_);
        if (delStatus != ANI_OK) {
            PRINT_HILOGW("GlobalReference_Delete failed, status: %{public}d", delStatus);
        }
        if (isAttached) {
            aniVm_->DetachCurrentThread();
        }
    }
    aniVm_ = nullptr;
    aniCallback_ = nullptr;
}

bool PrintAniCallback::OnCallback()
{
    PRINT_HILOGI("PrintTask Notification in");
    return true;
}

bool PrintAniCallback::OnCallback(uint32_t state, const PrinterInfo &info)
{
    PRINT_HILOGI("Printer Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallback(uint32_t state, const PrintJob &info)
{
    PRINT_HILOGI("PrintJob Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallback(const std::string &extensionId, const std::string &info)
{
    PRINT_HILOGI("ExtensionInfo Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds)
{
    PRINT_HILOGI("QueryPrinterInfo Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallbackAdapterLayout(const std::string &jobId,
    const PrintAttributes &oldAttrs, const PrintAttributes &newAttrs, uint32_t fd)
{
    PRINT_HILOGI("PrintCallback OnCallbackAdapterLayout Notification in, jobId:%{public}s newAttrs copyNum:%{public}d",
                 jobId.c_str(),
                 newAttrs.GetCopyNumber());
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
                                                        const uint32_t subState)
{
    PRINT_HILOGI("PrintCallback onCallbackAdapterJobStateChanged Notification in, jobId:%{public}s subState:%{public}d",
                 jobId.c_str(), subState);
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("OnCallbackAdapterGetFile in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

bool PrintAniCallback::OnCallback(const std::vector<PrintSharedHost> &sharedHosts)
{
    PRINT_HILOGI("SharedHostDiscover Notification in, host count: %{public}zu", sharedHosts.size());
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return false;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_BASE(env, aniVm_->DetachCurrentThread(), false);
    }
    return true;
}

WatermarkAniCallback::WatermarkAniCallback(ani_env *env, ani_object aniCallback)
{
    if (env == nullptr || aniCallback == nullptr) {
        PRINT_HILOGE("nullptr error");
        return;
    }
    ani_vm *vm = nullptr;
    PRINT_CALL_RETURN_VOID(env, env->GetVM(&vm));
    aniVm_ = vm;
    PRINT_CALL_RETURN_VOID(env, env->GlobalReference_Create(reinterpret_cast<ani_ref>(aniCallback), &aniCallback_));
}

WatermarkAniCallback::~WatermarkAniCallback()
{
    if (aniCallback_ != nullptr && aniVm_ != nullptr) {
        ani_env *env = nullptr;
        bool isAttached = false;
        if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
            ani_options aniArgs { 0, nullptr };
            if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) == ANI_OK) {
                isAttached = true;
            } else {
                PRINT_HILOGE("Failed to attach thread, global reference leaked.");
                aniVm_ = nullptr;
                aniCallback_ = nullptr;
                return;
            }
        }
        ani_status delStatus = env->GlobalReference_Delete(aniCallback_);
        if (delStatus != ANI_OK) {
            PRINT_HILOGW("GlobalReference_Delete failed, status: %{public}d", delStatus);
        }
        if (isAttached) {
            aniVm_->DetachCurrentThread();
        }
    }
    aniVm_ = nullptr;
    aniCallback_ = nullptr;
}

void WatermarkAniCallback::OnCallback(const std::string &jobId, uint32_t fd)
{
    PRINT_HILOGI("WatermarkAniCallback OnCallback in, jobId:%{public}s, fd:%{public}u", jobId.c_str(), fd);
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return;
    }
    ani_env *env = nullptr;
    bool isAttached = false;
    if (aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        ani_options aniArgs { 0, nullptr };
        if (aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
            PRINT_HILOGE("AttachCurrentThread failed");
            return;
        }
        isAttached = true;
    }
    if (isAttached) {
        PRINT_CALL_RETURN_VOID(env, aniVm_->DetachCurrentThread());
    }
}

}  // namespace OHOS::Print
