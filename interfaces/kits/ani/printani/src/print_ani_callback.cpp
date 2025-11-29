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
    env->GetVM(&vm);
    aniVm_ = vm;
    env->GlobalReference_Create(reinterpret_cast<ani_ref>(aniCallback), &aniCallback_);
}

PrintAniCallback::~PrintAniCallback()
{
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
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

bool PrintAniCallback::OnCallback(uint32_t state, const PrintJob &info)
{
    PRINT_HILOGI("PrintJob Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

bool PrintAniCallback::OnCallback(const std::string &extensionId, const std::string &info)
{
    PRINT_HILOGI("ExtensionInfo Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

bool PrintAniCallback::OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds)
{
    PRINT_HILOGI("QueryPrinterInfo Notification in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

bool PrintAniCallback::OnCallbackJobStateChanged(const std::string jobId, const uint32_t state)
{
    PRINT_HILOGI("[Job Id: %{public}s] PrintCallback OnCallbackJobStateChanged Notification in, state: %{public}d",
                 jobId.c_str(), state);
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
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
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
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
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

bool PrintAniCallback::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("OnCallbackAdapterGetFile in");
    if (aniVm_ == nullptr || aniCallback_ == nullptr) {
        PRINT_HILOGE("aniVm_ or aniCallback_ is nullptr");
        return false;
    }
    ani_env *env;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            PRINT_HILOGI("vm GetEnv, err: %{private}d", status);
            return false;
        }
    }
    aniVm_->DetachCurrentThread();
    return true;
}

}  // namespace OHOS::Print
