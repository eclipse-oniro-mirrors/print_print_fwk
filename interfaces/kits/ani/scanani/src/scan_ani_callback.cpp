/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "scan_ani_callback.h"
#include "scan_log.h"
#include "ani_scanner_device_helper.h"
#include "ani_scanner_sync_device_helper.h"
#include "print_callback_ani_util.h"

namespace OHOS::Scan {
using namespace OHOS::Print;
ScanAniCallback::ScanAniCallback(ani_env *env, ani_object callback)
{
    if (env == nullptr || callback == nullptr) {
        SCAN_HILOGE("nullptr error");
        return;
    }
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    aniVm_ = vm;
    env->GlobalReference_Create(reinterpret_cast<ani_ref>(callback), &callback_);
}

ScanAniCallback::~ScanAniCallback()
{
    if (callback_ != nullptr) {
        if (aniVm_ != nullptr) {
            ani_env *env = nullptr;
            ani_options aniArgs { 0, nullptr };
            auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
            if (status == ANI_OK && env != nullptr) {
                env->GlobalReference_Delete(callback_);
                aniVm_->DetachCurrentThread();
            }
        } else {
            SCAN_HILOGW("aniVm_ is nullptr, callback_ may not be released properly");
        }
    }
    aniVm_ = nullptr;
    callback_ = nullptr;
}

bool ScanAniCallback::OnCallback(uint32_t state, const ScanDeviceInfo &info)
{
    SCAN_HILOGI("OnScanDeviceFound");
    if (aniVm_ == nullptr || callback_ == nullptr) {
        SCAN_HILOGE("aniVm_ or callback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            SCAN_HILOGE("GetEnv failed");
            return false;
        }
    }
    ani_object deviceObj = AniScannerDeviceHelper::CreateScannerDevice(env, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    bool result = Callback(env, reinterpret_cast<ani_object>(callback_), deviceObj);
    aniVm_->DetachCurrentThread();
    return result;
}

bool ScanAniCallback::OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info)
{
    SCAN_HILOGI("OnScanDeviceSync");
    if (aniVm_ == nullptr || callback_ == nullptr) {
        SCAN_HILOGE("aniVm_ or callback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            SCAN_HILOGE("GetEnv failed");
            return false;
        }
    }
    ani_object deviceObj = AniScannerSyncDeviceHelper::CreateScannerSyncDevice(env, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    bool result = Callback(env, reinterpret_cast<ani_object>(callback_), deviceObj);
    aniVm_->DetachCurrentThread();
    return result;
}

bool ScanAniCallback::OnGetDevicesList(std::vector<ScanDeviceInfo> &info)
{
    SCAN_HILOGI("OnGetDevicesList");
    if (aniVm_ == nullptr || callback_ == nullptr) {
        SCAN_HILOGE("aniVm_ or callback_ is nullptr");
        return false;
    }
    ani_env *env = nullptr;
    ani_options aniArgs { 0, nullptr };
    auto status = aniVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = aniVm_->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            SCAN_HILOGE("GetEnv failed");
            return false;
        }
    }
    ani_object deviceObj = AniScannerDeviceHelper::CreateScannerDeviceArray(env, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    bool result = Callback(env, reinterpret_cast<ani_object>(callback_), deviceObj);
    aniVm_->DetachCurrentThread();
    return result;
}
}
