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
    : env_(env), callback_(callback)
{
}

bool ScanAniCallback::OnCallback(uint32_t state, const ScanDeviceInfo &info)
{
    SCAN_HILOGI("OnScanDeviceFound");
    if (env_ == nullptr) {
        SCAN_HILOGE("env_ is nullptr");
        return false;
    }
    if (callback_ == nullptr) {
        SCAN_HILOGE("callback_ is nullptr");
        return false;
    }
    ani_object deviceObj = AniScannerDeviceHelper::CreateScannerDevice(env_, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    if (!Callback(env_, callback_, deviceObj)) {
        SCAN_HILOGE("Callback failed");
        return false;
    }
    return true;
}

bool ScanAniCallback::OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info)
{
    SCAN_HILOGI("OnScanDeviceSync");
    if (env_ == nullptr) {
        SCAN_HILOGE("env_ is nullptr");
        return false;
    }
    if (callback_ == nullptr) {
        SCAN_HILOGE("callback_ is nullptr");
        return false;
    }
    ani_object deviceObj = AniScannerSyncDeviceHelper::CreateScannerSyncDevice(env_, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    if (!Callback(env_, callback_, deviceObj)) {
        SCAN_HILOGE("Callback failed");
        return false;
    }
    return true;
}

bool ScanAniCallback::OnGetDevicesList(std::vector<ScanDeviceInfo> &info)
{
    SCAN_HILOGI("OnGetDevicesList");
    if (env_ == nullptr) {
        SCAN_HILOGE("env_ is nullptr");
        return false;
    }
    if (callback_ == nullptr) {
        SCAN_HILOGE("callback_ is nullptr");
        return false;
    }
    ani_object deviceObj = AniScannerDeviceHelper::CreateScannerDeviceArray(env_, info);
    if (deviceObj == nullptr) {
        SCAN_HILOGE("deviceObj is nullptr");
        return false;
    }
    if (!Callback(env_, callback_, deviceObj)) {
        SCAN_HILOGE("Callback failed");
        return false;
    }
    return true;
}
}
