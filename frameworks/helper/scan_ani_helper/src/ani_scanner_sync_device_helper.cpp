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

#include <ani.h>
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_scanner_sync_device_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_SCANNER_ID = "scannerId";
const char* PARAM_DISCOVERY_MODE = "discoveryMode";
const char* PARAM_UNIQUE_ID = "uniqueId";
const char* PARAM_SYNC_MODE = "syncMode";
const char* PARAM_OLD_SCANNER_ID = "oldScannerId";
const char *CLASSNAME = "@ohos.scan.scan.ScannerSyncDevice";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScannerSyncDeviceHelper::CreateScannerSyncDevice(ani_env *env, const ScanDeviceInfoSync &device)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_object obj = CreateObject(env, nullptr, CLASSNAME);
    if (obj == nullptr) {
        SCAN_HILOGE("null obj");
        return nullptr;
    }
    SetStringProperty(env, obj, PARAM_SCANNER_ID, device.GetDeviceId());
    SetStringProperty(env, obj, PARAM_DISCOVERY_MODE, device.GetDiscoverMode());
    SetStringProperty(env, obj, PARAM_UNIQUE_ID, device.GetUniqueId());
    SetStringProperty(env, obj, PARAM_SYNC_MODE, device.GetSyncMode());
    if (!device.GetOldDeviceId().empty()) {
        SetStringProperty(env, obj, PARAM_OLD_SCANNER_ID, device.GetOldDeviceId());
    }
    return obj;
}

ani_object AniScannerSyncDeviceHelper::CreateScannerSyncDeviceArray(ani_env *env,
    const std::vector<ScanDeviceInfoSync> &devices)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass("std.core.Array", &arrayCls);
    if (status != ANI_OK) {
        SCAN_HILOGE("FindClass failed");
        return nullptr;
    }
    ani_method arrayCtor = nullptr;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        SCAN_HILOGE("Class_FindMethod failed");
        return nullptr;
    }
    ani_size length = devices.size();
    ani_object arrayObj = nullptr;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
    if (status != ANI_OK) {
        SCAN_HILOGE("Object_New failed");
        return nullptr;
    }

    for (size_t i = 0; i < devices.size(); i++) {
        ani_object deviceObj = CreateScannerSyncDevice(env, devices[i]);
        if (deviceObj == nullptr) {
            SCAN_HILOGW("null deviceObj");
            continue;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", i, deviceObj)) {
            SCAN_HILOGE("Set Array item failed");
            return nullptr;
        }
    }
    return arrayObj;
}
}  // namespace OHOS::Scan
