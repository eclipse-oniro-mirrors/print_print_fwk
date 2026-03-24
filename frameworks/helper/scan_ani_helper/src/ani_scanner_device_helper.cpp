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
#include "ani_scanner_device_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_SCANNER_ID = "scannerId";
const char* PARAM_DISCOVERY_MODE = "discoveryMode";
const char* PARAM_UNIQUE_ID = "uniqueId";
const char* PARAM_MANUFACTURER = "manufacturer";
const char* PARAM_MODEL = "model";
const char* PARAM_DEVICE_NAME = "deviceName";
const char *CLASSNAME = "@ohos.scan.scan.ScannerDevice";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScannerDeviceHelper::CreateScannerDevice(ani_env *env, const ScanDeviceInfo &device)
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
    SetStringProperty(env, obj, PARAM_MANUFACTURER, device.GetManufacturer());
    SetStringProperty(env, obj, PARAM_MODEL, device.GetModel());
    SetStringProperty(env, obj, PARAM_DEVICE_NAME, device.GetDeviceName());
    return obj;
}

ani_object AniScannerDeviceHelper::CreateScannerDeviceArray(ani_env *env, const std::vector<ScanDeviceInfo> &devices)
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
        ani_object deviceObj = CreateScannerDevice(env, devices[i]);
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
