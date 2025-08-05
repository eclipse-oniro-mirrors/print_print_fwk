/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "scanner_info_helper.h"
#include "napi_scan_utils.h"
#include "scan_log.h"

namespace OHOS::Scan {

static constexpr const char *PARAM_SCANNERID = "scannerId";
static constexpr const char *PARAM_INFO_DISCOVERMODE = "discoveryMode";
static constexpr const char *PARAM_UNIQUE_ID = "uniqueId";
static constexpr const char *PARAM_MANUFACTURER = "manufacturer";
static constexpr const char *PARAM_MODEL = "model";
static constexpr const char *PARAM_INFO_DEVICENAME = "deviceName";

static constexpr const char *PARAM_OLD_SCANNERID = "oldScannerId";
static constexpr const char *PARAM_INFO_SYNCMODE = "syncMode";

napi_value ScannerInfoHelper::MakeJsObject(napi_env env, const ScanDeviceInfo &info)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SCANNERID, info.GetDeviceId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DISCOVERMODE, info.GetDiscoverMode());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_UNIQUE_ID, info.GetUniqueId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_MANUFACTURER, info.GetManufacturer());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_MODEL, info.GetModel());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DEVICENAME, info.GetDeviceName());
    return jsObj;
}

napi_value ScannerInfoSyncHelper::MakeJsObject(napi_env env, const ScanDeviceInfoSync &info)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SCANNERID, info.GetDeviceId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DISCOVERMODE, info.GetDiscoverMode());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_UNIQUE_ID, info.GetUniqueId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_SYNCMODE, info.GetSyncMode());
    if (info.GetSyncMode() == "update") {
        NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_OLD_SCANNERID, info.GetOldDeviceId());
    }
    return jsObj;
}
}  // namespace OHOS::Print
