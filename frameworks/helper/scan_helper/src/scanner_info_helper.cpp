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
static constexpr const char *PARAM_TCP_DEVICENAME = "deviceName";
static constexpr const char *PARAM_TCP_UUID = "uuid";
static constexpr const char *PARAM_TCP_MODEL = "model";
static constexpr const char *PARAM_TCP_MANUFACTURER = "manufacturer";
static constexpr const char *PARAM_TCP_DEVICETYPE = "deviceType";
static constexpr const char *PARAM_TCP_PORT = "port";
static constexpr const char *PARAM_TCP_ADDR = "address";
static constexpr const char *PARAM_TCP_BUTTON = "button";
static constexpr const char *PARAM_TCP_FEEDER = "feeder";


static constexpr const char *PARAM_SCANNERID = "deviceId";
static constexpr const char *PARAM_MANUFACTURER = "manufacturer";
static constexpr const char *PARAM_MODEL = "model";
static constexpr const char *PARAM_DEVICETYPE = "deviceType";

static constexpr const char *PARAM_INFO_DEVICESTATE = "deviceState";
static constexpr const char *PARAM_INFO_DISCOVERMODE = "discoverMode";
static constexpr const char *PARAM_INFO_SERIALNUMBER = "serialNumber";
static constexpr const char *PARAM_INFO_DEVICENAME = "deviceName";
static constexpr const char *PARAM_INFO_SYNCMODE = "syncMode";
static constexpr const char *PARAM_UNIQUE_ID = "uniqueId";

napi_value ScannerInfoHelperTCP::MakeJsObject(napi_env env, const ScanDeviceInfoTCP &info)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_DEVICENAME, info.GetDeviceName());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_UUID, info.GetUuid());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_MODEL, info.GetModel());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_MANUFACTURER, info.GetManufacturer());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_DEVICETYPE, info.GetDeviceType());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_PORT, info.GetPort());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_ADDR, info.GetAddr());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_BUTTON, info.GetButton());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_TCP_FEEDER, info.GetFeeder());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_INFO_DEVICESTATE, info.GetDeviceState());
    return jsObj;
}


napi_value ScannerInfoHelper::MakeJsObject(napi_env env, const ScanDeviceInfo &info)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SCANNERID, info.GetDeviceId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_MANUFACTURER, info.GetManufacturer());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_MODEL, info.GetModel());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_DEVICETYPE, info.GetDeviceType());
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_INFO_DEVICESTATE, info.GetDeviceState());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DISCOVERMODE, info.GetDiscoverMode());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_SERIALNUMBER, info.GetSerialNumber());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DEVICENAME, info.GetDeviceName());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_UNIQUE_ID, info.GetUniqueId());
    return jsObj;
}

napi_value ScannerInfoSyncHelper::MakeJsObject(napi_env env, const ScanDeviceInfoSync &info)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_SCANNERID, info.GetDeviceId());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_DISCOVERMODE, info.GetDiscoverMode());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_SERIALNUMBER, info.GetSerialNumber());
    NapiScanUtils::SetStringPropertyUtf8(env, jsObj, PARAM_INFO_SYNCMODE, info.GetSyncMode());
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("ScannerInfoSyncHelper MakeJsObject DeviceId = %{public}s, DiscoverMode = %{public}s,"
                "SerialNumber = %{public}s SyncMode = %{public}s.",
                info.GetDeviceId().c_str(), info.GetDiscoverMode().c_str(),
                info.GetSerialNumber().c_str(), info.GetSyncMode().c_str());
#endif
    return jsObj;
}


}  // namespace OHOS::Print
