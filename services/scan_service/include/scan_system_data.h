/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SCAN_SYSTEM_DATA_H
#define SCAN_SYSTEM_DATA_H

#include <string>
#include <map>
#include <json/json.h>
#include "scanner_info.h"
#include "print_json_util.h"

namespace OHOS {
namespace Scan {

class ScanSystemData {
public:
    static ScanSystemData& GetInstance()
    {
        static ScanSystemData instance;
        return instance;
    }
    bool Init();
    void InsertScannerInfo(const std::string &uniqueId, const ScanDeviceInfo &scannerInfo);
    bool DeleteScannerInfo(const std::string &uniqueId);
    bool UpdateScannerNameByUniqueId(const std::string &uniqueId, const std::string &deviceName);
    bool UpdateScannerInfoByUniqueId(const std::string &uniqueId, const ScanDeviceInfo &scannerInfo);
    bool UpdateScannerIdByUsbDevicePort(const std::string &uniqueId, const std::string &usbDevicePort);
    bool QueryScannerNameByUniqueId(const std::string &uniqueId, std::string &deviceName);
    bool QueryScannerInfoByUniqueId(const std::string &uniqueId, ScanDeviceInfo &scannerInfo);
    void RefreshUsbDeviceId();
    void GetAddedScannerInfoList(std::vector<ScanDeviceInfo> &infoList);
    bool SaveScannerMap();
    bool IsContainScanner(const std::string &uniqueId);
    std::pair<std::string, std::string> UpdateNetScannerByUuid(const std::string &uuid, const std::string& ip);
    static std::string ReplaceDeviceIdUsbPort(const std::string& deviceId, const std::string& usbPort);
private:
    bool ParseScannerListJsonV1(Json::Value& jsonObject);
    bool CheckJsonObjectValue(const Json::Value& object);
    void ParseScannerJsonV1(ScanDeviceInfo &scanDeviceInfo, Json::Value &object);
    std::map<std::string, std::shared_ptr<ScanDeviceInfo>> addedScannerMap_;
    std::map<std::string, std::string> usbSnToPortMap_;
    std::mutex addedScannerMapLock_;
    const uint32_t MAX_SCANNER_SIZE = 1000;
};

}  // namespace Scan
}  // namespace OHOS
#endif  // SCAN_SYSTEM_DATA_H
