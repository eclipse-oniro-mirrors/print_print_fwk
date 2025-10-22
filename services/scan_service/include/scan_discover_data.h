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

#ifndef SCAN_DISCOVER_DATA
#define SCAN_DISCOVER_DATA

#include <string>
#include <map>
#include <mutex>
#include "scanner_info.h"

namespace OHOS::Scan {
class ScannerDiscoverData {
public:
    static ScannerDiscoverData& GetInstance();
    
    void SetUsbDevice(const std::string& uniqueId, const ScanDeviceInfo& info);
    void SetTcpDevice(const std::string& uniqueId, const ScanDeviceInfo& info);
    void SetEsclDevice(const std::string& uniqueId, const ScanDeviceInfo& info);
    
    bool GetUsbDevice(const std::string& uniqueId, ScanDeviceInfo& info) const;
    bool GetTcpDevice(const std::string& uniqueId, ScanDeviceInfo& info) const;
    bool GetEsclDevice(const std::string& uniqueId, ScanDeviceInfo& info) const;
    
    bool RemoveUsbDevice(const std::string& uniqueId);
    bool RemoveTcpDevice(const std::string& uniqueId);
    bool RemoveEsclDevice(const std::string& uniqueId);
    
    std::map<std::string, ScanDeviceInfo> GetAllUsbDevices() const;
    std::map<std::string, ScanDeviceInfo> GetAllTcpDevices() const;
    std::map<std::string, ScanDeviceInfo> GetAllEsclDevices() const;
    
    void ClearUsbDevices();
    void ClearTcpDevices();
    void ClearEsclDevices();
    
    bool HasUsbDevice(const std::string& uniqueId) const;
    bool HasTcpDevice(const std::string& uniqueId) const;
    bool HasEsclDevice(const std::string& uniqueId) const;

private:
    ScannerDiscoverData() = default;
    ~ScannerDiscoverData() = default;
    
    mutable std::mutex usbMutex_;
    mutable std::mutex tcpMutex_;
    mutable std::mutex esclMutex_;
    std::map<std::string, ScanDeviceInfo> usbDeviceInfoMap_;
    std::map<std::string, ScanDeviceInfo> tcpDeviceInfoMap_;
    std::map<std::string, ScanDeviceInfo> esclDeviceInfoMap_;
};

} // namespace OHOS::Scan
#endif // SCAN_SYSTEM_ABILITY_H