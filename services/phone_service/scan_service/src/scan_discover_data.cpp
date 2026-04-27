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

#include "scan_discover_data.h"

namespace OHOS::Scan {

ScannerDiscoverData& ScannerDiscoverData::GetInstance()
{
    static ScannerDiscoverData instance;
    return instance;
}

void ScannerDiscoverData::SetUsbDevice(const std::string& uniqueId, const ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    usbDeviceInfoMap_[uniqueId] = info;
}

void ScannerDiscoverData::SetTcpDevice(const std::string& uniqueId, const ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    tcpDeviceInfoMap_[uniqueId] = info;
}

void ScannerDiscoverData::SetEsclDevice(const std::string& uniqueId, const ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    esclDeviceInfoMap_[uniqueId] = info;
}

bool ScannerDiscoverData::GetUsbDevice(const std::string& uniqueId, ScanDeviceInfo& info) const
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    auto it = usbDeviceInfoMap_.find(uniqueId);
    if (it != usbDeviceInfoMap_.end()) {
        info = it->second;
        return true;
    }
    return false;
}

bool ScannerDiscoverData::GetTcpDevice(const std::string& uniqueId, ScanDeviceInfo& info) const
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    auto it = tcpDeviceInfoMap_.find(uniqueId);
    if (it != tcpDeviceInfoMap_.end()) {
        info = it->second;
        return true;
    }
    return false;
}

bool ScannerDiscoverData::GetEsclDevice(const std::string& uniqueId, ScanDeviceInfo& info) const
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    auto it = esclDeviceInfoMap_.find(uniqueId);
    if (it != esclDeviceInfoMap_.end()) {
        info = it->second;
        return true;
    }
    return false;
}

bool ScannerDiscoverData::RemoveUsbDevice(const std::string& uniqueId)
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    return usbDeviceInfoMap_.erase(uniqueId) > 0;
}

bool ScannerDiscoverData::RemoveTcpDevice(const std::string& uniqueId)
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    return tcpDeviceInfoMap_.erase(uniqueId) > 0;
}

bool ScannerDiscoverData::RemoveEsclDevice(const std::string& uniqueId)
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    return esclDeviceInfoMap_.erase(uniqueId) > 0;
}

std::map<std::string, ScanDeviceInfo> ScannerDiscoverData::GetAllUsbDevices() const
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    return usbDeviceInfoMap_;
}

std::map<std::string, ScanDeviceInfo> ScannerDiscoverData::GetAllTcpDevices() const
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    return tcpDeviceInfoMap_;
}

std::map<std::string, ScanDeviceInfo> ScannerDiscoverData::GetAllEsclDevices() const
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    return esclDeviceInfoMap_;
}

void ScannerDiscoverData::ClearUsbDevices()
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    usbDeviceInfoMap_.clear();
}

void ScannerDiscoverData::ClearTcpDevices()
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    tcpDeviceInfoMap_.clear();
}

void ScannerDiscoverData::ClearEsclDevices()
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    esclDeviceInfoMap_.clear();
}

bool ScannerDiscoverData::HasUsbDevice(const std::string& uniqueId) const
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    return usbDeviceInfoMap_.find(uniqueId) != usbDeviceInfoMap_.end();
}

bool ScannerDiscoverData::HasTcpDevice(const std::string& uniqueId) const
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    return tcpDeviceInfoMap_.find(uniqueId) != tcpDeviceInfoMap_.end();
}

bool ScannerDiscoverData::HasEsclDevice(const std::string& uniqueId) const
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    return esclDeviceInfoMap_.find(uniqueId) != esclDeviceInfoMap_.end();
}

} // namespace OHOS::Scan
