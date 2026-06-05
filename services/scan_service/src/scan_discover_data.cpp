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

bool ScannerDiscoverData::GetAndRemoveTcpDevice(const std::string& uniqueId, ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    auto it = tcpDeviceInfoMap_.find(uniqueId);
    if (it != tcpDeviceInfoMap_.end()) {
        info = it->second;
        tcpDeviceInfoMap_.erase(it);
        return true;
    }
    return false;
}

bool ScannerDiscoverData::GetAndRemoveEsclDevice(const std::string& uniqueId, ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    auto it = esclDeviceInfoMap_.find(uniqueId);
    if (it != esclDeviceInfoMap_.end()) {
        info = it->second;
        esclDeviceInfoMap_.erase(it);
        return true;
    }
    return false;
}

bool ScannerDiscoverData::UpdateUsbDevice(const std::string& uniqueId,
    std::function<void(ScanDeviceInfo&)> modifier)
{
    std::lock_guard<std::mutex> lock(usbMutex_);
    auto it = usbDeviceInfoMap_.find(uniqueId);
    if (it == usbDeviceInfoMap_.end()) {
        return false;
    }
    modifier(it->second);
    return true;
}

bool ScannerDiscoverData::UpdateTcpDevice(const std::string& srcKey, const std::string& dstKey,
    std::function<void(ScanDeviceInfo&)> modifier)
{
    std::lock_guard<std::mutex> lock(tcpMutex_);
    auto it = tcpDeviceInfoMap_.find(srcKey);
    if (it == tcpDeviceInfoMap_.end()) {
        return false;
    }
    ScanDeviceInfo info = it->second;
    if (srcKey != dstKey) {
        tcpDeviceInfoMap_.erase(it);
    }
    modifier(info);
    tcpDeviceInfoMap_[dstKey] = info;
    return true;
}

bool ScannerDiscoverData::RemoveEsclDevice(const std::string& uniqueId)
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    return esclDeviceInfoMap_.erase(uniqueId) > 0;
}

std::map<std::string, ScanDeviceInfo> ScannerDiscoverData::GetAllEsclDevices() const
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    return esclDeviceInfoMap_;
}

void ScannerDiscoverData::ClearEsclDevices()
{
    std::lock_guard<std::mutex> lock(esclMutex_);
    esclDeviceInfoMap_.clear();
}

} // namespace OHOS::Scan
