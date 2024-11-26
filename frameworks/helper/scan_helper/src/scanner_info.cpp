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

#include "scanner_info.h"

namespace OHOS::Scan {


//tcp
ScanDeviceInfoTCP::ScanDeviceInfoTCP()
{
    deviceName="";
    uuid="";
    model="";
    manufacturer="";
    deviceType="";
    port="";
    addr="";
    button="";
    feeder="";
    deviceState = 0;
}

ScanDeviceInfoTCP::ScanDeviceInfoTCP(const ScanDeviceInfoTCP &right)
{
    deviceName = right.deviceName;
    uuid = right.uuid;
    model = right.model;
    manufacturer = right.manufacturer;
    deviceType = right.deviceType;
    port = right.port;
    addr = right.addr;
    button = right.button;
    feeder = right.feeder;
    deviceState = right.deviceState;
}

ScanDeviceInfoTCP &ScanDeviceInfoTCP::operator=(const ScanDeviceInfoTCP &right)
{
    if (this != &right) {
        deviceName = right.deviceName;
        uuid = right.uuid;
        model = right.model;
        manufacturer = right.manufacturer;
        deviceType = right.deviceType;
        port = right.port;
        addr = right.addr;
        button = right.button;
        feeder = right.feeder;
        deviceState = right.deviceState;
    }
    return *this;
}

void ScanDeviceInfoTCP::SetDeviceName(const std::string& deviceName_)
{
    deviceName = deviceName_;
}

void ScanDeviceInfoTCP::SetUuid(const std::string& uuid_)
{
    uuid = uuid_;
}

void ScanDeviceInfoTCP::SetModel(const std::string& model_)
{
    model = model_;
}

void ScanDeviceInfoTCP::SetManufacturer(const std::string& manufacturer_)
{
    manufacturer = manufacturer_;
}

void ScanDeviceInfoTCP::SetDeviceType(const std::string& deviceType_)
{
    deviceType = deviceType_;
}

void ScanDeviceInfoTCP::SetPort(const std::string& port_)
{
    port = port_;
}

void ScanDeviceInfoTCP::SetAddr(const std::string& addr_)
{
    addr = addr_;
}

void ScanDeviceInfoTCP::SetButton(const std::string& button_)
{
    button = button_;
}

void ScanDeviceInfoTCP::SetFeeder(const std::string& feeder_)
{
    feeder = feeder_;
}

void ScanDeviceInfoTCP::SetDeviceState(const uint32_t& deviceState_)
{
    deviceState = deviceState_;
}

const std::string& ScanDeviceInfoTCP::GetDeviceName() const
{
    return deviceName;
}

const std::string& ScanDeviceInfoTCP::GetUuid() const
{
    return uuid;
}

const std::string& ScanDeviceInfoTCP::GetModel() const
{
    return model;
}

const std::string& ScanDeviceInfoTCP::GetManufacturer() const
{
    return manufacturer;
}

const std::string& ScanDeviceInfoTCP::GetDeviceType() const
{
    return deviceType;
}

const std::string& ScanDeviceInfoTCP::GetPort() const
{
    return port;
}

const std::string& ScanDeviceInfoTCP::GetAddr() const
{
    return addr;
}

const std::string& ScanDeviceInfoTCP::GetButton() const
{
    return button;
}

const std::string& ScanDeviceInfoTCP::GetFeeder() const
{
    return feeder;
}

const uint32_t& ScanDeviceInfoTCP::GetDeviceState() const
{
    return deviceState;
}

bool ScanDeviceInfoTCP::ReadFromParcel(Parcel &parcel)
{
    SetDeviceName(parcel.ReadString());
    SetUuid(parcel.ReadString());
    SetModel(parcel.ReadString());
    SetManufacturer(parcel.ReadString());
    SetDeviceType(parcel.ReadString());
    SetPort(parcel.ReadString());
    SetAddr(parcel.ReadString());
    SetButton(parcel.ReadString());
    SetFeeder(parcel.ReadString());
    return true;
}

bool ScanDeviceInfoTCP::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetDeviceName());
    parcel.WriteString(GetUuid());
    parcel.WriteString(GetModel());
    parcel.WriteString(GetManufacturer());
    parcel.WriteString(GetDeviceType());
    parcel.WriteString(GetPort());
    parcel.WriteString(GetAddr());
    parcel.WriteString(GetButton());
    parcel.WriteString(GetFeeder());
    return true;
}

std::shared_ptr<ScanDeviceInfoTCP> ScanDeviceInfoTCP::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanDeviceInfoTCP>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        SCAN_HILOGE("Failed to unmarshalling scaner info");
        return nullptr;
    }
    return nativeObj;
}


ScanDeviceInfo::ScanDeviceInfo()
{
    deviceId = "";
    manufacturer = "";
    model = "";
    deviceType = "";
    deviceState = 0;
    discoverMode = "";
    serialNumber = "";
    deviceName = "";
    uniqueId = "";
}

ScanDeviceInfo::ScanDeviceInfo(const ScanDeviceInfo &right)
{
    deviceId = right.deviceId;
    manufacturer = right.manufacturer;
    model = right.model;
    deviceType = right.deviceType;
    deviceState = right.deviceState;
    discoverMode = right.discoverMode;
    serialNumber = right.serialNumber;
    deviceName = right.deviceName;
    uniqueId = right.uniqueId;
}

ScanDeviceInfo &ScanDeviceInfo::operator=(const ScanDeviceInfo &right)
{
    if (this != &right) {
        deviceId = right.deviceId;
        manufacturer = right.manufacturer;
        model = right.model;
        deviceType = right.deviceType;
        deviceState = right.deviceState;
        discoverMode = right.discoverMode;
        serialNumber = right.serialNumber;
        deviceName = right.deviceName;
        uniqueId = right.uniqueId;
    }
    return *this;
}


void ScanDeviceInfo::SetDeviceId(const std::string& newScannerId)
{
    deviceId = newScannerId;
}

const std::string& ScanDeviceInfo::GetDeviceId() const
{
    return deviceId;
}

void ScanDeviceInfo::SetManufacturer(const std::string& newManufacturer)
{
    manufacturer = newManufacturer;
}

const std::string& ScanDeviceInfo::GetManufacturer() const
{
    return manufacturer;
}

void ScanDeviceInfo::SetModel(const std::string& newModel)
{
    model = newModel;
}

const std::string& ScanDeviceInfo::GetModel() const
{
    return model;
}

void ScanDeviceInfo::SetDeviceType(const std::string& newDeviceType)
{
    deviceType = newDeviceType;
}

const std::string& ScanDeviceInfo::GetDeviceType() const
{
    return deviceType;
}

void ScanDeviceInfo::SetDeviceState(const uint32_t& newDeviceState)
{
    deviceState = newDeviceState;
}

const uint32_t& ScanDeviceInfo::GetDeviceState() const
{
    return deviceState;
}

void ScanDeviceInfo::SetDiscoverMode(const std::string& newDiscoverMode)
{
    discoverMode = newDiscoverMode;
}

const std::string& ScanDeviceInfo::GetDiscoverMode() const
{
    return discoverMode;
}

void ScanDeviceInfo::SetSerialNumber(const std::string& newSerialNumber)
{
    serialNumber = newSerialNumber;
}

const std::string& ScanDeviceInfo::GetSerialNumber() const
{
    return serialNumber;
}

void ScanDeviceInfo::SetDeviceName(const std::string& newDeviceName)
{
    deviceName = newDeviceName;
}

const std::string& ScanDeviceInfo::GetDeviceName() const
{
    return deviceName;
}

void ScanDeviceInfo::SetUniqueId(const std::string& uniqueId)
{
    this->uniqueId = uniqueId;
}

const std::string& ScanDeviceInfo::GetUniqueId() const
{
    return uniqueId;
}

bool ScanDeviceInfo::ReadFromParcel(Parcel &parcel)
{
    SetDeviceId(parcel.ReadString());
    SetManufacturer(parcel.ReadString());
    SetModel(parcel.ReadString());
    SetDeviceType(parcel.ReadString());
    SetDiscoverMode(parcel.ReadString());
    SetSerialNumber(parcel.ReadString());
    SetDeviceName(parcel.ReadString());
    SetUniqueId(parcel.ReadString());
    return true;
}

bool ScanDeviceInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(deviceId);
    parcel.WriteString(manufacturer);
    parcel.WriteString(model);
    parcel.WriteString(deviceType);
    parcel.WriteString(discoverMode);
    parcel.WriteString(serialNumber);
    parcel.WriteString(deviceName);
    parcel.WriteString(uniqueId);
    return true;
}

std::shared_ptr<ScanDeviceInfo> ScanDeviceInfo::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanDeviceInfo>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        SCAN_HILOGE("Failed to unmarshalling scaner info");
        return nullptr;
    }
    return nativeObj;
}

// ScanDeviceInfoSync

ScanDeviceInfoSync::ScanDeviceInfoSync()
{
    deviceId = "";
    discoverMode = "";
    serialNumber = "";
    syncMode = "";
    deviceState = 0;
}

ScanDeviceInfoSync::ScanDeviceInfoSync(const ScanDeviceInfoSync &right)
{
    deviceId = right.deviceId;
    discoverMode = right.discoverMode;
    serialNumber = right.serialNumber;
    syncMode = right.syncMode;
    deviceState = right.deviceState;
}

ScanDeviceInfoSync &ScanDeviceInfoSync::operator=(const ScanDeviceInfoSync &right)
{
    if (this != &right) {
        deviceId = right.deviceId;
        discoverMode = right.discoverMode;
        serialNumber = right.serialNumber;
        syncMode = right.syncMode;
        deviceState = right.deviceState;
    }
    return *this;
}


void ScanDeviceInfoSync::SetDeviceId(const std::string& newScannerId)
{
    deviceId = newScannerId;
}

const std::string& ScanDeviceInfoSync::GetDeviceId() const
{
    return deviceId;
}

void ScanDeviceInfoSync::SetDiscoverMode(const std::string& newDiscoverMode)
{
    discoverMode = newDiscoverMode;
}

const std::string& ScanDeviceInfoSync::GetDiscoverMode() const
{
    return discoverMode;
}

void ScanDeviceInfoSync::SetSerialNumber(const std::string& newSerialNumber)
{
    serialNumber = newSerialNumber;
}

const std::string& ScanDeviceInfoSync::GetSerialNumber() const
{
    return serialNumber;
}

void ScanDeviceInfoSync::SetSyncMode(const std::string& newSyncMode)
{
    syncMode = newSyncMode;
}

const std::string& ScanDeviceInfoSync::GetSyncMode() const
{
    return syncMode;
}

void ScanDeviceInfoSync::SetDeviceState(const uint32_t& newDeviceState)
{
    deviceState = newDeviceState;
}

const uint32_t& ScanDeviceInfoSync::GetDeviceState() const
{
    return deviceState;
}

void ScanDeviceInfoSync::ReadFromParcel(Parcel &parcel)
{
    SetDeviceId(parcel.ReadString());
    SetDiscoverMode(parcel.ReadString());
    SetSerialNumber(parcel.ReadString());
    SetSyncMode(parcel.ReadString());
}

bool ScanDeviceInfoSync::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(deviceId);
    parcel.WriteString(discoverMode);
    parcel.WriteString(serialNumber);
    parcel.WriteString(syncMode);
    return true;
}

std::shared_ptr<ScanDeviceInfoSync> ScanDeviceInfoSync::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanDeviceInfoSync>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

} // namespace OHOS::Scan
