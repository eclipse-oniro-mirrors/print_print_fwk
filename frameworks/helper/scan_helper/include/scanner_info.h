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

#ifndef SCAN_DEVICE_INFO_H
#define SCAN_DEVICE_INFO_H
#define TDD_ENABLE 1

#include <map>
#include "napi/native_api.h"
#include "parcel.h"

#include "napi_scan_utils.h"


namespace OHOS::Scan {
class ScanDeviceInfoTCP final : public Parcelable {
public:
    explicit ScanDeviceInfoTCP();

    ScanDeviceInfoTCP(const ScanDeviceInfoTCP &right);

    ScanDeviceInfoTCP &operator=(const ScanDeviceInfoTCP &ScanDeviceInfoTCP);

    ~ScanDeviceInfoTCP() = default;
    
    void SetDeviceName(const std::string &deviceName_);
    void SetUuid(const std::string &uuid_);
    void SetModel(const std::string &model_);
    void SetManufacturer(const std::string &manufacturer_);
    void SetDeviceType(const std::string &deviceType_);
    void SetPort(const std::string &port_);
    void SetAddr(const std::string &addr_);
    void SetButton(const std::string &button_);
    void SetFeeder(const std::string &feeder_);
    void SetDeviceState(const uint32_t &deviceState_);
    void SetInfoType(const std::string &infoType_);

    [[nodiscard]] const std::string &GetDeviceName() const;
    [[nodiscard]] const std::string &GetUuid() const;
    [[nodiscard]] const std::string &GetModel() const;
    [[nodiscard]] const std::string &GetManufacturer() const;
    [[nodiscard]] const std::string &GetDeviceType() const;
    [[nodiscard]] const std::string &GetPort() const;
    [[nodiscard]] const std::string &GetAddr() const;
    [[nodiscard]] const std::string &GetButton() const;
    [[nodiscard]] const std::string &GetFeeder() const;
    [[nodiscard]] const uint32_t &GetDeviceState() const;
    [[nodiscard]] const std::string &GetInfoType() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<ScanDeviceInfoTCP> Unmarshalling(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    bool ReadFromParcel(Parcel &parcel);

    static bool ValidateProperty(napi_env env, napi_value object);

#ifndef TDD_ENABLE
private:
#endif
    std::string deviceName;
    std::string uuid;
    std::string model;
    std::string manufacturer;
    std::string deviceType;
    std::string port;
    std::string addr;
    std::string button;
    std::string feeder;
    uint32_t deviceState;
};

class ScanDeviceInfo final : public Parcelable {
public:
    explicit ScanDeviceInfo();

    ScanDeviceInfo(const ScanDeviceInfo &right);

    ScanDeviceInfo &operator=(const ScanDeviceInfo &ScanDeviceInfo);

    ~ScanDeviceInfo() = default;

    void SetDeviceId(const std::string &newDeviceId);
    void SetManufacturer(const std::string &newManufacturer);
    void SetModel(const std::string &newModel);
    void SetDeviceType(const std::string &newDeviceType);
    void SetDeviceState(const uint32_t &newDeviceState);
    void Dump();
    void SetDiscoverMode(const std::string &newDiscoverMode);
    void SetSerialNumber(const std::string &newSerialNumber);
    void SetDeviceName(const std::string &newDeviceName);
    void SetUniqueId(const std::string &uniqueId);

    [[nodiscard]] const std::string &GetDeviceId() const;
    [[nodiscard]] const std::string &GetManufacturer() const;
    [[nodiscard]] const std::string &GetModel() const;
    [[nodiscard]] const std::string &GetDeviceType() const;
    [[nodiscard]] const uint32_t &GetDeviceState() const;
    [[nodiscard]] const std::string &GetDiscoverMode() const;
    [[nodiscard]] const std::string &GetSerialNumber() const;
    [[nodiscard]] const std::string &GetDeviceName() const;
    [[nodiscard]] const std::string &GetUniqueId() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<ScanDeviceInfo> Unmarshalling(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    bool ReadFromParcel(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    std::string deviceId;
    std::string manufacturer;
    std::string model;
    std::string deviceType;
    uint32_t deviceState;
    std::string discoverMode;
    std::string serialNumber;
    std::string deviceName;
    std::string uniqueId;
};

class ScanDeviceInfoSync final : public Parcelable {
public:
    explicit ScanDeviceInfoSync();

    ScanDeviceInfoSync(const ScanDeviceInfoSync &right);

    ScanDeviceInfoSync &operator=(const ScanDeviceInfoSync &ScanDeviceInfoSync);

    ~ScanDeviceInfoSync() = default;

    void SetDeviceId(const std::string &newDeviceId);
    void SetDiscoverMode(const std::string &newDiscoverMode);
    void SetSerialNumber(const std::string &newSerialNumber);
    void SetSyncMode(const std::string &newSyncMode);
    void SetDeviceState(const uint32_t &newDeviceState);

    [[nodiscard]] const std::string &GetDeviceId() const;
    [[nodiscard]] const std::string &GetDiscoverMode() const;
    [[nodiscard]] const std::string &GetSerialNumber() const;
    [[nodiscard]] const std::string &GetSyncMode() const;
    [[nodiscard]] const uint32_t &GetDeviceState() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<ScanDeviceInfoSync> Unmarshalling(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    void ReadFromParcel(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    std::string deviceId;
    std::string discoverMode;
    std::string serialNumber;
    std::string syncMode;
    uint32_t deviceState;
};

} // namespace OHOS::Scan
#endif // SCAN_DEVICE_INFO_H
