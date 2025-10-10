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

#ifndef SCAN_SERVICE_ABILITY_H
#define SCAN_SERVICE_ABILITY_H

#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include <queue>
#include <chrono>
#include <atomic>

#include "ability_manager_client.h"
#include "event_handler.h"
#include "extension_ability_info.h"
#include "iscan_callback.h"
#include "iremote_object.h"
#include "scan_constant.h"
#include "scan_service_stub.h"
#include "system_ability.h"
#include "scanner_info.h"
#include "scan_mdns_service.h"
#include "scan_option_descriptor.h"
#include "jpeglib.h"
#include "scan_discover_data.h"
#include "scan_task.h"
#include "scan_picture_data.h"
namespace OHOS::Scan {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class ScanServiceAbility : public SystemAbility, public ScanServiceStub {
    DECLARE_SYSTEM_ABILITY(ScanServiceAbility);
public:
    DISALLOW_COPY_AND_MOVE(ScanServiceAbility);
    ScanServiceAbility(int32_t systemAbilityId, bool runOnCreate);
    ScanServiceAbility();
    ~ScanServiceAbility();
    static sptr<ScanServiceAbility> GetInstance();
    int32_t InitScan() override;
    int32_t ExitScan() override;
    int32_t GetScannerList() override;
    int32_t OpenScanner(const std::string scannerId) override;
    int32_t CloseScanner(const std::string scannerId) override;
    int32_t GetScanOptionDesc(const std::string scannerId, const int32_t optionIndex,
        ScanOptionDescriptor &desc) override;
    int32_t OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
        const ScanOptionOpType op, ScanOptionValue &value) override;
    int32_t GetScanParameters(const std::string scannerId, ScanParameters &para) override;
    int32_t StartScan(const std::string scannerId, const bool &batchMode) override;
    int32_t CancelScan(const std::string scannerId) override;
    int32_t On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener) override;
    int32_t Off(const std::string taskId, const std::string &type) override;
    int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog) override;
    int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner) override;
    void DisConnectUsbScanner(std::string serialNumber, std::string newDeviceId); // public
    void UpdateScannerId(const ScanDeviceInfoSync& usbSyncInfo); // public

private:
    int32_t ActionSetAuto(const std::string &scannerId, const int32_t &optionIndex);
    int32_t ActionGetValue(const std::string &scannerId, ScanOptionValue &value, const int32_t &optionIndex);
    int32_t ActionSetValue(const std::string &scannerId, ScanOptionValue &value,
                           const int32_t &optionIndex);
    int32_t DoScanTask(ScanTask &scanTask);
    void StartScanTask(ScanTask &scanTask);
    void SendDeviceInfo(const ScanDeviceInfo &info, std::string event);
    void SendDeviceInfoSync(const ScanDeviceInfoSync &info, std::string event);
    void SetScannerSerialNumber(ScanDeviceInfo &info);
    void SaneGetScanner();
    void SetScannerSerialNumberByTCP(ScanDeviceInfo &info);
    void SetScannerSerialNumberByUSB(ScanDeviceInfo &info);
public:
    void UnloadSystemAbility();
protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t ServiceInit();
    void InitServiceHandler();
    void ManualStart();
    bool CheckPermission(const std::string &permissionName);
    void GetPicFrame(ScanTask &scanTask, int32_t &scanStatus, ScanParameters &parm);
    void GeneratePictureBatch(ScanTask &scanTask);
    void GeneratePictureSingle(ScanTask &scanTask);
    bool GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId);
    bool GetTcpDeviceIp(const std::string &deviceId, std::string &ip);
    void SendDeviceList(std::vector<ScanDeviceInfo> &info, std::string event);
    int32_t GetCurrentUserId();
    bool CreateAndOpenScanFile(ScanTask &scanTask);
    void AddFoundScanner(ScanDeviceInfo& info, std::vector<ScanDeviceInfo>& scanDeviceInfos);
    void UpdateScanSystemData(const ScanDeviceInfo &info);
    void CleanUpAfterScan(ScanTask &scanTask, int32_t scanStatus);
    int32_t RestartScan(const std::string &scannerId);
    void InitializeScanService();
    void CleanupScanService();
    int32_t StartScanOnce(const std::string scannerId);
    int32_t GetScannerImageDpi(const std::string& scannerId, int32_t& dpi);
    std::set<std::string> openedScannerList_;
    std::atomic<ServiceRunningState> state_;
    std::mutex lock_;
    static std::mutex instanceLock_;
    static sptr<ScanServiceAbility> instance_;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::map<std::string, sptr<IScanCallback>> registeredListeners_;
    std::recursive_mutex apiMutex_;
    std::recursive_mutex scanMutex_;
    std::vector<ScanDeviceInfo> deviceInfos_;
    std::atomic<int32_t> appCount_{0};
    std::atomic<int32_t> scannerState_{SCANNER_READY};
    ScannerDiscoverData& scannerDiscoverData_ = ScannerDiscoverData::GetInstance();
    ScanPictureData& scanPictureData_ = ScanPictureData::GetInstance();
};
} // namespace OHOS::Scan
#endif // SCAN_SYSTEM_ABILITY_H