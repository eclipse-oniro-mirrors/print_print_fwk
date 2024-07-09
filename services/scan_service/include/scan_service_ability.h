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

#include "ability_manager_client.h"
#include "event_handler.h"
#include "extension_ability_info.h"
#include "iscan_callback.h"
#include "iremote_object.h"
#include "scan_constant.h"
#include "scan_service_stub.h"
#include "system_ability.h"
#ifdef SANE_ENABLE
#include "sane/sane.h"
#include "sane/saneopts.h"
#endif
#include "scanner_info.h"
#include "scan_mdns_service.h"
#include "scan_option_descriptor.h"
#include "jpeglib.h"
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
    int32_t InitScan(int32_t &scanVersion) override;
    int32_t ExitScan() override;
    int32_t GetScannerList() override;
    int32_t StopDiscover() override;
    int32_t OpenScanner(const std::string scannerId) override;
    int32_t CloseScanner(const std::string scannerId) override;
    int32_t GetScanOptionDesc(const std::string scannerId, const int32_t optionIndex,
        ScanOptionDescriptor &desc) override;
    int32_t OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
        const ScanOptionOpType op, ScanOptionValue &value, int32_t &info) override;
    int32_t GetScanParameters(const std::string scannerId, ScanParameters &para) override;
    int32_t StartScan(const std::string scannerId, const bool &batchMode) override;
    int32_t GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd) override;
    int32_t CancelScan(const std::string scannerId) override;
    int32_t SetScanIOMode(const std::string scannerId, const bool isNonBlocking) override;
    int32_t GetScanSelectFd(const std::string scannerId, int32_t &fd) override;
    int32_t On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener) override;
    int32_t Off(const std::string taskId, const std::string &type) override;
    int32_t GetScannerState(int32_t &scannerState) override;
    int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog) override;
    int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner) override;
    int32_t UpdateScannerName(const std::string& serialNumber,
        const std::string& discoverMode, const std::string& deviceName) override;
    int32_t AddPrinter(const std::string& serialNumber, const std::string& discoverMode) override;
    int32_t OnStartScan(const std::string scannerId, const bool &batchMode);
    void DisConnectUsbScanner(std::string serialNumber, std::string newDeviceId); // public
    void UpdateUsbScannerId(std::string serialNumber, std::string newDeviceId); // public

private:
#ifdef SANE_ENABLE
    int32_t ActionSetAuto(SANE_Handle &scannerHandle, const int32_t &optionIndex);
    int32_t ActionGetValue(SANE_Handle &scannerHandle, ScanOptionValue &value, const int32_t &optionIndex);
    int32_t ActionSetValue(SANE_Handle &scannerHandle, ScanOptionValue &value,
        const int32_t &optionIndex, int32_t &info);
    int32_t SelectScanOptionDesc(const SANE_Option_Descriptor* &optionDesc, ScanOptionDescriptor &desc);
#endif
    int32_t DoScanTask(const std::string scannerId, ScanProgress* scanProPtr);
    void StartScanTask(const std::string scannerId);
    void SendDeviceInfoTCP(const ScanDeviceInfoTCP &info, std::string event);
    void SendDeviceInfo(const ScanDeviceInfo &info, std::string event);
    void SendDeviceInfoSync(const ScanDeviceInfoSync &info, std::string event);
    void SendInitEvent(int32_t &scanVersion, std::string event);
    void SendDeviceSearchEnd(std::string &info, std::string event);
    void SetScannerSerialNumber(ScanDeviceInfo &info);
    void SaneGetScanner();
    void SyncScannerInfo(ScanDeviceInfo &info);
public:
    static std::map<std::string, ScanDeviceInfoTCP> scanDeviceInfoTCPMap_;
    static std::map<std::string, ScanDeviceInfo> saneGetUsbDeviceInfoMap;
    static std::map<std::string, ScanDeviceInfo> saneGetTcpDeviceInfoMap;
    static std::map<std::string, std::string> usbSnMap;
    void UnloadSystemAbility();
    static int32_t appCount_;
protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t ServiceInit();
    void InitServiceHandler();
    void ManualStart();
    int32_t ReInitScan(int32_t &scanVersion);
    bool CheckPermission(const std::string &permissionName);
    void SendGetFrameResEvent(const bool isGetSucc, const int32_t sizeRead);
#ifdef SANE_ENABLE
    void SetScanOptionDescriptor(ScanOptionDescriptor &desc, const SANE_Option_Descriptor *optionDesc);
    SANE_Handle GetScanHandle(const std::string &scannerId);
#endif
    int32_t WriteJpegHeader(ScanParameters &parm, struct jpeg_error_mgr* jerr);
    void GeneratePicture(const std::string &scannerId, std::string &file_name,
        std::string &output_file, int32_t &status, ScanProgress* &scanProPtr);
    void GetPicFrame(const std::string scannerId, ScanProgress *scanProPtr,
        int32_t &scanStatus, ScanParameters &parm);
    bool WritePicData(int &jpegrow, int32_t curReadSize, ScanParameters &parm, ScanProgress *scanProPtr);
    void GeneratePictureBatch(const std::string &scannerId, std::string &file_name,
        std::string &output_file, int32_t &status, ScanProgress* &scanProPtr);
    void GeneratePictureSingle(const std::string &scannerId, std::string &file_name,
        std::string &output_file, int32_t &status, ScanProgress* &scanProPtr);
    void AddFoundUsbScanner(ScanDeviceInfo &info);
    void AddFoundTcpScanner(ScanDeviceInfo &info);
#ifdef SANE_ENABLE
    bool SetScannerInfo(const SANE_Device** &currentDevice, ScanDeviceInfo &info);
#endif
    bool GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId);
    bool GetTcpDeviceIp(const std::string &deviceId, std::string &ip);
    void CleanScanTask(const std::string &scannerId);
    void SendDeviceList(std::vector<ScanDeviceInfo> &info, std::string event);
#ifdef SANE_ENABLE
    std::map<std::string, SANE_Handle> scannerHandleList_;
#endif
    ServiceRunningState state_;
    std::mutex lock_;
    static std::mutex instanceLock_;
    static sptr<ScanServiceAbility> instance_;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::map<std::string, sptr<IScanCallback>> registeredListeners_;
    std::recursive_mutex apiMutex_;
    std::recursive_mutex scanMutex_;
    uint64_t currentJobId_;
#ifdef SANE_ENABLE
    std::function<void(SANE_Handle scannerHandle, uint32_t fd)> getSingleFrameFDExe;
#endif
    std::function<void()> cyclicCallExe;
    std::queue<int32_t> scanQueue;
    std::map<int32_t, ScanProgress> scanTaskMap;
    std::vector<ScanDeviceInfo> deviceInfos;
    int32_t nextPicId = 1;
    int32_t buffer_size;
    bool batchMode_ = false;
    uint8_t *saneReadBuf;
    struct jpeg_compress_struct cinfo;
    FILE *ofp = NULL;
    bool isCancel = false;
    int32_t dpi = 0;
    JSAMPLE *jpegbuf = NULL;
};
} // namespace OHOS::Scan
#endif // SCAN_SYSTEM_ABILITY_H