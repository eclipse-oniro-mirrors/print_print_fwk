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
#include "scan_service_ability.h"

#include <cerrno>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>
#include <condition_variable>
#include <regex>

#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "scan_util.h"
#include "scanner_info.h"
#include "string_wrapper.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "scan_usb_manager.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "scan_system_data.h"

namespace OHOS::Scan {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using SteadyTimePoint = std::chrono::steady_clock::time_point;

constexpr int ONE_MB = 1024 * 1024; // default buffersize 1MB
constexpr int SCAN_PROGRESS_100 = 100;
#ifdef SANE_ENABLE
constexpr int SCAN_PROGRESS_10 = 10;
constexpr int SCAN_PROGRESS_19 = 19;
constexpr int SCAN_PROGRESS_80 = 80;
#endif
constexpr int JPEG_QUALITY_SEVENTY_FIVE = 75;
constexpr int CHANNEL_ONE = 1;
constexpr int CHANNEL_THREE = 3;
#ifdef SANE_ENABLE
constexpr int MAX_PICTURE_DPI = 3000;
constexpr int MAX_SANE_VALUE_LEN = 2000;
#endif
const int64_t INIT_INTERVAL = 5000L;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t UNLOAD_SYSTEMABILITY_DELAY = 1000 * 30;

static int32_t g_scannerState = SCANNER_READY;
#ifdef SANE_ENABLE
static bool g_hasOpenScannerFaild = false;
#endif
static bool g_hasIoFaild = false;
static bool g_isJpegWriteSuccess = false;
static const std::string PERMISSION_NAME_SCAN = "ohos.permission.SCAN";
static const std::string PERMISSION_NAME_SCAN_JOB = "ohos.permission.MANAGE_SCAN_JOB";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_JOB = "ohos.permission.MANAGE_PRINT_JOB";
static const std::string SCAN_DEVICE_FOUND_TCP = "scanDeviceFoundTCP";
static const std::string SCAN_DEVICE_FOUND = "scanDeviceFound";
static const std::string SCAN_DEVICE_SYNC = "scanDeviceSync";
static const std::string SCAN_DEVICE_ADD = "scanDeviceAdd";
static const std::string SCAN_DEVICE_DEL = "scanDeviceDel";
static const std::string SCAN_INIT_EVENT = "scanInitEvent";

static const std::string DEVICE_EVENT_TYPE = "deviceStateChange";
static const std::string GET_FRAME_RES_EVENT_TYPE = "getFrameResult";
static const std::string GET_SCANNER_DEVICE_LIST = "GET_SCANNER_DEVICE_LIST";

std::map<std::string, sptr<IScanCallback>> OHOS::Scan::ScanServiceAbility::registeredListeners_;

REGISTER_SYSTEM_ABILITY_BY_ID(ScanServiceAbility, SCAN_SERVICE_ID, true);

int32_t ScanServiceAbility::appCount_ = 0;
std::mutex ScanServiceAbility::instanceLock_;
sptr<ScanServiceAbility> ScanServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> ScanServiceAbility::serviceHandler_;
std::map<std::string, ScanDeviceInfoTCP> ScanServiceAbility::scanDeviceInfoTCPMap_;
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetUsbDeviceInfoMap;
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetTcpDeviceInfoMap;
std::map<std::string, std::string> ScanServiceAbility::usbSnMap;

ScanServiceAbility::ScanServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START),
    currentJobId_(SCAN_CONSTRAINT_NONE)
{
    buffer_size = ONE_MB;
    saneReadBuf = static_cast<uint8_t *>(malloc(buffer_size));
#ifdef SANE_ENABLE
    getSingleFrameFDExe = [=](SANE_Handle scannerHandle, uint32_t fd) {
            int32_t totalReadSize = 0;
            int32_t curReadSize = 0;
            uint8_t *buffer = static_cast<uint8_t *>(malloc(buffer_size));
            if (!buffer) {
                SCAN_HILOGE("malloc memory for buffer failed!!!");
                SendGetFrameResEvent(false, totalReadSize);
                return;
            }
            SANE_Status status = SANE_STATUS_GOOD;
            while (true) {
                status = sane_read(scannerHandle, buffer, buffer_size, &curReadSize);
                if (status == SANE_STATUS_EOF) {
                    SCAN_HILOGD("Totally read %{public}d bytes of frame data", totalReadSize);
                    SendGetFrameResEvent(true, totalReadSize);
                    break;
                }
                if (status != SANE_STATUS_GOOD) {
                    SCAN_HILOGE("sane_read failed, reason: [%{public}s]", sane_strstatus(status));
                    g_scannerState = SCANNER_READY;
                    SendGetFrameResEvent(false, totalReadSize);
                    break;
                }
                write(fd, buffer, curReadSize);
                totalReadSize += curReadSize;
                SCAN_HILOGD("sane_read success, current read: %{public}d Bytes, already read %{public}d Bytes",
                    curReadSize, totalReadSize);
            }
            free(buffer);
            buffer = nullptr;
    };
#endif
    cinfoPtr = new (std::nothrow) jpeg_compress_struct();
    if (cinfoPtr == nullptr) {
        SCAN_HILOGE("cinfoPtr allocated failed");
        return;
    }
    cinfoPtr->comps_in_scan = 0;
}

ScanServiceAbility::~ScanServiceAbility()
{
    FREE_AND_NULLPTR(saneReadBuf);
    FREE_AND_NULLPTR(jpegbuf)
    DELETE_AND_NULLIFY(cinfoPtr);
    SCAN_HILOGD("~ScanServiceAbility state_  is %{public}d.", static_cast<int>(state_));
}

sptr<ScanServiceAbility> ScanServiceAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new ScanServiceAbility(SCAN_SERVICE_ID, true);
        }
    }
    return instance_;
}

int32_t ScanServiceAbility::ServiceInit()
{
    bool ret = Publish(ScanServiceAbility::GetInstance());
    if (!ret) {
        SCAN_HILOGE("ScanServiceAbility Publish failed.");
        return E_SCAN_SERVER_FAILURE;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    SCAN_HILOGD("state_ is %{public}d.", static_cast<int>(state_));
    SCAN_HILOGI("Init ScanServiceAbility success.");
    return ERR_OK;
}

void ScanServiceAbility::OnStart()
{
    SCAN_HILOGI("ScanServiceAbility::Enter OnStart.");
    if (instance_ == nullptr) {
        instance_ = this;
    }
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        SCAN_HILOGI("ScanServiceAbility is already running.");
        return;
    }

    InitServiceHandler();
    int32_t ret = ServiceInit();
    if (ret != ERR_OK) {
        auto callback = [=]() { ServiceInit(); };
        serviceHandler_->PostTask(callback, INIT_INTERVAL);
        SCAN_HILOGE("ScanServiceAbility Init failed. Try again 5s later");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    return;
}

void ScanServiceAbility::InitServiceHandler()
{
    SCAN_HILOGI("InitServiceHandler started.");
    if (serviceHandler_ != nullptr) {
        SCAN_HILOGI("InitServiceHandler already init.");
        return;
    }
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("ScanServiceAbility");
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    SCAN_HILOGI("InitServiceHandler succeeded.");
}

void ScanServiceAbility::ManualStart()
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        SCAN_HILOGI("ScanServiceAbility restart.");
        OnStart();
    }
}

void ScanServiceAbility::OnStop()
{
    SCAN_HILOGI("OnStop started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return;
    }
    serviceHandler_ = nullptr;
    state_ = ServiceRunningState::STATE_NOT_START;
    SCAN_HILOGI("OnStop end.");
}
void ScanServiceAbility::UnloadSystemAbility()
{
    SCAN_HILOGI("appCount_= %{public}d", appCount_);
    auto unloadTask = [this]() {
        if (ScanServiceAbility::appCount_ != 0) {
            SCAN_HILOGW("appCount is not equal to zerro");
            return;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("get samgr failed");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(SCAN_SERVICE_ID);
        if (ret != ERR_OK) {
            SCAN_HILOGE("unload system ability failed");
            return;
        }
        this->ExitScan();
        SCAN_HILOGI("unload system ability successfully");
    };
    serviceHandler_->PostTask(unloadTask, UNLOAD_SYSTEMABILITY_DELAY);
}

#ifdef SANE_ENABLE
SANE_Handle ScanServiceAbility::GetScanHandle(const std::string &scannerId)
{
    auto scannerIt = scannerHandleList_.find(scannerId);
    if (scannerIt == scannerHandleList_.end()) {
        SCAN_HILOGE("ScannerId: [%{public}s] is not openned!!!", scannerId.c_str());
        return nullptr;
    }

    return scannerHandleList_[scannerId];
}
#endif

int32_t ScanServiceAbility::InitScan(int32_t &scanVersion)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ExitScan();
    SCAN_HILOGI("ScanServiceAbility InitScan start");
#ifdef SANE_ENABLE
    SANE_Status status = sane_init(&scanVersion, nullptr);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_init failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
#endif
    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    ScanSystemData::GetInstance().Init();
    SCAN_HILOGI("ScanServiceAbility InitScan end, scanVersion = [%{public}d]", scanVersion);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ExitScan()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility ExitScan start");
    std::lock_guard<std::mutex> autoLock(lock_);
#ifdef SANE_ENABLE
    sane_exit();
    scannerHandleList_.clear();
#endif
    g_scannerState = SCANNER_READY;
    std::queue<int32_t> empty;
    scanQueue.swap(empty);
    scanTaskMap.clear();
    SCAN_HILOGI("ScanServiceAbility ExitScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ReInitScan(int32_t &scanVersion)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility ReInitScan start");
#ifdef SANE_ENABLE
    sane_exit();
    scannerHandleList_.clear();
    g_scannerState = SCANNER_READY;
    std::queue<int32_t> empty;
    scanQueue.swap(empty);
    scanTaskMap.clear();

    SANE_Status status = sane_init(&scanVersion, nullptr);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("ReInitScan sane_init failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
#endif
    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    SCAN_HILOGD("ScanServiceAbility ReInitScan end, scanVersion = [%{public}d]", scanVersion);
    return E_SCAN_NONE;
}

bool ScanServiceAbility::GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId)
{
    std::regex pattern(R"(([a-zA-Z0-9_]+):(libusb):([0-9]{3}):([0-9]{3}))");
    std::smatch match;
    if (std::regex_match(deviceId, match, pattern)) {
        constexpr size_t STRING_POS_THREE = 3;
        constexpr size_t STRING_POS_FOUR = 4;
        firstId = std::to_string(std::stoi(match[STRING_POS_THREE]));
        secondId = std::to_string(std::stoi(match[STRING_POS_FOUR]));
        return true;
    } else {
        SCAN_HILOGE("In USB mode, the deviceId string format does not match");
        return false;
    }
}

bool ScanServiceAbility::GetTcpDeviceIp(const std::string &deviceId, std::string &ip)
{
    std::regex pattern(R"(([^ ]+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ([^ ]+))");
    std::smatch match;
    if (std::regex_match(deviceId, match, pattern)) {
        constexpr size_t STRING_POS_TWO = 2;
        ip = match[STRING_POS_TWO];
        return true;
    } else {
        SCAN_HILOGE("In TCP mode, the deviceId string format does not match");
        return false;
    }
}

void ScanServiceAbility::SetScannerSerialNumber(ScanDeviceInfo &info)
{
    if (info.model.find("(") > 0) {
        info.model = info.model.substr(0, info.model.find("(") - 1);
    }
    if (info.deviceId.find(":tcp") != info.deviceId.npos) {
        info.discoverMode = "TCP";
        SCAN_HILOGI("SetScannerSerialNumber discoverMode:[%{public}s]", info.discoverMode.c_str());
        std::string ip;
        if (!GetTcpDeviceIp(info.deviceId, ip)) {
            SCAN_HILOGE("cannot get device's ip");
            return;
        }
        auto it = scanDeviceInfoTCPMap_.find(ip);
        if (it != scanDeviceInfoTCPMap_.end()) {
            info.serialNumber = it->second.deviceName.substr(
                it->second.deviceName.find_last_of(" ") + 1, it->second.deviceName.size() - 1);
            SCAN_HILOGI("Set mdns ScannerSerialNumber :[%{public}s]", info.serialNumber.c_str());
        }
        info.deviceName = it->second.deviceName;
    } else if (info.deviceId.find(":libusb") != info.deviceId.npos) {
        info.discoverMode = "USB";
        SCAN_HILOGI("SetScannerSerialNumber discoverMode:[%{public}s]", info.discoverMode.c_str());
        std::string firstId;
        std::string secondId;
        if (!GetUsbDevicePort(info.deviceId, firstId, secondId)) {
            SCAN_HILOGE("cannot get usb's port");
            return;
        }
        std::string usbScannerPort = firstId + "-" + secondId;
        SCAN_HILOGI("usbScannerPort: firstId-secondId [%{public}s]", usbScannerPort.c_str());
        DelayedSingleton<ScanUsbManager>::GetInstance()->RefreshUsbDevice();
        auto it = usbSnMap.find(usbScannerPort);
        if (it != usbSnMap.end() && it->second != "") {
            SCAN_HILOGI("set serialNumber [%{public}s]", usbSnMap[usbScannerPort].c_str());
            info.serialNumber = usbSnMap[usbScannerPort];
        } else {
            SCAN_HILOGE("usb %{public}s can't find serialNumber", usbScannerPort.c_str());
        }
        info.deviceName = info.manufacturer + "-" + info.model + "-" + info.serialNumber;
    }
}

void ScanServiceAbility::SyncScannerInfo(ScanDeviceInfo &info)
{
    std::string uniqueId = info.discoverMode + info.serialNumber;
    std::string deviceName = "";
    if (ScanSystemData::GetInstance().QueryScannerNameByUniqueId(uniqueId, deviceName)) {
        info.deviceName = deviceName;
    } else {
        SCAN_HILOGW("ScanServiceAbility SyncScannerInfo deviceName not need upadate");
    }
    if (ScanSystemData::GetInstance().UpdateScannerInfoByUniqueId(uniqueId, info)) {
        ScanSystemData::GetInstance().SaveScannerMap();
    }
}

void ScanServiceAbility::AddFoundUsbScanner(ScanDeviceInfo &info)
{
    SCAN_HILOGI("AddFoundUsbScanner start model:[%{public}s]", info.model.c_str());
    SyncScannerInfo(info);
    std::lock_guard<std::mutex> autoLock(clearMapLock_);
#ifdef DEBUG_ENABLE
    auto it = saneGetUsbDeviceInfoMap.find(info.serialNumber);
    if (it != saneGetUsbDeviceInfoMap.end()) {
        SCAN_HILOGD("AddFoundUsbScanner usbScanner deviceId:[%{public}s] of serialNumber:[%{public}s] has change",
                    saneGetUsbDeviceInfoMap[info.serialNumber].deviceId.c_str(), info.serialNumber.c_str());
    }
#endif
    saneGetUsbDeviceInfoMap[info.serialNumber] = info;
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("AddFoundUsbScanner usbScanner deviceId:[%{public}s] of serialNumber:[%{public}s]",
                saneGetUsbDeviceInfoMap[info.serialNumber].deviceId.c_str(), info.serialNumber.c_str());
#endif
    SCAN_HILOGI("AddFoundUsbScanner end model:[%{public}s]", info.model.c_str());
}

void ScanServiceAbility::AddFoundTcpScanner(ScanDeviceInfo &info)
{
    SCAN_HILOGI("AddFoundTcpScanner start: model:[%{public}s]", info.model.c_str());
    SyncScannerInfo(info);
#ifdef DEBUG_ENABLE
    auto it = saneGetTcpDeviceInfoMap.find(info.serialNumber);
    if (it != saneGetTcpDeviceInfoMap.end()) {
        SCAN_HILOGD("AddFoundTcpScanner tcpScanner deviceId:[%{public}s] of serialNumber:[%{public}s] has change",
                    saneGetTcpDeviceInfoMap[info.serialNumber].deviceId.c_str(), info.serialNumber.c_str());
    }
#endif
    saneGetTcpDeviceInfoMap[info.serialNumber] = info;
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("AddFoundTcpScanner tcpScanner deviceId:[%{public}s] of serialNumber:[%{public}s]",
                saneGetTcpDeviceInfoMap[info.serialNumber].deviceId.c_str(), info.serialNumber.c_str());
#endif
    SCAN_HILOGI("AddFoundTcpScanner end: model:[%{public}s]", info.model.c_str());
}

#ifdef SANE_ENABLE
bool ScanServiceAbility::SetScannerInfo(const SANE_Device** &currentDevice, ScanDeviceInfo &info)
{
    SCAN_HILOGI("SetScannerInfo start.");
    const std::string nullString = "";
    if ((*currentDevice)->name != nullptr && (*currentDevice)->name != nullString) {
        info.deviceId = (*currentDevice)->name;
    } else {
        SCAN_HILOGE("SaneGetScanner current_device's name is null.");
        return false;
    }
    if ((*currentDevice)->vendor != nullptr) {
        info.manufacturer = (*currentDevice)->vendor;
    }
    if ((*currentDevice)->model != nullptr) {
        info.model = (*currentDevice)->model;
    }
    if ((*currentDevice)->type != nullptr) {
        info.deviceType = (*currentDevice)->type;
    }
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("SetScannerInfo deviceId:[%{public}s] manufacturer:[%{public}s]"
                "model:[%{public}s] deviceType:[%{public}s]",
                info.deviceId.c_str(), info.manufacturer.c_str(), info.model.c_str(), info.deviceType.c_str());
#endif
    SCAN_HILOGI("SetScannerInfo end.");
    return true;
}
#endif

#ifdef SANE_ENABLE
void ScanServiceAbility::SaneGetScanner()
{
    const SANE_Device **deviceList;
    SANE_Status devicesStatus = SANE_STATUS_GOOD;
    std::lock_guard<std::mutex> autoLock(lock_);
    {
        std::lock_guard<std::mutex> autoLock(clearMapLock_);
        saneGetTcpDeviceInfoMap.clear();
        saneGetUsbDeviceInfoMap.clear();
    }
    g_scannerState = SCANNER_SEARCHING;
    devicesStatus = sane_get_devices(&deviceList, SANE_FALSE);
    if (devicesStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_get_devices failed, reason: [%{public}s]", sane_strstatus(devicesStatus));
        g_scannerState = SCANNER_READY;
        return;
    }
    for (const SANE_Device **currentDevice = deviceList; *currentDevice != nullptr; ++currentDevice) {
        ScanDeviceInfo info;
        if (!SetScannerInfo(currentDevice, info)) {
            SCAN_HILOGE("SaneGetScanner SetScannerInfo failed");
            continue;
        }
        SetScannerSerialNumber(info);
#ifdef DEBUG_ENABLE
        SCAN_HILOGD("SaneGetScanner serialNumber:[%{public}s] discoverMode:[%{public}s",
                    info.serialNumber.c_str(), info.discoverMode.c_str());
#endif
        if (info.serialNumber != "" && info.discoverMode == "USB") {
            SCAN_HILOGI("SaneGetScanner AddFoundUsbScanner model:[%{public}s]", info.model.c_str());
            AddFoundUsbScanner(info);
        } else if (info.serialNumber != "" && info.discoverMode == "TCP") {
            SCAN_HILOGI("SaneGetScanner AddFoundTcpScanner model:[%{public}s]", info.model.c_str());
            AddFoundTcpScanner(info);
        } else {
            SCAN_HILOGE("SaneGetScanner SetScannerSerialNumber failed, model:[%{public}s]", info.model.c_str());
        }
    }
    std::lock_guard<std::mutex> autoLock(clearMapLock_);
    for (auto &t : saneGetUsbDeviceInfoMap) {
        SendDeviceInfo(t.second, SCAN_DEVICE_FOUND);
        deviceInfos.emplace_back(t.second);
    }
    for (auto &t : saneGetTcpDeviceInfoMap) {
        SendDeviceInfo(t.second, SCAN_DEVICE_FOUND);
        deviceInfos.emplace_back(t.second);
    }
    g_scannerState = SCANNER_READY;
}
#endif

int32_t ScanServiceAbility::GetScannerList()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        return E_SCAN_NO_PERMISSION;
    }
    if (g_scannerState != SCANNER_READY) {
        SCAN_HILOGW("is working");
        return E_SCAN_DEVICE_BUSY;
    }
    int32_t version = 0;
    InitScan(version);
    SCAN_HILOGD("ScanServiceAbility GetScannerList start");
    std::lock_guard<std::mutex> autoLock(lock_);
    // tcp
    auto exec_tcp = [=]() {
        ScanMdnsService::GetInstance().SetServiceType("_scanner._tcp");
        ScanMdnsService::GetInstance().onStartDiscoverService();
    };
    auto exec_sane_getscaner = [=]() {
        deviceInfos.clear();
#ifdef SANE_ENABLE
        SaneGetScanner();
#endif
        std::string message = "EOF";
        SendDeviceSearchEnd(message, SCAN_DEVICE_FOUND);
        SendDeviceList(deviceInfos, GET_SCANNER_DEVICE_LIST);
    };
    serviceHandler_->PostTask(exec_tcp, ASYNC_CMD_DELAY);
    serviceHandler_->PostTask(exec_sane_getscaner, ASYNC_CMD_DELAY);
    SCAN_HILOGD("ScanServiceAbility GetScannerList end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StopDiscover()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility StopDiscover start");

    ScanMdnsService::GetInstance().onStopDiscoverService();

    SCAN_HILOGD("ScanServiceAbility StopDiscover end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::OpenScanner(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility OpenScanner start");
    if (scannerId.empty()) {
        SCAN_HILOGE("OpenScanner scannerId is empty");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (g_scannerState != SCANNER_READY) {
        SCAN_HILOGE("OpenScanner scannerState not ready");
        return E_SCAN_DEVICE_BUSY;
    }
#ifdef SANE_ENABLE
    SANE_Handle scannerHandle = 0;
    SANE_String_Const scannerIdCstr = scannerId.c_str();
    SANE_Status status = sane_open(scannerIdCstr, &scannerHandle);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_open failed, reason: [%{public}s], retry one times", sane_strstatus(status));
        g_hasOpenScannerFaild = true;
    }
    if (g_hasOpenScannerFaild == true) {
        int32_t scanVersion = 0;
        int32_t ret = ReInitScan(scanVersion);
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("ScanServiceAbility OpenScanner ReInitScan failed !!!");
            return ret;
        }
        status = sane_open(scannerIdCstr, &scannerHandle);
        g_hasOpenScannerFaild = false;
    }

    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_open failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }

    scannerHandleList_[scannerId] = scannerHandle;
#endif
    SCAN_HILOGI("ScanServiceAbility OpenScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CloseScanner(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility CloseScanner start");

#ifdef SANE_ENABLE

    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility CloseScanner error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    scanTaskMap.clear();
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    sane_close(scannerHandle);
    scannerHandleList_.erase(scannerId);
#endif
    SCAN_HILOGI("ScanServiceAbility CloseScanner end");
    return E_SCAN_NONE;
}

#ifdef SANE_ENABLE
void ScanServiceAbility::SetScanOptionDescriptor(ScanOptionDescriptor &desc, const SANE_Option_Descriptor *optionDesc)
{
    if (optionDesc->name != nullptr) {
        desc.SetOptionName(std::string(optionDesc->name));
    }
    if (optionDesc->title != nullptr) {
        desc.SetOptionTitle(std::string(optionDesc->title));
    }
    if (optionDesc->desc != nullptr) {
        desc.SetOptionDesc(std::string(optionDesc->desc));
    }
    desc.SetOptionType(optionDesc->type);
    desc.SetOptionUnit(optionDesc->unit);
    desc.SetOptionSize(optionDesc->size);
    desc.SetOptionCap(optionDesc->cap);
    desc.SetOptionConstraintType(optionDesc->constraint_type);
}
#endif

#ifdef SANE_ENABLE
int32_t ScanServiceAbility::SelectScanOptionDesc(
    const SANE_Option_Descriptor* &optionDesc, ScanOptionDescriptor &desc)
{
    if (optionDesc->constraint_type == SANE_CONSTRAINT_RANGE && optionDesc->constraint.range != nullptr) {
        ScanRange scanRange;
        scanRange.SetMinValue(optionDesc->constraint.range->min);
        scanRange.SetMaxValue(optionDesc->constraint.range->max);
        scanRange.SetQuantValue(optionDesc->constraint.range->quant);
        desc.SetOptionConstraintRange(scanRange);
    } else if (optionDesc->constraint_type == SANE_CONSTRAINT_WORD_LIST
        && optionDesc->constraint.word_list != nullptr) {
        std::vector<int32_t> optionConstraintNumber;
        int sizeNumber = *(optionDesc->constraint.word_list) + 1;
        for (int i = 0; i < sizeNumber; i++) {
            SCAN_HILOGD("SANE_CONSTRAINT_WORD_LIST: %{public}d", *(optionDesc->constraint.word_list + i));
            optionConstraintNumber.push_back(*(optionDesc->constraint.word_list + i));
        }
        desc.SetOptionConstraintNumber(optionConstraintNumber);
    } else if (optionDesc->constraint_type == SANE_CONSTRAINT_STRING_LIST
        && optionDesc->constraint.string_list != nullptr) {
        std::vector<std::string> optionConstraintString;
        const SANE_String_Const* stringList = optionDesc->constraint.string_list;
        if (stringList == nullptr) {
            SCAN_HILOGE("sane_get_option_descriptor stringList nullptr");
            return E_SCAN_INVALID_PARAMETER;
        }
        for (int i = 0; stringList[i] != nullptr; i++) {
            SCAN_HILOGD("SANE_CONSTRAINT_STRING_LIST: %{public}s", stringList[i]);
            optionConstraintString.push_back(std::string(stringList[i]));
        }
        optionConstraintString.push_back(string("null"));
        desc.SetOptionConstraintString(optionConstraintString);
    }
    return E_SCAN_NONE;
}
#endif

int32_t ScanServiceAbility::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanOptionDesc start");
    SCAN_HILOGI("optionIndex [%{public}d]", optionIndex);

#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility GetScanOptionDesc error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    const SANE_Option_Descriptor *optionDesc = sane_get_option_descriptor(scannerHandle, optionIndex);
    if (optionDesc == nullptr) {
        SCAN_HILOGE("sane_get_option_descriptor failed, ScannerId: [%{public}s]", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    SetScanOptionDescriptor(desc, optionDesc);
    int32_t state = SelectScanOptionDesc(optionDesc, desc);
    if (state != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceAbility GetScanOptionDesc error exit");
        return state;
    }

#endif
    SCAN_HILOGD("ScanServiceAbility GetScanOptionDesc end");
    return E_SCAN_NONE;
}

#ifdef SANE_ENABLE
int32_t ScanServiceAbility::ActionSetAuto(SANE_Handle &scannerHandle, const int32_t &optionIndex)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_SET_AUTO");
    SANE_Status status = SANE_STATUS_GOOD;
    status = sane_control_option(scannerHandle, optionIndex, SANE_ACTION_SET_AUTO, 0, 0);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_control_option failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
    return E_SCAN_NONE;
}
#endif

#ifdef SANE_ENABLE
int32_t ScanServiceAbility::ActionGetValue(SANE_Handle &scannerHandle, ScanOptionValue &value,
    const int32_t &optionIndex)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_GET_VALUE");
    SANE_Status status = SANE_STATUS_GOOD;
    int32_t valueSize = value.GetValueSize() / sizeof(SANE_Word);
    uint32_t bufSize = (value.GetStrValue().size() + 1)
        > sizeof(int) ? (value.GetStrValue().size() + 1) : sizeof(int);
    if (bufSize == 0 || bufSize > MAX_SANE_VALUE_LEN) {
        SCAN_HILOGE("malloc value buffer size error");
        return E_SCAN_GENERIC_FAILURE;
    }
    void* saneValueBuf = malloc(bufSize);
    ScanOptionValueType valueType = value.GetScanOptionValueType();
    if (!saneValueBuf) {
        SCAN_HILOGE("malloc value buffer failed");
        return E_SCAN_GENERIC_FAILURE;
    }
    if (memset_s(saneValueBuf, bufSize, 0, bufSize) != 0) {
        SCAN_HILOGE("memset_s failed");
        free(saneValueBuf);
        saneValueBuf = nullptr;
        return E_SCAN_GENERIC_FAILURE;
    }

    status = sane_control_option(scannerHandle, optionIndex, SANE_ACTION_GET_VALUE, saneValueBuf, 0);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_control_option failed, reason: [%{public}s]", sane_strstatus(status));
        free(saneValueBuf);
        saneValueBuf = nullptr;
        return ScanUtil::ConvertErro(status);
    }

    if (valueType == SCAN_VALUE_NUM) {
        value.SetNumValue(*static_cast<int *>(saneValueBuf));
    } else if (valueType == SCAN_VALUE_NUM_LIST) {
        std::vector<int32_t> numListValue;
        for (int i = 0; i < valueSize; i++) {
            numListValue.emplace_back(*(static_cast<int32_t *>(saneValueBuf) + i));
        }
        value.SetNumListValue(numListValue);
    } else if (valueType == SCAN_VALUE_STR) {
        value.SetStrValue(*static_cast<std::string*>(saneValueBuf));
    } else if (valueType == SCAN_VALUE_BOOL) {
        value.SetBoolValue(*static_cast<int32_t *>(saneValueBuf) > 0 ? true : false);
    }

    free(saneValueBuf);
    saneValueBuf = nullptr;
    return E_SCAN_NONE;
}
#endif

#ifdef SANE_ENABLE
int32_t ScanServiceAbility::ActionSetValue(SANE_Handle &scannerHandle, ScanOptionValue &value,
    const int32_t &optionIndex, int32_t &info)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_SET_VALUE");
    SANE_Status status = SANE_STATUS_GOOD;
    int32_t valueSize = value.GetValueSize() / sizeof(SANE_Word);
    uint32_t bufSize = (value.GetStrValue().size() + 1)
        > sizeof(int) ? (value.GetStrValue().size() + 1) : sizeof(int);
    if (bufSize == 0 || bufSize > MAX_SANE_VALUE_LEN) {
        SCAN_HILOGE("malloc value buffer size error");
        return E_SCAN_GENERIC_FAILURE;
    }
    void* saneValueBuf = malloc(bufSize);
    if (!saneValueBuf) {
        SCAN_HILOGE("malloc value buffer failed");
        return E_SCAN_GENERIC_FAILURE;
    }
    if (memset_s(saneValueBuf, bufSize, 0, bufSize) != 0) {
        SCAN_HILOGE("memset_s failed");
        free(saneValueBuf);
        saneValueBuf = nullptr;
        return E_SCAN_GENERIC_FAILURE;
    }
    ScanOptionValueType valueType = value.GetScanOptionValueType();
    if (valueType == SCAN_VALUE_NUM) {
        int32_t numValue = value.GetNumValue();
        dpi = numValue > 0 && numValue < MAX_PICTURE_DPI ? numValue : 0;
        *static_cast<int *>(saneValueBuf) = value.GetNumValue();
    } else if (valueType == SCAN_VALUE_NUM_LIST) {
        std::vector<int32_t> numListValue;
        value.GetNumListValue(numListValue);
        for (int i = 0; i < valueSize; i++) {
            *(static_cast<int32_t *>(saneValueBuf) + i) = numListValue[i];
        }
    } else if (valueType == SCAN_VALUE_STR) {
        SCAN_HILOGE("Set scanner mode:[%{public}s]", value.GetStrValue().c_str());
        strncpy_s(static_cast<char*>(saneValueBuf), bufSize,
            value.GetStrValue().c_str(), value.GetStrValue().size());
    } else if (valueType == SCAN_VALUE_BOOL) {
        *static_cast<int32_t *>(saneValueBuf) = value.GetBoolValue() > 0 ? true : false;
    }
    status = sane_control_option(scannerHandle, optionIndex,
        SANE_ACTION_SET_VALUE, saneValueBuf, &info);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_control_option failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }

    free(saneValueBuf);
    saneValueBuf = nullptr;

    return E_SCAN_NONE;
}
#endif

int32_t ScanServiceAbility::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value, int32_t &info)
{
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start");
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("optionIndex [%{public}d]", optionIndex);
    int32_t state = E_SCAN_NONE;
#ifdef SANE_ENABLE
    if (g_hasIoFaild) {
        SCAN_HILOGI("OpScanOptionValue try to reOpenScanner start");
        int32_t openRet = OpenScanner(scannerId);
        if (openRet != E_SCAN_NONE) {
            SCAN_HILOGE("OpScanOptionValue try to reOpenScanner failed");
            return E_SCAN_DEVICE_BUSY;
        }
        g_hasIoFaild = false;
    }

    std::lock_guard<std::mutex> autoLock(lock_);

    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility OpScanOptionValue error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start to dump value");
    value.Dump();
    switch (op) {
        case SCAN_ACTION_SET_AUTO:
            state = ActionSetAuto(scannerHandle, optionIndex);
            break;
        case SCAN_ACTION_GET_VALUE:
            state = ActionGetValue(scannerHandle, value, optionIndex);
            break;
        case SCAN_ACTION_SET_VALUE:
            state = ActionSetValue(scannerHandle, value, optionIndex, info);
            break;
        default:
            SCAN_HILOGE("ScanServiceAbility OpScanOptionValue not find ScanOptionOpType");
            break;
    }

    if (state != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceAbility::OpScanOptionValue error exit");
    }

    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start to dump value");
    value.Dump();
#endif
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue end");
    return state;
}


int32_t ScanServiceAbility::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanParameters start");

#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility GetScanParameters error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    SANE_Parameters parameters;
    SANE_Status status = sane_get_parameters(scannerHandle, &parameters);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_get_parameters failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
    para.SetFormat((ScanFrame)parameters.format);
    para.SetLastFrame((bool)parameters.last_frame);
    para.SetBytesPerLine(parameters.bytes_per_line);
    para.SetPixelsPerLine(parameters.pixels_per_line);
    para.SetLines(parameters.lines);
    para.SetDepth(parameters.depth);
    para.Dump();
#endif
    SCAN_HILOGD("ScanServiceAbility GetScanParameters end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetSingleFrameFD start");

#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility GetSingleFrameFD error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
#ifdef SANE_ENABLE
    auto exeFrameFD = this->getSingleFrameFDExe;
    auto exe = [=]() {
        exeFrameFD(scannerHandle, fd);
    };
#endif
    serviceHandler_->PostTask(exe, ASYNC_CMD_DELAY);

#endif
    SCAN_HILOGD("ScanServiceAbility GetSingleFrameFD end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CancelScan(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan start");
#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle != nullptr) {
        SCAN_HILOGW("start sane_cancel");
        sane_cancel(scannerHandle);
    }
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    if (g_scannerState == SCANNER_SCANING) {
        SCAN_HILOGW("ScannerState change to SCANNER_CANCELING");
        g_scannerState = SCANNER_CANCELING;
    }
#endif
    SCAN_HILOGI("ScanServiceAbility CancelScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::SetScanIOMode(const std::string scannerId, const bool isNonBlocking)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility SetScanIOMode start");

#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility SetScanIOMode error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    SANE_Status status = sane_set_io_mode(scannerHandle, isNonBlocking);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_set_io_mode failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
#endif
    SCAN_HILOGE("ScanServiceAbility SetScanIOMode end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetScanSelectFd(const std::string scannerId, int32_t &fd)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanSelectFd start");

#ifdef SANE_ENABLE
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility GetScanSelectFd error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    SANE_Status status = sane_get_select_fd(scannerHandle, &fd);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_set_io_mode failed, reason: [%{public}s]", sane_strstatus(status));
        return ScanUtil::ConvertErro(status);
    }
#endif
    SCAN_HILOGE("ScanServiceAbility GetScanSelectFd end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    std::string eventType = type;
    if (taskId != "") {
        eventType = NapiScanUtils::GetTaskEventId(taskId, type);
    }
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }

    SCAN_HILOGD("ScanServiceAbility::On started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (registeredListeners_.find(eventType) == registeredListeners_.end()) {
        const auto temp = registeredListeners_.insert(std::make_pair(eventType, listener));
        if (!temp.second) {
            SCAN_HILOGE("ScanServiceAbility::On insert type=%{public}s object fail.", eventType.c_str());
            return E_SCAN_SERVER_FAILURE;
        }
    } else {
        SCAN_HILOGD("ScanServiceAbility::On Replace listener.");
        registeredListeners_[eventType] = listener;
    }
    SCAN_HILOGD("ScanServiceAbility::On end.");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::Off(const std::string taskId, const std::string &type)
{
    std::string eventType = type;
    if (taskId != "") {
        eventType = NapiScanUtils::GetTaskEventId(taskId, type);
    }
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }

    SCAN_HILOGD("ScanServiceAbility::Off started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter != registeredListeners_.end()) {
        SCAN_HILOGD("ScanServiceAbility::Off delete type=%{public}s object message.", eventType.c_str());
        registeredListeners_.erase(iter);
        return E_SCAN_NONE;
    }
    return E_SCAN_INVALID_PARAMETER;
}

void ScanServiceAbility::SendGetFrameResEvent(const bool isGetSucc, const int32_t sizeRead)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    SCAN_HILOGE("ScanServiceAbility::SendGetFrameSuccEvent SizeRead %{public}d", sizeRead);
    auto eventIt = registeredListeners_.find(GET_FRAME_RES_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnGetFrameResCallback(isGetSucc, sizeRead);
    } else {
        SCAN_HILOGE("%{public}s event not register", GET_FRAME_RES_EVENT_TYPE.c_str());
    }
}

void ScanServiceAbility::SendDeviceInfoTCP(const ScanDeviceInfoTCP &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoTCP parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGI("GetScannerListSendDeviceInfoTCP event has registered");
        eventIt->second->OnCallback(info.GetDeviceState(), info);
    } else {
        SCAN_HILOGE("GetScannerList SendDeviceInfoTCP event not register");
    }
}

void ScanServiceAbility::SendDeviceInfo(const ScanDeviceInfo &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGI("GetScannerList SendDeviceInfo event has registered");
        eventIt->second->OnCallback(info.GetDeviceState(), info);
    } else {
        SCAN_HILOGE("GetScannerList SendDeviceInfo event not register");
    }
}

void ScanServiceAbility::SendDeviceList(std::vector<ScanDeviceInfo> &infos, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGE("GetScannerList SendDeviceList event has registered");
        eventIt->second->OnGetDevicesList(infos);
    } else {
        SCAN_HILOGE("GetScannerList SendDeviceList event not register");
    }
}

void ScanServiceAbility::SendDeviceInfoSync(const ScanDeviceInfoSync &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoSync parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGI("DealUsbDevStatusChange SendDeviceInfoSync event has registered");
            eventIt->second->OnCallbackSync(info.GetDeviceState(), info);
    } else {
        SCAN_HILOGE("DealUsbDevStatusChange SendDeviceInfoSync event not register");
    }
}

void ScanServiceAbility::DisConnectUsbScanner(std::string serialNumber, std::string deviceId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    SCAN_HILOGD("DisConnectUsbScanner start deviceId:%{public}s", deviceId.c_str());
    ScanDeviceInfoSync scanDeviceInfoSync;
    scanDeviceInfoSync.serialNumber = serialNumber;
    scanDeviceInfoSync.deviceId = deviceId;
    scanDeviceInfoSync.discoverMode = "USB";
    scanDeviceInfoSync.syncMode = "delete";
    scanDeviceInfoSync.deviceState = 0;
    SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("GetScannerList delete end serialNumber:%{public}s newDeviceId:%{public}s",
                serialNumber.c_str(), deviceId.c_str());
#endif
}

void ScanServiceAbility::UpdateUsbScannerId(std::string serialNumber, std::string newDeviceId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    SCAN_HILOGD("UpdateUsbScannerId start newDeviceId:%{public}s", newDeviceId.c_str());
    ScanDeviceInfoSync scanDeviceInfoSync;
    scanDeviceInfoSync.serialNumber = serialNumber;
    scanDeviceInfoSync.deviceId = newDeviceId;
    scanDeviceInfoSync.discoverMode = "USB";
    scanDeviceInfoSync.syncMode = "update";
    scanDeviceInfoSync.deviceState = 0;
    std::lock_guard<std::mutex> autoLock(clearMapLock_);
    auto it = saneGetUsbDeviceInfoMap.find(serialNumber);
    if (it != saneGetUsbDeviceInfoMap.end()) {
        saneGetUsbDeviceInfoMap[serialNumber].deviceId = newDeviceId;
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    }
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("GetScannerList UpdateUsbScannerId serialNumber:%{public}s newDeviceId:%{public}s",
                serialNumber.c_str(), newDeviceId.c_str());
#endif
}

void ScanServiceAbility::SendInitEvent(int32_t &scanVersion, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendInitEvent parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGE("InitScan SendInitEvent event has registered");
        eventIt->second->OnScanInitCallback(scanVersion);
    } else {
        SCAN_HILOGE("InitScan SendInitEvent event not register");
    }
}

void ScanServiceAbility::SendDeviceSearchEnd(std::string &message, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (message.empty() || event.empty()) {
        SCAN_HILOGE("SendDeviceSearchEnd parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt != registeredListeners_.end()) {
        SCAN_HILOGD("SCAN_DEVICE_FOUND event has registered");
        if (!(eventIt->second)) {
            SCAN_HILOGE("eventIt null ptr error");
            return;
        }
        eventIt->second->OnSendSearchMessage(message);
    } else {
        SCAN_HILOGE("SCAN_DEVICE_FOUND event not register");
    }
}

bool ScanServiceAbility::CheckPermission(const std::string &permissionName)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        SCAN_HILOGE("invalid token id");
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (result != PERMISSION_GRANTED) {
        if (permissionName == PERMISSION_NAME_PRINT) {
            result = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NAME_PRINT_JOB);
        }
        SCAN_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
}

int32_t ScanServiceAbility::GetScannerState(int32_t &scannerState)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScannerState start");
    scannerState = g_scannerState;
    SCAN_HILOGD("ScanServiceAbility GetScannerState end, scannerState = [%{public}d]", scannerState);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility GetScanProgress start");

#ifdef SANE_ENABLE
    if (scanQueue.empty()) {
        SCAN_HILOGE("Not exist scan progress");
        if (g_hasIoFaild) {
            return E_SCAN_INVALID_PARAMETER;
        }
        return E_SCAN_GENERIC_FAILURE;
    }
    int32_t frontPicId = scanQueue.front();
    SCAN_HILOGD("frontPicId : [%{public}d]", frontPicId);
    auto frontProg = scanTaskMap[frontPicId];
    auto taskCode = frontProg.GetTaskCode();
    if (taskCode != E_SCAN_GOOD) {
        SCAN_HILOGE("scanprogress exception occurred:[%{public}u]", taskCode);
        scanQueue.pop();
        return taskCode;
    }
    auto scanProgress = frontProg.GetScanProgress();
    if (scanProgress == SCAN_PROGRESS_100) {
        SCAN_HILOGE("get scan picture successfully!");
        prog = frontProg;
        prog.Dump();
        scanQueue.pop();
        return E_SCAN_NONE;
    }
    auto nowTime = std::chrono::steady_clock::now();
    auto preTime = scanTaskMap[frontPicId].GetScanTime();
    auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(nowTime - preTime);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(SCAN_PROGRESS_10, SCAN_PROGRESS_19);
    int32_t randomNumber = dis(gen);
    if (elapsedTime.count() >= 1 && scanProgress < SCAN_PROGRESS_80) {
        scanTaskMap[frontPicId].SetScanProgress(scanProgress + randomNumber);
        scanTaskMap[frontPicId].SetScanTime(nowTime);
    }
    prog = scanTaskMap[frontPicId];
    prog.Dump();
#endif
    SCAN_HILOGI("ScanServiceAbility GetScanProgress end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (discoverMode != "USB" && discoverMode != "TCP") {
        SCAN_HILOGE("discoverMode is a invalid parameter.");
        return E_SCAN_INVALID_PARAMETER;
    }
    auto addScannerExe = [=]() {
#ifdef SANE_ENABLE
        std::string uniqueId = discoverMode + serialNumber;
        ScanSystemData &scanData = ScanSystemData::GetInstance();
        std::lock_guard<std::mutex> autoLock(clearMapLock_);
        if (discoverMode == "USB") {
            auto usbIt = saneGetUsbDeviceInfoMap.find(serialNumber);
            if (usbIt == saneGetUsbDeviceInfoMap.end() || scanData.IsContainScanner(uniqueId)) {
                SCAN_HILOGE("Failed to add usb scanner.");
                return;
            }
            scanData.InsertScannerInfo(uniqueId, usbIt->second);
            if (!scanData.SaveScannerMap()) {
                SCAN_HILOGE("ScanServiceAbility AddScanner SaveScannerMap fail");
                return;
            }
            SendDeviceInfo(usbIt->second, SCAN_DEVICE_ADD);
        } else if (discoverMode == "TCP") {
            auto tcpIt = saneGetTcpDeviceInfoMap.find(serialNumber);
            if (tcpIt == saneGetTcpDeviceInfoMap.end() || scanData.IsContainScanner(uniqueId)) {
                SCAN_HILOGE("Failed to add tcp scanner.");
                return;
            }
            scanData.InsertScannerInfo(uniqueId, tcpIt->second);
            if (!scanData.SaveScannerMap()) {
                SCAN_HILOGE("ScanServiceAbility AddScanner SaveScannerMap fail");
                return;
            }
            SendDeviceInfo(tcpIt->second, SCAN_DEVICE_ADD);
        } else {
            SCAN_HILOGE("discoverMode is invalid.");
        }
#endif
    };
    serviceHandler_->PostTask(addScannerExe, ASYNC_CMD_DELAY);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility DeleteScanner start");

#ifdef SANE_ENABLE
    std::string uniqueId = discoverMode + serialNumber;
    ScanDeviceInfo scannerInfo;
    if (!ScanSystemData::GetInstance().QueryScannerInfoByUniqueId(uniqueId, scannerInfo)) {
        SCAN_HILOGE("ScanServiceAbility DeleteScanner QueryScannerInfoByUniqueId fail");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (!ScanSystemData::GetInstance().DeleteScannerInfo(uniqueId)) {
        SCAN_HILOGE("ScanServiceAbility DeleteScanner DeleteScannerInfo fail");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (!ScanSystemData::GetInstance().SaveScannerMap()) {
        SCAN_HILOGE("ScanServiceAbility DeleteScanner SaveScannerMap fail");
        return E_SCAN_GENERIC_FAILURE;
    }
    SendDeviceInfo(scannerInfo, SCAN_DEVICE_DEL);
#endif
    SCAN_HILOGI("ScanServiceAbility DeleteScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner start");
#ifdef SANE_ENABLE
    ScanSystemData::GetInstance().GetAddedScannerInfoList(allAddedScanner);
#endif
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::UpdateScannerName(const std::string& serialNumber,
    const std::string& discoverMode, const std::string& deviceName)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility UpdateScannerName start");

#ifdef SANE_ENABLE
    std::string uniqueId = discoverMode + serialNumber;
    if (!ScanSystemData::GetInstance().UpdateScannerNameByUniqueId(uniqueId, deviceName)) {
        SCAN_HILOGE("ScanServiceAbility UpdateScannerNameByUniqueId fail");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (!ScanSystemData::GetInstance().SaveScannerMap()) {
        SCAN_HILOGE("ScanServiceAbility UpdateScannerName SaveScannerMap fail");
        return E_SCAN_GENERIC_FAILURE;
    }
#endif
    SCAN_HILOGI("ScanServiceAbility UpdateScannerName end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::OnStartScan(const std::string scannerId, const bool &batchMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    int32_t status = StartScan(scannerId, batchMode_);
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("Start Scan error");
        return status;
    }
    batchMode_ = batchMode;
    g_scannerState = SCANNER_SCANING;
    auto exe = [=]() {
        StartScanTask(scannerId);
    };
    serviceHandler_->PostTask(exe, ASYNC_CMD_DELAY);
    SCAN_HILOGI("StartScan successfully");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StartScan(const std::string scannerId, const bool &batchMode)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility StartScan start");

#ifdef SANE_ENABLE
    if (g_scannerState == SCANNER_CANCELING) {
        SCAN_HILOGE("scan task is canceling");
        return E_SCAN_DEVICE_BUSY;
    }
    auto scannerHandle = GetScanHandle(scannerId);
    if (scannerHandle == nullptr) {
        SCAN_HILOGE("ScanServiceAbility StartScan error exit");
        return E_SCAN_INVALID_PARAMETER;
    }
    SANE_Status saneStatus = sane_start(scannerHandle);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_start failed, reason: [%{public}s], sane sane_cancel start", sane_strstatus(saneStatus));
        sane_cancel(scannerHandle);
        auto it = scanTaskMap.find(nextPicId);
        if (it != scanTaskMap.end() && it != scanTaskMap.begin()) {
            it--;
            (it->second).SetScanProgress(SCAN_PROGRESS_100);
        }
        return ScanUtil::ConvertErro(saneStatus);
    }
    ScanProgress prog;
    scanTaskMap[nextPicId] = prog;
    scanQueue.push(nextPicId);
    scanTaskMap[nextPicId].SetPictureId(nextPicId);
    auto nowTime = std::chrono::steady_clock::now();
    scanTaskMap[nextPicId].SetScanTime(nowTime);
    nextPicId++;
#endif
    SCAN_HILOGI("ScanServiceAbility StartScan end");
    return E_SCAN_NONE;
}

void ScanServiceAbility::StartScanTask(const std::string scannerId)
{
    SCAN_HILOGI("ScanServiceAbility StartScanTask start, batchMode_ = [%{public}d]", batchMode_);
    int32_t status = E_SCAN_NONE;
    std::string file_name;
    std::string output_file;
    ScanProgress* scanProPtr = nullptr;
    if (batchMode_) {
        SCAN_HILOGI("start batch mode scan");
        GeneratePictureBatch(scannerId, file_name, output_file, status, scanProPtr);
    } else {
        SCAN_HILOGI("start single mode scan");
        GeneratePictureSingle(scannerId, file_name, output_file, status, scanProPtr);
    }
    if (status != E_SCAN_NONE) {
        SCAN_HILOGI("ScanServiceAbility StartScanTask error, errorcode = [%{public}d]", status);
    }
    g_scannerState = SCANNER_READY;
    SCAN_HILOGI("ScanServiceAbility StartScanTask end");
}

void ScanServiceAbility::GeneratePictureBatch(const std::string &scannerId, std::string &file_name,
    std::string &output_file, int32_t &status, ScanProgress* &scanProPtr)
{
    bool firstScan = true;
    do {
        if (!firstScan) {
            SCAN_HILOGE("not first scan");
            status = StartScan(scannerId, batchMode_);
            if (status != E_SCAN_NONE) {
                SCAN_HILOGE("ScanTask restart fail");
                break;
            }
            auto it = scanTaskMap.find(nextPicId - 2); // nextPicId - 2 is to find a PicId before nowScanId.
            (it->second).SetIsFinal(false);
            it->second.SetScanProgress(SCAN_PROGRESS_100);
            SCAN_HILOGE("ScanTask restart success, status:[%{public}d]", status);
        }
        auto it = scanTaskMap.find(nextPicId - 1);
        int32_t nowScanId = it->first;
        SCAN_HILOGI("scanQueue.size:[%{public}lu], scanTaskMap.size:[%{public}lu]",
            static_cast<unsigned long>(scanQueue.size()), static_cast<unsigned long>(scanTaskMap.size()));
        SCAN_HILOGI("nowScanId :[%{public}d], nextPicId: [%{public}d]", nowScanId, nextPicId);
        file_name = "scan_tmp"+ std::to_string(nowScanId) +".jpg";
        std::string outputDir = "/data/service/el2/public/print_service/sane/tmp/";
        output_file = outputDir.append(file_name);
        ofp = fopen(output_file.c_str(), "w");
        if (ofp == nullptr) {
            SCAN_HILOGE("file [%{public}s] open fail", output_file.c_str());
            return ;
        }
        SCAN_HILOGI("create picture file [%{public}s] open", output_file.c_str());
        scanProPtr = &(scanTaskMap[nowScanId]);
#ifdef SANE_ENABLE
        status = DoScanTask(scannerId, scanProPtr);
#endif
        SCAN_HILOGE("ScanTask status:[%{public}d]", status);
        auto fd = open(output_file.c_str(), O_RDONLY);
        scanProPtr->SetScanPictureFd(fd);
        firstScan = false;
    } while (status == E_SCAN_EOF);
    if (status == E_SCAN_NO_DOCS) {
        auto it = scanTaskMap.find(nextPicId - 1);
        it->second.SetScanProgress(SCAN_PROGRESS_100);
        SCAN_HILOGI("ScanTask batch mode exit successfully [%{public}d]", status);
    } else {
        SCAN_HILOGE("ScanTask error exit[%{public}d]", status);
    }
}

void ScanServiceAbility::GeneratePictureSingle(const std::string &scannerId, std::string &file_name,
    std::string &output_file, int32_t &status, ScanProgress* &scanProPtr)
{
    auto it = scanTaskMap.find(nextPicId - 1);
    int32_t nowScanId = it->first;
    SCAN_HILOGI("scanQueue.size:[%{public}lu], scanTaskMap.size:[%{public}lu]",
        static_cast<unsigned long>(scanQueue.size()), static_cast<unsigned long>(scanTaskMap.size()));
    SCAN_HILOGI("nowScanId :[%{public}d], nextPicId: [%{public}d]", nowScanId, nextPicId);
    file_name = "scan_tmp"+ std::to_string(nowScanId) +".jpg";
    std::string outputDir = "/data/service/el2/public/print_service/sane/tmp/";
    output_file = outputDir.append(file_name);
    ofp = fopen(output_file.c_str(), "w");
    if (ofp == nullptr) {
        SCAN_HILOGE("file [%{public}s] open fail", output_file.c_str());
        return ;
    }
    SCAN_HILOGI("create picture file [%{public}s] open", output_file.c_str());
    scanProPtr = &(scanTaskMap[nowScanId]);
#ifdef SANE_ENABLE
    status = DoScanTask(scannerId, scanProPtr);
#endif
    SCAN_HILOGE("ScanTask status:[%{public}d]", status);
    if (status == E_SCAN_EOF) {
        auto fd = open(output_file.c_str(), O_RDONLY);
        scanProPtr->SetScanPictureFd(fd);
        scanProPtr->SetScanProgress(SCAN_PROGRESS_100);
    } else {
        SCAN_HILOGE("ScanTask error exit[%{public}d]", status);
    }
    if (ofp) {
        fclose(ofp);
        ofp = NULL;
    }
    {
#ifdef SANE_ENABLE
        std::lock_guard<std::mutex> autoLock(lock_);
        SANE_Handle scannerHandle = GetScanHandle(scannerId);
        if (scannerHandle != nullptr) {
            SCAN_HILOGI("GeneratePictureSingle finished, doing sane_cancel");
            sane_cancel(scannerHandle);
        }
#endif
    }
}

#ifdef SANE_ENABLE
int32_t ScanServiceAbility::DoScanTask(const std::string scannerId, ScanProgress* scanProPtr)
{
    int32_t first_frame = 1;
    int32_t scanStatus = E_SCAN_NONE;
    ScanParameters parm;
    struct jpeg_error_mgr jerr;
    do {
        SCAN_HILOGI("start DoScanTask");
        if (!first_frame) {
            scanStatus = StartScan(scannerId, batchMode_);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGE("StartScanTask error exit after StartScan");
                return scanStatus;
            }
        }
        scanStatus = GetScanParameters(scannerId, parm);
        if (scanStatus != E_SCAN_NONE) {
            SCAN_HILOGE("cyclicCallExe error exit after GetScanParameters");
            return scanStatus;
        }
        if (first_frame) {
            scanStatus = WriteJpegHeader(parm, &jerr);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGE("StartScanTask error exit after WriteJpegHeader");
                return scanStatus;
            }
            jpegbuf = (JSAMPLE*)malloc(parm.GetBytesPerLine());
            if (jpegbuf == nullptr) {
                SCAN_HILOGE("jpegbuf malloc fail");
                return E_SCAN_GENERIC_FAILURE;
            }
        }
        GetPicFrame(scannerId, scanProPtr, scanStatus, parm);
        if (g_scannerState == SCANNER_CANCELING) {
            SCAN_HILOGE("DoScanTask cancel");
            FREE_AND_NULLPTR(jpegbuf)
            return E_SCAN_NONE;
        }
        if (scanStatus != E_SCAN_GOOD && scanStatus != E_SCAN_EOF) {
            SCAN_HILOGE("get scanframe fail");
            FREE_AND_NULLPTR(jpegbuf)
            return E_SCAN_NONE;
        }
        first_frame = 0;
    } while (!(parm.GetLastFrame()));
    jpeg_finish_compress(cinfoPtr);
    fflush(ofp);
    FREE_AND_NULLPTR(jpegbuf)
    SCAN_HILOGI("end DoScanTask");
    return scanStatus;
}
#endif

int32_t ScanServiceAbility::WriteJpegHeader(ScanParameters &parm, struct jpeg_error_mgr* jerr)
{
    ScanFrame format = parm.GetFormat();
    int32_t width = parm.GetPixelsPerLine();
    int32_t height = parm.GetLines();
    cinfoPtr->err = jpeg_std_error(jerr);
    cinfoPtr->err->error_exit = [](j_common_ptr cinfo) {
        g_isJpegWriteSuccess = false;
    };
    g_isJpegWriteSuccess = true;
    jpeg_create_compress(cinfoPtr);
    jpeg_stdio_dest(cinfoPtr, ofp);

    cinfoPtr->image_width = (JDIMENSION)width;
    cinfoPtr->image_height = (JDIMENSION)height;
    if (format == SCAN_FRAME_RGB) {
        cinfoPtr->in_color_space = JCS_RGB;
        cinfoPtr->input_components = CHANNEL_THREE;
        SCAN_HILOGI("generate RGB picture");
    } else if (format == SCAN_FRAME_GRAY) {
        cinfoPtr->in_color_space = JCS_GRAYSCALE;
        cinfoPtr->input_components = CHANNEL_ONE;
        SCAN_HILOGI("generate gray picture");
    } else {
        SCAN_HILOGE("not support this color");
        return E_SCAN_INVALID_PARAMETER;
    }
    jpeg_set_defaults(cinfoPtr);
    cinfoPtr->density_unit = 1;
    cinfoPtr->X_density = dpi;
    cinfoPtr->Y_density = dpi;
    cinfoPtr->write_JFIF_header = TRUE;
    SCAN_HILOGI("width:[%{public}d],height:[%{public}d],dpi:[%{public}d]", width, height, dpi);
    jpeg_set_quality(cinfoPtr, JPEG_QUALITY_SEVENTY_FIVE, TRUE);
    jpeg_start_compress(cinfoPtr, TRUE);
    SCAN_HILOGI("finish write jpegHeader");
    return E_SCAN_NONE;
}

void ScanServiceAbility::CleanScanTask(const std::string &scannerId)
{
    CancelScan(scannerId);
    scanTaskMap.clear();
    g_hasIoFaild = true;
}

#ifdef SANE_ENABLE
void ScanServiceAbility::GetPicFrame(const std::string scannerId, ScanProgress *scanProPtr,
    int32_t &scanStatus, ScanParameters &parm)
{
    int32_t curReadSize = 0;
    int64_t totalBytes = 0;
    int jpegrow = 0;
    SANE_Handle scannerHandle = GetScanHandle(scannerId);
    int64_t hundred_percent = ((int64_t)parm.GetBytesPerLine()) * parm.GetLines() * (((SANE_Frame)parm.GetFormat()
        == SANE_FRAME_RGB || (SANE_Frame)parm.GetFormat() == SANE_FRAME_GRAY) ?  CHANNEL_ONE : CHANNEL_THREE);
    if (hundred_percent == 0) {
        scanStatus = E_SCAN_INVAL;
        return;
    }
    while (true) {
        SANE_Status saneStatus = sane_read(scannerHandle, saneReadBuf, buffer_size, &curReadSize);
        scanStatus = ScanUtil::ConvertErro(saneStatus);
        totalBytes += (int64_t)curReadSize;
        int64_t progr = ((totalBytes * SCAN_PROGRESS_100) / hundred_percent);
        if (progr >= SCAN_PROGRESS_100)
            progr = SCAN_PROGRESS_100 - 1;
        if (progr > (scanProPtr->GetScanProgress())) {
            scanProPtr->SetScanProgress((int32_t)progr);
        }
        SCAN_HILOGI(" %{public}lld bytes ; scan progr:%{public}lld", totalBytes, progr);
        if (g_scannerState == SCANNER_CANCELING) {
            std::queue<int32_t> emptyQueue;
            scanQueue.swap(emptyQueue);
            nextPicId--;
            scanTaskMap.erase(nextPicId);
            scanStatus = E_SCAN_NONE;
            SCAN_HILOGE("scan task is canceled");
            return;
        }
        if (saneStatus == SANE_STATUS_EOF) {
            SCAN_HILOGI("Totally read %{public}lld bytes of frame data", totalBytes);
            break;
        }
        if (saneStatus != SANE_STATUS_GOOD) {
            SCAN_HILOGE("sane_read failed, reason: [%{public}s]", sane_strstatus(saneStatus));
            ScanErrorCode taskCode = ScanUtil::ConvertErro(saneStatus);
            scanProPtr->SetTaskCode(taskCode);
            if (taskCode == E_SCAN_IO_ERROR) {
                CleanScanTask(scannerId);
            }
            break;
        }

        if (!WritePicData(jpegrow, curReadSize, parm, scanProPtr)) {
            SCAN_HILOGI("WritePicData fail");
            return;
        }
    }
}
#endif

bool ScanServiceAbility::WritePicData(int &jpegrow, int32_t curReadSize, ScanParameters &parm, ScanProgress *scanProPtr)
{
    SCAN_HILOGI("start write jpeg picture data");
    constexpr int bit = 1;
    int i = 0;
    int left = curReadSize;
    while (jpegrow + left >= parm.GetBytesPerLine()) {
        if (!g_isJpegWriteSuccess) {
            scanProPtr->SetTaskCode(E_SCAN_NO_MEM);
            return false;
        }
        int ret = memcpy_s(jpegbuf + jpegrow, parm.GetBytesPerLine(),
            saneReadBuf + i, parm.GetBytesPerLine() - jpegrow);
        if (ret != ERR_OK) {
            scanProPtr->SetTaskCode(E_SCAN_GENERIC_FAILURE);
            SCAN_HILOGE("memcpy_s failed");
            return false;
        }
        if (parm.GetDepth() != 1) {
            jpeg_write_scanlines(cinfoPtr, &jpegbuf, bit);
            i += parm.GetBytesPerLine() - jpegrow;
            left -= parm.GetBytesPerLine() - jpegrow;
            jpegrow = 0;
            continue;
        }
        constexpr int byteBits = 8;
        JSAMPLE *buf8 = (JSAMPLE *)malloc(parm.GetBytesPerLine() * byteBits);
        if (buf8 == nullptr) {
            scanProPtr->SetTaskCode(E_SCAN_GENERIC_FAILURE);
            SCAN_HILOGE("pic buffer malloc fail");
            return false;
        }
        for (int col1 = 0; col1 < parm.GetBytesPerLine(); col1++) {
            for (int col8 = 0; col8 < byteBits; col8++) {
                buf8[col1 * byteBits + col8] = jpegbuf[col1] & (1 << (byteBits - col8 - 1)) ? 0 : 0xff;
                jpeg_write_scanlines(cinfoPtr, &buf8, byteBits);
            }
        }
        free(buf8);
        i += parm.GetBytesPerLine() - jpegrow;
        left -= parm.GetBytesPerLine() - jpegrow;
        jpegrow = 0;
    }
    if (memcpy_s(jpegbuf + jpegrow, parm.GetBytesPerLine(), saneReadBuf + i, left) != ERR_OK) {
        SCAN_HILOGE("memcpy_s failed");
        return false;
    }
    jpegrow += left;
    SCAN_HILOGI("finish write jpeg picture data");
    return true;
}
}  // namespace OHOS::Scan