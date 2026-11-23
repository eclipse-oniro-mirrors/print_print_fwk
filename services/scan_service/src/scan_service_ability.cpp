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

#include <ctime>
#include <string>
#include <sys/time.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <regex>

#include "print_json_util.h"
#include "image_exporter.h"
#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "file_ex.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "scan_service_utils.h"
#include "tofu_cert_store.h"
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
#include "media_errors.h"
#include "scan_system_data.h"
#include "sane_manager_client.h"
#include "sane_option_descriptor.h"
#include "sane_device.h"
#include "sane_control_param.h"
#include "sane_picture_data.h"
#include "scan_log.h"
#include "os_account_manager.h"
#include "saneopts.h"
#include "caller_app_monitor.h"
#include "escl_driver_manager.h"
#include "ability_manager_adapter.h"
#include "scan_ability_connection.h"
#include "want.h"

namespace OHOS::Scan {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using SteadyTimePoint = std::chrono::steady_clock::time_point;

const int64_t INIT_INTERVAL = 5000L;
const uint32_t ASYNC_CMD_DELAY = 10;
constexpr int32_t MAX_SCANNER_PARA_COUNT = 1000;
constexpr uint32_t CERT_DIALOG_MAX_RETRY_TIMES = 2;
constexpr int32_t CERT_DIALOG_RETRY_INTERVAL_MS = 200;
// Reclaim the single dialog slot if the ability never reports connected.
constexpr int32_t CERT_DIALOG_LAUNCH_TIMEOUT_MS = 10000;

static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_JOB = "ohos.permission.MANAGE_PRINT_JOB";
static const std::string SCAN_DEVICE_FOUND_TCP = "scanDeviceFoundTCP";
static const std::string SCAN_DEVICE_FOUND = "scanDeviceFound";
static const std::string SCAN_DEVICE_SYNC = "scanDeviceSync";
static const std::string SCAN_DEVICE_ADD = "scanDeviceAdd";
static const std::string SCAN_DEVICE_DEL = "scanDeviceDel";
static const std::string SCAN_INIT_EVENT = "scanInitEvent";

static const std::string DEVICE_EVENT_TYPE = "deviceStateChange";
static const std::string GET_SCANNER_DEVICE_LIST = "GET_SCANNER_DEVICE_LIST";

static const std::unordered_map<std::string, std::string> SCAN_PERMISSION_MAP = {
    {SCAN_DEVICE_FOUND, PERMISSION_NAME_PRINT},
    {SCAN_DEVICE_SYNC, PERMISSION_NAME_PRINT},
    {SCAN_DEVICE_ADD, PERMISSION_NAME_PRINT_JOB},
    {SCAN_DEVICE_DEL, PERMISSION_NAME_PRINT_JOB},
    {GET_SCANNER_DEVICE_LIST, PERMISSION_NAME_PRINT}};

std::map<std::string, sptr<IScanCallback>> OHOS::Scan::ScanServiceAbility::registeredListeners_;

namespace {
std::string GenerateSessionId()
{
    // Generational token, not a secret; SA-lifetime uniqueness suffices.
    static std::atomic<uint64_t> sessionCounter{0};
    uint64_t id = ++sessionCounter;
    return std::to_string(id);
}
} // namespace

REGISTER_SYSTEM_ABILITY_BY_ID(ScanServiceAbility, SCAN_SERVICE_ID, true);

std::mutex ScanServiceAbility::instanceLock_;
sptr<ScanServiceAbility> ScanServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> ScanServiceAbility::serviceHandler_;

ScanServiceAbility::ScanServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{}

ScanServiceAbility::~ScanServiceAbility()
{
    SCAN_HILOGD("~ScanServiceAbility state_  is %{public}d.", static_cast<int>(state_.load()));
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
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(ScanServiceAbility::GetInstance());
    if (!ret) {
        SCAN_HILOGE("ScanServiceAbility Publish failed.");
        state_ = ServiceRunningState::STATE_NOT_START;
        return E_SCAN_SERVER_FAILURE;
    }
    SCAN_HILOGD("state_ is %{public}d.", static_cast<int>(state_.load()));
    SCAN_HILOGI("Init ScanServiceAbility success.");
    return ERR_OK;
}

void ScanServiceAbility::OnStart()
{
    SCAN_HILOGI("ScanServiceAbility::Enter OnStart.");
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = this;
        }
    }
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        SCAN_HILOGI("ScanServiceAbility is already running.");
        return;
    }

    InitServiceHandler();
    InitializeScanService();
    
    scanPictureData_.CleanDiskCache();
    
    CallerAppMonitor::GetInstance().StartCallerAppMonitor(
        [this]() { this->UnloadSystemAbility(); },
        [this](int32_t deadPid) { this->CleanupDeadCaller(deadPid); });
    int32_t ret = ServiceInit();
    if (ret != ERR_OK) {
        auto callback = [=]() { ServiceInit(); };
        std::shared_ptr<AppExecFwk::EventHandler> handler;
        {
            std::lock_guard<std::recursive_mutex> lock(apiMutex_);
            handler = serviceHandler_;
        }
        if (handler != nullptr) {
            handler->PostTask(callback, INIT_INTERVAL);
            SCAN_HILOGE("ScanServiceAbility Init failed. Try again 5s later");
        } else {
            SCAN_HILOGE("ScanServiceAbility Init failed and serviceHandler_ is nullptr");
        }
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
    CallerAppMonitor::GetInstance().QueryCallerAppAndSave();
}

void ScanServiceAbility::OnStop()
{
    SCAN_HILOGI("OnStop started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        SCAN_HILOGW("service is not running");
        return;
    }
    DestroyCertDialogIfActive();
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        serviceHandler_ = nullptr;
    }
    state_ = ServiceRunningState::STATE_NOT_START;
    SCAN_HILOGI("OnStop end.");
}

void ScanServiceAbility::UnloadSystemAbility()
{
    CleanupScanService();
    SaneManagerClient::GetInstance().UnloadSystemAbility();
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        SCAN_HILOGE("get samgr failed");
        return;
    }
    int32_t ret = samgrProxy->UnloadSystemAbility(SCAN_SERVICE_ID);
    if (ret != ERR_OK) {
        SCAN_HILOGE("unload scan_service failed");
        return;
    }
    SCAN_HILOGI("unload scan_service successfully");
}

int32_t ScanServiceAbility::InitScan()
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ExitScan()
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    // Defer cleanup to scan-task end if this caller's scan is still running.
    if (openedScanner_.has_value() && openedScanner_->callerPid == callerPid) {
        if (scannerState_.load() != SCANNER_READY) {
            pendingCleanOwner_ = callerPid;
        }
        if (int32_t ret = CloseScanner(openedScanner_->scannerId); ret != E_SCAN_NONE) {
            SCAN_HILOGW("ExitScan CloseScanner failed: %{public}d, continue cleanup", ret);
        }
    }
    // Clean now unless deferred (also no-ops a wind-down-window re-entry).
    if (pendingCleanOwner_ != callerPid) {
        scanPictureData_.CleanByOwner(callerPid);
    }
    return E_SCAN_NONE;
}

void ScanServiceAbility::InitializeScanService()
{
    SaneManagerClient::GetInstance().SaneInit();
    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    ScanSystemData::GetInstance().Init();
    EsclDriverManager::InitializeEsclScannerDriver();
}

void ScanServiceAbility::CleanupScanService()
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (openedScanner_.has_value()) {
        SaneManagerClient::GetInstance().SaneCancel(openedScanner_->scannerId);
        SaneManagerClient::GetInstance().SaneClose(openedScanner_->scannerId);
    }
    openedScanner_.reset();
    colorModeSettings_.clear();
    SaneManagerClient::GetInstance().SaneExit();
    ScanMdnsService::GetInstance().OnStopDiscoverService();
    {
        std::lock_guard<std::mutex> lock(discoverMutex_);
        rediscoverPending_ = false;
        discoverInProgress_ = false;
    }
    scannerState_.store(SCANNER_READY);
    scanPictureData_.CleanAllCache();
    DestroyCertDialogIfActive();
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        SCAN_HILOGI("clear registeredListeners_ on service cleanup, size=%{public}zu",
                    registeredListeners_.size());
        registeredListeners_.clear();
    }
}

bool ScanServiceAbility::GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId)
{
    constexpr size_t TOKEN_SIZE_FOUR = 4;
    std::vector<std::string> tokens = ScanServiceUtils::ExtractIpOrPortFromUrl(deviceId, ':', TOKEN_SIZE_FOUR);
    if (tokens.empty()) {
        SCAN_HILOGE("split [%{private}s] fail ", deviceId.c_str());
        return false;
    }
    constexpr size_t STRING_POS_ONE = 1;
    constexpr size_t STRING_POS_TWO = 2;
    constexpr size_t STRING_POS_THREE = 3;
    if (tokens[STRING_POS_ONE] != "libusb") {
        SCAN_HILOGE("parse [%{private}s] fail", deviceId.c_str());
        return false;
    }
    static const std::regex pattern(R"(([0-9]{3}))");
    if (!std::regex_match(tokens[STRING_POS_TWO], pattern) ||
        !std::regex_match(tokens[STRING_POS_THREE], pattern)) {
        SCAN_HILOGE("parse [%{private}s]:[%{private}s] fail", tokens[STRING_POS_TWO].c_str(),
                    tokens[STRING_POS_THREE].c_str());
        return false;
    }
    int32_t firstNumTmp = 0;
    int32_t secondNumTmp = 0;
    const std::string firstIdTmp = tokens[STRING_POS_TWO];
    const std::string secondIdTmp = tokens[STRING_POS_THREE];
    if (!ScanUtil::ConvertToInt(firstIdTmp, firstNumTmp) ||
        !ScanUtil::ConvertToInt(secondIdTmp, secondNumTmp)) {
        SCAN_HILOGE("parse [%{private}s]:[%{private}s] fail", firstIdTmp.c_str(), secondIdTmp.c_str());
        return false;
    }
    firstId = std::to_string(firstNumTmp);
    secondId = std::to_string(secondNumTmp);
    return true;
}

bool ScanServiceAbility::GetTcpDeviceIp(const std::string &deviceId, std::string &ip)
{
    constexpr size_t TOKEN_SIZE_TWO = 2;
    std::vector <std::string> tokens = ScanServiceUtils::ExtractIpOrPortFromUrl(deviceId, ' ', TOKEN_SIZE_TWO);
    if (tokens.empty()) {
        SCAN_HILOGE("split [%{private}s] fail ", deviceId.c_str());
        return false;
    }
    constexpr size_t STRING_POS_ONE = 1;
    std::string rawIp = tokens[STRING_POS_ONE];
    static const std::regex pattern(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    std::smatch match;
    if (std::regex_match(rawIp, match, pattern)) {
        constexpr size_t STRING_POS_ZERO = 0;
        ip = match[STRING_POS_ZERO];
        return true;
    } else {
        SCAN_HILOGE("In TCP mode, the deviceId string format does not match, ip invalid form");
        return false;
    }
}

void ScanServiceAbility::SetScannerSerialNumberByTCP(ScanDeviceInfo &info)
{
    info.discoverMode = ScannerDiscoveryMode::TCP_MODE;
    std::string ip;
    if (!GetTcpDeviceIp(info.deviceId, ip)) {
        SCAN_HILOGE("cannot get device's ip");
        info.SetDeviceAvailable(false);
        return;
    }
    info.uniqueId = ip;
    ScanDeviceInfoTCP netScannerInfo;
    if (ScanMdnsService::GetInstance().FindNetScannerInfoByIp(ip, netScannerInfo)) {
        info.uuid = netScannerInfo.uuid;
        info.deviceName = netScannerInfo.deviceName;
    } else {
        info.deviceName = info.manufacturer + "-" + info.model;
    }
}

void ScanServiceAbility::SetScannerSerialNumberByUSB(ScanDeviceInfo &info)
{
    info.discoverMode = ScannerDiscoveryMode::USB_MODE;
    std::string firstId;
    std::string secondId;
    if (!GetUsbDevicePort(info.deviceId, firstId, secondId)) {
        SCAN_HILOGE("cannot get usb's port");
        return;
    }
    std::string usbScannerPort = firstId + "-" + secondId;
    auto scanUsbManager = DelayedSingleton<ScanUsbManager>::GetInstance();
    if (scanUsbManager == nullptr) {
        SCAN_HILOGE("scanUsbManager is nullptr");
        return;
    }
    std::string serialNumber = scanUsbManager->GetSerialNumberByPort(usbScannerPort);
    if (serialNumber.empty() && !scanUsbManager->IsDeviceAvailable(firstId, secondId)) {
        SCAN_HILOGD("usb can't find device: %{private}s", usbScannerPort.c_str());
        info.SetDeviceAvailable(false);
        return;
    }
    std::ostringstream oss;
    if (serialNumber.empty()) {
        oss << "USB-" << info.manufacturer << " " << info.model << " " << usbScannerPort;
        info.deviceName = oss.str();
    } else {
        info.serialNumber = serialNumber;
        info.uniqueId = serialNumber;
        oss << "USB-" << info.manufacturer << " " << info.model << "-";
        constexpr int32_t SERIAL_NUMBER_SUFFIX_LENGTH  = 6;
        if (serialNumber.size() <= SERIAL_NUMBER_SUFFIX_LENGTH) {
            oss << serialNumber;
        } else {
            oss << serialNumber.substr(serialNumber.size() - SERIAL_NUMBER_SUFFIX_LENGTH);
        }
        info.deviceName = oss.str();
    }
}

void ScanServiceAbility::SetScannerSerialNumber(ScanDeviceInfo &info)
{
    if (info.deviceId.find(":tcp") != info.deviceId.npos) {
        SetScannerSerialNumberByTCP(info);
    } else if (info.deviceId.find(":libusb") != info.deviceId.npos) {
        SetScannerSerialNumberByUSB(info);
    } else {
        SCAN_HILOGE("Unknown scanner connect method");
    }
}

void ScanServiceAbility::UpdateScanSystemData(const ScanDeviceInfo &info)
{
    std::string uniqueId = info.discoverMode + info.uniqueId;
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    ScanDeviceInfoSync scanDeviceInfoSync;
    scanDeviceInfoSync.uniqueId = info.uniqueId;
    scanDeviceInfoSync.deviceId = info.deviceId;
    scanDeviceInfoSync.syncMode = ScannerSyncMode::UPDATE_MODE;
    scanDeviceInfoSync.discoverMode = info.discoverMode;
    if (info.discoverMode == ScannerDiscoveryMode::USB_MODE) {
        ScanDeviceInfo scannerInfo;
        if (scanData.QueryScannerInfoByUniqueId(uniqueId, scannerInfo)) {
            scanData.UpdateScannerInfoByUniqueId(uniqueId, info);
            if (scannerInfo.deviceId != info.deviceId) {
                scanDeviceInfoSync.oldDeviceId = scannerInfo.deviceId;
                SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
            }
        }
    } else {
        auto updateResult = scanData.UpdateNetScannerByUuid(info.uuid, info.uniqueId);
        if (updateResult.has_value()) {
            scanDeviceInfoSync.oldDeviceId = updateResult.value().first;
            /* IP changed: the baseline was already renamed inside
             * UpdateNetScannerByUuid. Invalidate the active dialog session,
             * dropping its pending cert. */
            InvalidateCertDialogForDevice(updateResult.value().first);
            SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
        }
    }
    scanData.SaveScannerMap();
}

void ScanServiceAbility::AddFoundScanner(ScanDeviceInfo &info, std::vector<ScanDeviceInfo>& scanDeviceInfos)
{
    if (info.GetDeviceAvailable() == false) {
        SCAN_HILOGE("device is unavailable");
        return;
    }
    if (info.discoverMode != ScannerDiscoveryMode::USB_MODE && info.discoverMode != ScannerDiscoveryMode::TCP_MODE) {
        SCAN_HILOGE("discoverMode is invalid:[%{public}s]", info.discoverMode.c_str());
        return;
    }
    if (info.uniqueId.empty()) {
        SCAN_HILOGD("uniqueId is set to deviceId [%{private}s]", info.deviceId.c_str());
        info.uniqueId = info.deviceId;
    } else {
        UpdateScanSystemData(info);
    }
    if (info.discoverMode == ScannerDiscoveryMode::USB_MODE) {
        scannerDiscoverData_.SetUsbDevice(info.uniqueId, info);
    } else {
        scannerDiscoverData_.SetTcpDevice(info.uniqueId, info);
    }
    scanDeviceInfos.push_back(info);
}

void ScanServiceAbility::SaneGetScanner()
{
    ScanMdnsService::GetInstance().OnStartDiscoverService();
    SaneManagerClient::GetInstance().SaneInit();
    std::vector<SaneDevice> saneDeviceInfos;
    SaneStatus status = SaneManagerClient::GetInstance().SaneGetDevices(saneDeviceInfos);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetDevices failed, ret: [%{public}u]", status);
        return;
    }
    std::vector<ScanDeviceInfo> scanDeviceInfos;
    for (const auto &device : saneDeviceInfos) {
        ScanDeviceInfo info;
        info.deviceId = device.name_;
        info.manufacturer = device.vendor_;
        info.model = device.model_;
        info.deviceType = device.type_;
        SetScannerSerialNumber(info);
        AddFoundScanner(info, scanDeviceInfos);
    }
    EsclDriverManager::AddEsclScannerInfo(scanDeviceInfos);
    for (auto& scanDeviceInfo : scanDeviceInfos) {
        SendDeviceInfo(scanDeviceInfo, SCAN_DEVICE_FOUND);
    }
    SendDeviceList(scanDeviceInfos, GET_SCANNER_DEVICE_LIST);
}

int32_t ScanServiceAbility::GetScannerList()
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    SCAN_HILOGI("ScanServiceAbility GetScannerList start");
    // USB attach can fire GetScannerList repeatedly; coalesce discovery tasks.
    {
        std::lock_guard<std::mutex> lock(discoverMutex_);
        if (discoverInProgress_) {
            rediscoverPending_ = true;
            SCAN_HILOGI("discovery in progress, mark pending rediscover");
            return E_SCAN_NONE;
        }
        discoverInProgress_ = true;
    }
    auto exec_sane_getscaner = [=]() {
        while (true) {
            SaneGetScanner();
            // Pick up a discovery request that arrived during this round.
            std::lock_guard<std::mutex> lock(discoverMutex_);
            if (rediscoverPending_) {
                rediscoverPending_ = false;
                continue;
            }
            discoverInProgress_ = false;
            break;
        }
    };
    {
        std::shared_ptr<AppExecFwk::EventHandler> handler;
        {
            std::lock_guard<std::recursive_mutex> lock(apiMutex_);
            handler = serviceHandler_;
        }
        SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(handler, E_SCAN_SERVER_FAILURE, __func__);
        handler->PostTask(exec_sane_getscaner, ASYNC_CMD_DELAY);
    }
    SCAN_HILOGI("ScanServiceAbility GetScannerList end");
    return E_SCAN_NONE;
}

// Called with lock_ held.
int32_t ScanServiceAbility::DoOpenScanner(const std::string &scannerId)
{
    SaneStatus status = SaneManagerClient::GetInstance().SaneOpen(scannerId);
    if (status == SANE_STATUS_TLS_CERT_CHANGED) {
        // 100 is deterministic; return immediately and raise the dialog async.
        SCAN_HILOGE("SaneOpen cert changed, status: [%{public}u]", status);
        return HandleSaneStatus(scannerId, status);
    }
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_open failed, ret: [%{public}u], retry one times", status);
        status = SaneManagerClient::GetInstance().SaneOpen(scannerId);
    }
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneOpen failed, status: [%{public}u]", status);
        // HTTPS unavailable only if two https opens fail and a plain-HTTP open succeeds.
        std::string plainDeviceId;
        if (EsclDriverManager::BuildPlainHttpDeviceId(scannerId, plainDeviceId,
            GetPlainHttpPort(scannerId))) {
            if (IsPlainHttpReachable(plainDeviceId)) {
                return E_SCAN_HTTPS_UNAVAILABLE;
            }
        }
        // The retry may itself have hit 100; route through the shared handler.
        return HandleSaneStatus(scannerId, status);
    }
    openedScanner_ = OpenedScanner{scannerId, IPCSkeleton::GetCallingPid(), GetCurrentUserId()};
    return E_SCAN_NONE;
}

// True when the plain-HTTP open works (caller should prompt an https re-add).
bool ScanServiceAbility::IsPlainHttpReachable(const std::string &plainDeviceId)
{
    SaneStatus plainStatus = SaneManagerClient::GetInstance().SaneOpen(plainDeviceId);
    if (plainStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGI("https open failed twice, plain HTTP probe also failed, status: [%{public}u]",
            plainStatus);
        return false;
    }
    SaneManagerClient::GetInstance().SaneClose(plainDeviceId);
    SCAN_HILOGI("HTTPS unavailable but plain HTTP open ok, prompt re-add: %{private}s",
        plainDeviceId.c_str());
    return true;
}

int32_t ScanServiceAbility::OpenScanner(const std::string scannerId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    SCAN_HILOGI("ScanServiceAbility OpenScanner start, isEscl=%{public}d",
        EsclDriverManager::IsEsclScanner(scannerId));
    if (scannerId.empty()) {
        SCAN_HILOGE("OpenScanner scannerId is empty");
        return E_SCAN_INVALID_PARAMETER;
    }
    // Opening a different device invalidates the previous one's dialog.
    if (certDialogSession_.has_value() && certDialogSession_->scannerId != scannerId) {
        InvalidateCertDialog("open other scanner");
    }

    if (openedScanner_.has_value()) {
        if (openedScanner_->scannerId == scannerId &&
            openedScanner_->callerPid == IPCSkeleton::GetCallingPid() &&
            openedScanner_->userId == GetCurrentUserId()) {
            SCAN_HILOGD("scannerId %{private}s is already opened by same caller", scannerId.c_str());
            return E_SCAN_NONE;
        }
        SCAN_HILOGE("scanner %{private}s is already opened, only one scanner can be opened at a time",
                    openedScanner_->scannerId.c_str());
        return E_SCAN_DEVICE_BUSY;
    }
    int32_t ret = DoOpenScanner(scannerId);
    if (ret == E_SCAN_NONE) {
        SCAN_HILOGI("ScanServiceAbility OpenScanner end");
    }
    return ret;
}

int32_t ScanServiceAbility::CloseScanner(const std::string scannerId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    SCAN_HILOGI("ScanServiceAbility CloseScanner start");
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    // Clear the in-progress queue only; keep delivered results for re-export.
    scanPictureData_.CleanScanQueue();
    if (scannerState_.load() == SCANNER_SCANING) {
        SaneManagerClient::GetInstance().SaneCancel(scannerId);
        // CANCELING: reject RestartScan (batch) and keep StartScan BUSY until task end.
        scannerState_.store(SCANNER_CANCELING);
    }
    SaneStatus status = SaneManagerClient::GetInstance().SaneClose(scannerId);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneClose failed, status: [%{public}u]", status);
        return HandleSaneStatus(scannerId, status);
    }
    openedScanner_.reset();
    colorModeSettings_.erase(scannerId);
    InvalidateCertDialogForDevice(scannerId);
    SCAN_HILOGI("ScanServiceAbility CloseScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    SCAN_HILOGI("ScanServiceAbility GetScanOptionDesc start");
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    SaneOptionDescriptor saneDesc;
    SaneStatus status = SaneManagerClient::GetInstance().SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetOptionDescriptor failed, status: [%{public}u]", status);
        return HandleSaneStatus(scannerId, status);
    }
    if (EsclDriverManager::IsEsclScanner(scannerId)) {
        EsclDriverManager::InjectLineartOption(saneDesc);
    }
    FillOptionConstraint(saneDesc, desc);
    desc.Dump();
    SCAN_HILOGI("ScanServiceAbility GetScanOptionDesc end");
    return E_SCAN_NONE;
}

void ScanServiceAbility::FillOptionConstraint(SaneOptionDescriptor &saneDesc, ScanOptionDescriptor &desc)
{
    desc.SetOptionName(saneDesc.optionName_);
    desc.SetOptionTitle(saneDesc.optionTitle_);
    desc.SetOptionDesc(saneDesc.optionDesc_);
    desc.SetOptionType(saneDesc.optionType_);
    desc.SetOptionUnit(saneDesc.optionUnit_);
    desc.SetOptionConstraintType(saneDesc.optionConstraintType_);
    if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_RANGE) {
        ScanRange scanRange;
        scanRange.SetMinValue(saneDesc.minValue_);
        scanRange.SetMaxValue(saneDesc.maxValue_);
        scanRange.SetQuantValue(saneDesc.quantValue_);
        desc.SetOptionConstraintRange(scanRange);
    } else if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_WORD_LIST) {
        std::vector<int32_t> optionConstraintNumber;
        for (const auto &number : saneDesc.optionConstraintNumber_) {
            SCAN_HILOGD("SANE_CONSTRAINT_WORD_LIST : %{public}d", number);
            optionConstraintNumber.push_back(number);
        }
        desc.SetOptionConstraintNumber(optionConstraintNumber);
    } else if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_STRING_LIST) {
        std::vector<std::string> optionConstraintString;
        std::vector<std::string> &stringList = saneDesc.optionConstraintString_;
        for (auto &str : stringList) {
            SCAN_HILOGD("SANE_CONSTRAINT_STRING_LIST %{public}s", str.c_str());
            optionConstraintString.push_back(str);
        }
        desc.SetOptionConstraintString(optionConstraintString);
    }
}

int32_t ScanServiceAbility::ActionSetAuto(const std::string &scannerId, const int32_t &optionIndex)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_SET_AUTO");
    SaneStatus status = SANE_STATUS_GOOD;
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = static_cast<SaneAction>(SANE_ACTION_SET_AUTO);
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance().SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return HandleSaneStatus(scannerId, status);
    }
    if (auto sit = colorModeSettings_.find(scannerId); sit != colorModeSettings_.end()) {
        sit->second.erase(optionIndex);
        if (sit->second.empty()) {
            colorModeSettings_.erase(sit);
        }
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ActionGetValue(
    const std::string &scannerId, ScanOptionValue &value, const int32_t &optionIndex)
{
    SCAN_HILOGI("Set OpScanOptionValue SCAN_ACTION_GET_VALUE");
    if (auto sit = colorModeSettings_.find(scannerId); sit != colorModeSettings_.end()) {
        if (auto oit = sit->second.find(optionIndex); oit != sit->second.end()) {
            value = oit->second;
            return E_SCAN_NONE;
        }
    }
    SaneStatus status = SANE_STATUS_GOOD;
    ScanOptionValueType valueType = value.GetScanOptionValueType();
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = static_cast<int32_t>(valueType);
    controlParam.valueSize_ = value.GetValueSize();
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance().SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_control_option failed, status: [%{public}d]", status);
        return HandleSaneStatus(scannerId, status);
    }
    if (valueType == SCAN_VALUE_NUM) {
        value.SetNumValue(outParam.valueNumber_);
    } else if (valueType == SCAN_VALUE_STR) {
        value.SetStrValue(outParam.valueStr_);
    } else if (valueType == SCAN_VALUE_BOOL) {
        value.SetBoolValue(outParam.valueBool_);
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ActionSetValue(
    const std::string &scannerId, ScanOptionValue &value, const int32_t &optionIndex)
{
    SCAN_HILOGI("Set OpScanOptionValue SCAN_ACTION_SET_VALUE");
    bool shouldDowngrade = false;
    if (value.GetScanOptionValueType() == SCAN_VALUE_STR) {
        shouldDowngrade = EsclDriverManager::ShouldDowngradeBwMode(scannerId, value.GetStrValue());
    }

    SaneStatus status = SANE_STATUS_GOOD;
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = static_cast<SaneAction>(SANE_ACTION_SET_VALUE);
    controlParam.valueType_ = static_cast<int32_t>(value.GetScanOptionValueType());
    int32_t numValue = value.GetNumValue();
    controlParam.valueNumber_ = numValue;
    controlParam.valueStr_ = value.GetStrValue();

    if (shouldDowngrade) {
        controlParam.valueStr_ = SCAN_MODE_GRAY;
        SCAN_HILOGD("BW downgrade: Lineart -> Gray");
    }

    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance().SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, ret = [%{public}d]", status);
        return HandleSaneStatus(scannerId, status);
    }

    if (shouldDowngrade) {
        colorModeSettings_[scannerId][optionIndex] = value;
    }

    return status;
}

int32_t ScanServiceAbility::OpScanOptionValue(
    const std::string scannerId, const int32_t optionIndex, const ScanOptionOpType op, ScanOptionValue &value)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start");
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    int32_t state = E_SCAN_NONE;
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start to dump value");
    value.Dump();
    switch (op) {
        case SCAN_ACTION_SET_AUTO:
            state = ActionSetAuto(scannerId, optionIndex);
            break;
        case SCAN_ACTION_GET_VALUE:
            state = ActionGetValue(scannerId, value, optionIndex);
            break;
        case SCAN_ACTION_SET_VALUE:
            state = ActionSetValue(scannerId, value, optionIndex);
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
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue end");
    return state;
}

int32_t ScanServiceAbility::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    return GetScanParametersInternal(scannerId, para);
}

int32_t ScanServiceAbility::GetScanParametersInternal(const std::string &scannerId, ScanParameters &para)
{
    SCAN_HILOGI("ScanServiceAbility GetScanParameters start");
    SaneParameters saneParams;
    SaneStatus status = SaneManagerClient::GetInstance().SaneGetParameters(scannerId, saneParams);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetParameters failed, status: [%{public}u]", status);
        return HandleSaneStatus(scannerId, status);
    }
    int32_t frameValue = static_cast<int32_t>(saneParams.format_);
    if (frameValue < SANE_FRAME_GRAY || frameValue >= SANE_FRAME_MAX) {
        SCAN_HILOGE("Invalid scan format: [%{public}d]", frameValue);
        return E_SCAN_INVALID_PARAMETER;
    }
    para.SetFormat(static_cast<ScanFrame>(saneParams.format_));
    para.SetLastFrame(saneParams.lastFrame_);
    para.SetBytesPerLine(saneParams.bytesPerLine_);
    para.SetPixelsPerLine(saneParams.pixelsPerLine_);
    para.SetLines(saneParams.lines_);
    para.SetDepth(saneParams.depth_);
    para.Dump();
    SCAN_HILOGI("ScanServiceAbility GetScanParameters end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CancelScan(const std::string scannerId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan start");
    scanPictureData_.CleanScanQueue();
    SaneStatus saneStatus = SaneManagerClient::GetInstance().SaneCancel(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneCancel failed, status: [%{public}u]", saneStatus);
        return HandleSaneStatus(scannerId, saneStatus);
    }
    if (scannerState_.load() == SCANNER_SCANING) {
        SCAN_HILOGW("ScannerState change to SCANNER_CANCELING");
        scannerState_.store(SCANNER_CANCELING);
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    const std::string &permission = (SCAN_PERMISSION_MAP.find(type) != SCAN_PERMISSION_MAP.end())
                                        ? SCAN_PERMISSION_MAP.at(type)
                                        : PERMISSION_NAME_PRINT_JOB;
    if (!CheckPermission(permission)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    int32_t userId = GetCurrentUserId();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string eventType = ScanServiceUtils::GetTaskEventId(taskId, type, userId, callerPid);

    SCAN_HILOGD("ScanServiceAbility::On started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    constexpr int32_t MAX_LISTENERS_COUNT = 1000;
    if (registeredListeners_.size() > MAX_LISTENERS_COUNT) {
        SCAN_HILOGE("Exceeded the maximum number of registration.");
        return E_SCAN_GENERIC_FAILURE;
    }
    auto it = registeredListeners_.find(eventType);
    if (it == registeredListeners_.end()) {
        const auto temp = registeredListeners_.insert(std::make_pair(eventType, listener));
        if (!temp.second) {
            SCAN_HILOGE("ScanServiceAbility::On insert type=%{public}s object fail.", eventType.c_str());
            return E_SCAN_SERVER_FAILURE;
        }
    } else {
        SCAN_HILOGI("ScanServiceAbility::On Replace listener.");
        it->second = listener;
    }
    SCAN_HILOGI("ScanServiceAbility::On end.");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::Off(const std::string taskId, const std::string &type)
{
    const std::string &permission = (SCAN_PERMISSION_MAP.find(type) != SCAN_PERMISSION_MAP.end())
                                        ? SCAN_PERMISSION_MAP.at(type)
                                        : PERMISSION_NAME_PRINT_JOB;
    if (!CheckPermission(permission)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    int32_t userId = GetCurrentUserId();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string eventType = ScanServiceUtils::GetTaskEventId(taskId, type, userId, callerPid);
    SCAN_HILOGD("ScanServiceAbility::Off started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter != registeredListeners_.end()) {
        SCAN_HILOGD("ScanServiceAbility::Off delete type=%{public}s object message.", eventType.c_str());
        registeredListeners_.erase(iter);
        return E_SCAN_NONE;
    }
    return E_SCAN_INVALID_PARAMETER;
}

void ScanServiceAbility::SendDeviceInfo(const ScanDeviceInfo &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    SCAN_HILOGI("SendDeviceInfo [%{private}s], event = %{public}s", info.deviceId.c_str(), event.c_str());
    info.Dump();
    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    for (auto [eventType, listener] : registeredListeners_) {
        std::string type;
        ScanServiceUtils::EncodeTaskEventId(eventType, type);
        if (type == event && listener != nullptr) {
            listener->OnCallback(info.GetDeviceState(), info);
        }
    }
}

void ScanServiceAbility::SendDeviceList(std::vector<ScanDeviceInfo> &infos, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    for (auto [eventType, listener] : registeredListeners_) {
        std::string type;
        ScanServiceUtils::EncodeTaskEventId(eventType, type);
        if (type == event && listener != nullptr) {
            listener->OnGetDevicesList(infos);
        }
    }
}

void ScanServiceAbility::SendDeviceInfoSync(const ScanDeviceInfoSync &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    SCAN_HILOGI("SendDeviceInfo [%{private}s], event = %{public}s", info.deviceId.c_str(), event.c_str());
    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoSync parm has nullptr");
        return;
    }
    info.Dump();
    for (auto [eventType, listener] : registeredListeners_) {
        std::string type;
        ScanServiceUtils::EncodeTaskEventId(eventType, type);
        if (type == event && listener != nullptr) {
            listener->OnCallbackSync(info.GetDeviceState(), info);
        }
    }
}

void ScanServiceAbility::DisConnectUsbScanner(std::string serialNumber, std::string deviceId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    SCAN_HILOGD("DisConnectUsbScanner start deviceId:%{private}s", deviceId.c_str());
    scannerDiscoverData_.RemoveUsbDevice(serialNumber);
    ScanDeviceInfoSync scanDeviceInfoSync;
    scanDeviceInfoSync.uniqueId = serialNumber;
    scanDeviceInfoSync.deviceId = deviceId;
    scanDeviceInfoSync.discoverMode = ScannerDiscoveryMode::USB_MODE;
    scanDeviceInfoSync.syncMode = ScannerSyncMode::DELETE_MODE;
    scanDeviceInfoSync.deviceState = 0;
    SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
}

void ScanServiceAbility::UpdateScannerId(const ScanDeviceInfoSync &syncInfo)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    SCAN_HILOGD("UpdateScannerId start newDeviceId:[%{private}s]", syncInfo.deviceId.c_str());
    ScanDeviceInfoSync scanDeviceInfoSync = syncInfo;
    if (scanDeviceInfoSync.discoverMode == ScannerDiscoveryMode::USB_MODE) {
        scannerDiscoverData_.UpdateUsbDevice(scanDeviceInfoSync.uniqueId,
            [&scanDeviceInfoSync](ScanDeviceInfo& info) {
                info.deviceId = scanDeviceInfoSync.deviceId;
            });
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else if (scanDeviceInfoSync.discoverMode == ScannerDiscoveryMode::TCP_MODE) {
        std::string oldIp;
        ScanUtil::ExtractIpAddresses(scanDeviceInfoSync.oldDeviceId, oldIp);
        scannerDiscoverData_.UpdateTcpDevice(oldIp, scanDeviceInfoSync.uniqueId,
            [&scanDeviceInfoSync](ScanDeviceInfo& info) {
                info.deviceId = scanDeviceInfoSync.deviceId;
            });
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else {
        SCAN_HILOGE("invalid discover mode %{public}s", scanDeviceInfoSync.discoverMode.c_str());
    }
}

void ScanServiceAbility::NetScannerLossNotify(const ScanDeviceInfoSync& syncInfo)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    if (syncInfo.discoverMode != ScannerDiscoveryMode::TCP_MODE) {
        SCAN_HILOGE("discoverMode is error:[%{private}s]", syncInfo.discoverMode.c_str());
        return;
    }
    SendDeviceInfoSync(syncInfo, SCAN_DEVICE_SYNC);
}

void ScanServiceAbility::NotifyEsclScannerFound(const ScanDeviceInfo& info)
{
    {
        std::lock_guard<std::mutex> lock(discoverMutex_);
        if (discoverInProgress_) {
            SCAN_HILOGI("discovery in progress, skip escl notification");
            return;
        }
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    SCAN_HILOGI("NotifyEsclScannerFound [%{private}s]", info.deviceId.c_str());
    info.Dump();
    for (auto [eventType, listener] : registeredListeners_) {
        std::string type;
        ScanServiceUtils::EncodeTaskEventId(eventType, type);
        if (type == SCAN_DEVICE_FOUND && listener != nullptr) {
            listener->OnCallback(info.GetDeviceState(), info);
        }
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
            result = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NAME_PRINT);
        }
        SCAN_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
}

int32_t ScanServiceAbility::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    int32_t status = scanPictureData_.GetPictureProgressInQueue(prog);
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("scanprogress exception occurred:[%{public}u]", status);
        return status;
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::AddScanner(const std::string &uniqueId, const std::string &discoverMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    if (discoverMode != ScannerDiscoveryMode::USB_MODE && discoverMode != ScannerDiscoveryMode::TCP_MODE) {
        SCAN_HILOGE("discoverMode is a invalid parameter.");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (discoverMode == ScannerDiscoveryMode::USB_MODE) {
        AddUsbScanner(uniqueId, discoverMode);
    } else if (discoverMode == ScannerDiscoveryMode::TCP_MODE) {
        AddNetScanner(uniqueId, discoverMode);
    } else {
        SCAN_HILOGE("discoverMode is invalid.");
    }
    return E_SCAN_NONE;
}

void ScanServiceAbility::AddNetScanner(const std::string& uniqueId, const std::string &discoverMode)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    ScanDeviceInfo info;
    if (scannerDiscoverData_.GetTcpDevice(uniqueId, info)) {
        SCAN_HILOGI("add private driver scanner");
    } else if (scannerDiscoverData_.GetEsclDevice(uniqueId, info)) {
        SCAN_HILOGI("add escl driver scanner");
    } else {
        SCAN_HILOGE("not found net scanner in map");
        return;
    }
    if (scanData.IsContainScanner(discoverMode + uniqueId)) {
        SCAN_HILOGE("The net scanner has already been added");
        return;
    }
    ProbeHttpsAndDowngrade(info);
    scanData.InsertScannerInfo(discoverMode + uniqueId, info);
    if (!scanData.SaveScannerMap()) {
        SCAN_HILOGE("ScanServiceAbility AddNetScanner SaveScannerMap fail");
        return;
    }
    SendDeviceInfo(info, SCAN_DEVICE_ADD);
}

std::string ScanServiceAbility::GetPlainHttpPort(const std::string& scannerId)
{
    std::string ipAddress;
    int32_t portNumber = 0;
    std::string plainPort = "80";
    if (EsclDriverManager::ExtractIpAndPort(scannerId, ipAddress, portNumber)) {
        ScanMdnsService::GetInstance().GetPlainHttpPort(ipAddress, plainPort);
    }
    return plainPort;
}

std::string ScanServiceAbility::GetDeviceName(const std::string& scannerId)
{
    std::string ipAddress;
    int32_t portNumber = 0;
    if (!EsclDriverManager::ExtractIpAndPort(scannerId, ipAddress, portNumber)) {
        return "";
    }
    ScanDeviceInfo info;
    bool found = ScanSystemData::GetInstance().QueryScannerInfoByUniqueId(ipAddress, info);
    if (!found) {
        found = scannerDiscoverData_.GetEsclDevice(ipAddress, info);
    }
    if (!found) {
        return "";
    }
    if (!info.GetDeviceName().empty()) {
        return info.GetDeviceName();
    }
    if (!info.GetManufacturer().empty() || !info.GetModel().empty()) {
        return info.GetManufacturer() + "-" + info.GetModel();
    }
    return "";
}

void ScanServiceAbility::ProbeHttpsAndDowngrade(ScanDeviceInfo &info)
{
    // Add-time protocol probe: decide https/http once, while the user is present.
    if (!info.GetIsHttps()) {
        return;
    }
    SaneStatus status = SaneManagerClient::GetInstance().SaneOpen(info.deviceId);
    if (status == SANE_STATUS_GOOD) {
        SaneManagerClient::GetInstance().SaneClose(info.deviceId);
        SCAN_HILOGI("AddNetScanner https probe ok, keep https: %{private}s", info.deviceId.c_str());
        return;
    }
    SCAN_HILOGW("AddNetScanner https probe failed, status: [%{public}u], downgrade to http", status);
    // Persist the downgrade so the record and runtime path use plain HTTP.
    std::string plainDeviceId;
    if (EsclDriverManager::BuildPlainHttpDeviceId(info.deviceId, plainDeviceId,
        GetPlainHttpPort(info.deviceId))) {
        info.SetDeviceId(plainDeviceId);
    } else {
        // Should not happen (isHttps implies https scheme); no-op.
        return;
    }
    info.SetIsHttps(false);
}

int32_t ScanServiceAbility::HandleSaneStatus(const std::string &scannerId, SaneStatus status)
{
    // Any SANE call can surface 100; every path raises the dialog.
    if (status == SANE_STATUS_TLS_CERT_CHANGED) {
        SCAN_HILOGE("SANE status cert changed on scanner %{private}s", scannerId.c_str());
        std::string ipAddress;
        int32_t portNumber = 0;
        EsclDriverManager::ExtractIpAndPort(scannerId, ipAddress, portNumber);
        // The pending certificate is the only thing the user can confirm.
        std::string fingerprint;
        if (!TofuCertStore::GetInstance().ReadPendingFingerprint(ipAddress, fingerprint)) {
            SCAN_HILOGE("cert changed but pending cert unavailable for %{private}s", scannerId.c_str());
            return E_SCAN_IO_ERROR;
        }
        LaunchCertDialog(ScanDialogEventType::CERT_CHANGED, {
            {ScanDialogParam::SESSION_ID, GenerateSessionId()},
            {ScanDialogParam::SCANNER_ID, scannerId},
            {ScanDialogParam::DEVICE_NAME, GetDeviceName(scannerId)},
            {ScanDialogParam::DEVICE_IP, ipAddress},
            {ScanDialogParam::DEVICE_PORT, portNumber > 0 ? std::to_string(portNumber) : ""},
            {ScanDialogParam::CERT_FINGERPRINT, fingerprint}
        });
        return E_SCAN_TLS_CERT_CHANGED;
    }
    return ScanServiceUtils::ConvertErro(status);
}

// Fills the single dialog slot under lock_. False = a dialog is active or params are invalid.
bool ScanServiceAbility::PrepareCertDialogSession(const std::vector<std::pair<std::string, std::string>> &params,
    CertDialogSession &session)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (certDialogSession_.has_value()) {
        // De-dup: one dialog at a time; later 100s only return the error code.
        SCAN_HILOGI("cert dialog already active, skip launch");
        return false;
    }
    for (const auto &param : params) {
        if (param.first == ScanDialogParam::SESSION_ID) {
            session.sessionId = param.second;
        } else if (param.first == ScanDialogParam::SCANNER_ID) {
            session.scannerId = param.second;
        } else if (param.first == ScanDialogParam::DEVICE_IP) {
            session.ipAddress = param.second;
        } else if (param.first == ScanDialogParam::CERT_FINGERPRINT) {
            session.fingerprint = param.second;
        }
    }
    if (session.sessionId.empty() || session.scannerId.empty() || session.ipAddress.empty()) {
        SCAN_HILOGE("launch cert dialog: missing session/scanner/ip");
        return false;
    }
    session.state = CertDialogState::LAUNCHING;
    certDialogSession_ = session;
    return true;
}

void ScanServiceAbility::ResetCertDialogSession(const std::string &sessionId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (certDialogSession_.has_value() && certDialogSession_->sessionId == sessionId) {
        certDialogSession_.reset();
    }
}

int32_t ScanServiceAbility::ConnectCertDialogWithRetry(const AAFwk::Want &want,
    const sptr<ScanAbilityConnection> &connection)
{
    // Do not hold lock_ across the ability-connect IPC + retry sleeps.
    ErrCode ret = ERR_OK;
    for (uint32_t retry = 0; retry < CERT_DIALOG_MAX_RETRY_TIMES; retry++) {
        ret = OHOS::Print::AbilityManagerAdapter::GetInstance().ConnectAbility(want, connection, -1);
        if (ret == ERR_OK) {
            break;
        }
        SCAN_HILOGE("connect cert dialog ability failed, ret: %{public}d, retry: %{public}u",
            ret, retry);
        std::this_thread::sleep_for(std::chrono::milliseconds(CERT_DIALOG_RETRY_INTERVAL_MS));
    }
    return ret;
}

void ScanServiceAbility::PublishCertDialogConnection(const CertDialogSession &session,
    const std::string &eventType, const sptr<ScanAbilityConnection> &connection,
    const sptr<ScanCertDecisionCallback> &callback)
{
    bool staleConnection = false;
    {
        std::lock_guard<std::recursive_mutex> autoLock(lock_);
        if (!certDialogSession_.has_value() ||
            certDialogSession_->sessionId != session.sessionId) {
            // The dialog was invalidated or replaced while retrying; drop the stale connection.
            staleConnection = true;
        } else {
            certDialogSession_->connection = connection;
            certDialogSession_->callback = callback;
            certDialogSession_->dialogRemote = connection->GetRemote();
            SCAN_HILOGI("launch cert dialog requested, eventType: %{public}s, scanner: %{private}s",
                eventType.c_str(), session.scannerId.c_str());
        }
    }
    if (staleConnection) {
        SCAN_HILOGI("cert dialog session changed before launch completed, disconnect stale connection");
        OHOS::Print::AbilityManagerAdapter::GetInstance().DisconnectAbility(connection);
    }
}

void ScanServiceAbility::DoLaunchCertDialog(const std::string &eventType,
    const std::vector<std::pair<std::string, std::string>> &params, const CertDialogSession &session)
{
    AAFwk::Want want;
    want.SetElementName(SCAN_APP_BUNDLE_NAME, SCAN_CERT_DIALOG_EXT_ABILITY);
    want.SetParam(ScanDialogParam::EVENT_TYPE, eventType);
    for (const auto &param : params) {
        want.SetParam(param.first, param.second);
    }
    sptr<ScanCertDecisionCallback> callback = new ScanCertDecisionCallback(
        [this](const std::string &sessionId, const std::string &scannerId,
            const std::string &fingerprint, int32_t decision) {
            this->OnCertDecision(sessionId, scannerId, fingerprint, decision);
        });
    sptr<ScanAbilityConnection> connection = new ScanAbilityConnection(
        [this](const std::string &sessionId) { this->OnCertDialogConnected(sessionId); },
        [this](const std::string &sessionId) { this->OnCertDialogClosed(sessionId); });
    connection->SetDecisionCallback(callback, session.sessionId);
    int32_t ret = ConnectCertDialogWithRetry(want, connection);
    if (ret != ERR_OK) {
        SCAN_HILOGE("launch cert dialog failed, keep error-code path only");
        ResetCertDialogSession(session.sessionId);
        return;
    }
    PublishCertDialogConnection(session, eventType, connection, callback);
}

void ScanServiceAbility::LaunchCertDialog(const std::string &eventType,
    const std::vector<std::pair<std::string, std::string>> &params)
{
    CertDialogSession session;
    if (!PrepareCertDialogSession(params, session)) {
        return;
    }
    // Launch asynchronously: callers hold lock_ and must not block on ability connect.
    auto launch = [this, eventType, params, session]() {
        DoLaunchCertDialog(eventType, params, session);
    };
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        handler = serviceHandler_;
    }
    if (handler == nullptr) {
        SCAN_HILOGE("LaunchCertDialog: serviceHandler_ is nullptr");
        ResetCertDialogSession(session.sessionId);
        return;
    }
    handler->PostTask(launch, ASYNC_CMD_DELAY);
    // Watchdog: if no connect callback arrives, free the slot for the next 100.
    auto timeout = [this, sessionId = session.sessionId]() {
        OnCertDialogLaunchTimeout(sessionId);
    };
    handler->PostTask(timeout, CERT_DIALOG_LAUNCH_TIMEOUT_MS);
}

void ScanServiceAbility::OnCertDialogLaunchTimeout(const std::string &sessionId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (!certDialogSession_.has_value() ||
        certDialogSession_->sessionId != sessionId ||
        certDialogSession_->state != CertDialogState::LAUNCHING) {
        return;
    }
    SCAN_HILOGE("cert dialog launch timeout, session: %{private}s", sessionId.c_str());
    InvalidateCertDialog("launch timeout");
}

void ScanServiceAbility::OnCertDialogConnected(const std::string &sessionId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (!certDialogSession_.has_value() ||
        certDialogSession_->sessionId != sessionId) {
        SCAN_HILOGI("ignore stale cert dialog connect, session: %{private}s", sessionId.c_str());
        return;
    }
    if (certDialogSession_->state == CertDialogState::LAUNCHING) {
        certDialogSession_->state = CertDialogState::SHOWING;
        SCAN_HILOGI("cert dialog showing, scanner: %{private}s", certDialogSession_->scannerId.c_str());
    }
}

void ScanServiceAbility::OnCertDialogClosed(const std::string &sessionId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    // Connection lifecycle is the close notification.
    if (!certDialogSession_.has_value() ||
        certDialogSession_->sessionId != sessionId) {
        SCAN_HILOGI("ignore stale cert dialog close, session: %{private}s", sessionId.c_str());
        return;
    }
    if (certDialogSession_->state == CertDialogState::CLOSING) {
        // A decision is in progress outside lock_; do not delete its pending cert.
        SCAN_HILOGI("cert dialog closed while decision in progress, skip cleanup");
        return;
    }
    SCAN_HILOGI("cert dialog closed without decision, reset state");
    TofuCertStore::GetInstance().DropPending(certDialogSession_->ipAddress);
    certDialogSession_.reset();
}

void ScanServiceAbility::DestroyCertDialogIfActive()
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    InvalidateCertDialog("destroy");
}

void ScanServiceAbility::InvalidateCertDialog(const std::string &reason)
{
    // Caller holds lock_.
    if (!certDialogSession_.has_value()) {
        return;
    }
    CertDialogSession session = *certDialogSession_;
    certDialogSession_.reset();
    SCAN_HILOGI("invalidate cert dialog: %{public}s, scanner: %{private}s",
        reason.c_str(), session.scannerId.c_str());
    if (session.connection != nullptr) {
        if (session.connection->IsConnected()) {
            session.connection->SendDismiss(session.sessionId);
        }
        // Also disconnect a connection that is still LAUNCHING.
        OHOS::Print::AbilityManagerAdapter::GetInstance().DisconnectAbility(session.connection);
    }
    TofuCertStore::GetInstance().DropPending(session.ipAddress);
}

void ScanServiceAbility::InvalidateCertDialogForDevice(const std::string &deviceId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (certDialogSession_.has_value() && certDialogSession_->scannerId == deviceId) {
        InvalidateCertDialog("device changed");
    }
}

void ScanServiceAbility::OnCertDecision(const std::string &sessionId, const std::string &scannerId,
    const std::string &fingerprint, int32_t decision)
{
    CertDialogSession session;
    {
        std::lock_guard<std::recursive_mutex> autoLock(lock_);
        if (!certDialogSession_.has_value() ||
            certDialogSession_->state != CertDialogState::SHOWING ||
            certDialogSession_->sessionId != sessionId ||
            certDialogSession_->scannerId != scannerId ||
            certDialogSession_->fingerprint != fingerprint) {
            SCAN_HILOGE("stale or invalid cert decision dropped");
            return;
        }
        session = *certDialogSession_;
        // Claim the session so duplicate/late decisions are dropped.
        certDialogSession_->state = CertDialogState::CLOSING;
    }

    // File I/O and binder IPC must not run under lock_.
    int32_t ret = E_SCAN_NONE;
    if (decision == static_cast<int32_t>(ScanCertDecision::TRUST)) {
        ret = HandleTrustCert(session);
    } else {
        HandleRejectCert(session);
    }
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("cert decision failed: %{public}d", ret);
    }
    FinishCertDialog(session);

    {
        std::lock_guard<std::recursive_mutex> autoLock(lock_);
        if (certDialogSession_.has_value() &&
            certDialogSession_->sessionId == session.sessionId) {
            certDialogSession_.reset();
        }
    }
}

void ScanServiceAbility::FinishCertDialog(const CertDialogSession &session)
{
    if (session.connection != nullptr && session.connection->IsConnected()) {
        session.connection->SendDismiss(session.sessionId);
        OHOS::Print::AbilityManagerAdapter::GetInstance().DisconnectAbility(session.connection);
    }
    TofuCertStore::GetInstance().DropPending(session.ipAddress);
}

int32_t ScanServiceAbility::HandleTrustCert(CertDialogSession &session)
{
    if (TofuCertStore::GetInstance().PromotePending(session.ipAddress, session.fingerprint) !=
        TofuCertStore::PromoteResult::OK) {
        return E_SCAN_IO_ERROR;
    }
    // Drop the cached handle so the next operation re-handshakes.
    SaneManagerClient::GetInstance().SaneClose(session.scannerId);
    // Re-open so the app's retry on the same session finds a handle.
    SaneStatus reopenStatus = SaneManagerClient::GetInstance().SaneOpen(session.scannerId);
    if (reopenStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("reopen scanner after trust failed, status: %{public}u", reopenStatus);
    }
    SCAN_HILOGI("trusted new cert for %{private}s", session.scannerId.c_str());
    return E_SCAN_NONE;
}

void ScanServiceAbility::HandleRejectCert(CertDialogSession &session)
{
    TofuCertStore::GetInstance().DropPending(session.ipAddress);
    SCAN_HILOGI("rejected new cert for %{private}s, old baseline kept", session.scannerId.c_str());
}

void ScanServiceAbility::AddUsbScanner(const std::string& uniqueId, const std::string &discoverMode)
{
    ScanSystemData &scanData = ScanSystemData::GetInstance();
    ScanDeviceInfo info;
    if (!scannerDiscoverData_.GetUsbDevice(uniqueId, info)) {
        SCAN_HILOGE("AddUsbScanner fail, the scanner was not found in the discovery list");
        return;
    }
    if (scanData.IsContainScanner(discoverMode + uniqueId)) {
        SCAN_HILOGE("The usb scanner has already been added");
        return;
    }
    scanData.InsertScannerInfo(discoverMode + uniqueId, info);
    if (!scanData.SaveScannerMap()) {
        SCAN_HILOGE("ScanServiceAbility AddUsbScanner SaveScannerMap fail");
        return;
    }
    SendDeviceInfo(info, SCAN_DEVICE_ADD);
}

int32_t ScanServiceAbility::DeleteScanner(const std::string &serialNumber, const std::string &discoverMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    SCAN_HILOGI("ScanServiceAbility DeleteScanner start");

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
    InvalidateCertDialogForDevice(scannerInfo.GetDeviceId());
    // Remove TOFU certificate for eSCL scanner
    if (EsclDriverManager::IsEsclScanner(scannerInfo.GetDeviceId())) {
        std::string ipAddress;
        int32_t portNumber = 0;
        if (EsclDriverManager::ExtractIpAndPort(scannerInfo.GetDeviceId(), ipAddress, portNumber)) {
            TofuCertStore::GetInstance().RemoveCert(ipAddress);
        }
    }

    SendDeviceInfo(scannerInfo, SCAN_DEVICE_DEL);
    SCAN_HILOGI("ScanServiceAbility DeleteScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetAddedScanner(std::vector<ScanDeviceInfo> &allAddedScanner)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner start");
    ScanSystemData::GetInstance().GetAddedScannerInfoList(allAddedScanner);
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StartScanOnceInternal(const std::string &scannerId)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    SCAN_HILOGI("ScanServiceAbility StartScan start");

    if (scannerState_.load() == SCANNER_CANCELING) {
        SCAN_HILOGE("scan task is canceling");
        return E_SCAN_DEVICE_BUSY;
    }

    SaneStatus saneStatus = SaneManagerClient::GetInstance().SaneStart(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneStart failed, status is %{public}u", saneStatus);
        SaneManagerClient::GetInstance().SaneCancel(scannerId);
        return HandleSaneStatus(scannerId, saneStatus);
    }
    SCAN_HILOGI("ScanServiceAbility StartScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CheckAdfEmpty(const std::string &scannerId)
{
    if (!EsclDriverManager::IsEsclScanner(scannerId)) {
        return E_SCAN_NONE;
    }
    std::string ipAddress;
    int32_t portNumber = 0;
    if (!EsclDriverManager::ExtractIpAndPort(scannerId, ipAddress, portNumber)) {
        SCAN_HILOGE("Failed to extract IP and port from scannerId");
        return E_SCAN_INVALID_PARAMETER;
    }
    ScanDeviceInfo discoveredInfo;
    bool isHttps =
        scannerDiscoverData_.GetEsclDevice(ipAddress, discoveredInfo) && discoveredInfo.GetIsHttps();
    if (EsclDriverManager::IsAdfMode(scannerId) && EsclDriverManager::IsAdfEmpty(isHttps, ipAddress, portNumber)) {
        SCAN_HILOGI("ADF is empty, no paper available");
        return E_SCAN_NO_DOCS;
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StartScan(const std::string scannerId, const bool &batchMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }
    if (scannerState_.load() != SCANNER_READY) {
        SCAN_HILOGE("scannerId %{private}s is not ready", scannerId.c_str());
        return E_SCAN_DEVICE_BUSY;
    }

    if (int32_t adfRet = CheckAdfEmpty(scannerId); adfRet != E_SCAN_NONE) {
        return adfRet;
    }

    bool needBinarize = PrepareBwScan(scannerId);

    if (int32_t status = StartScanOnceInternal(scannerId); status != E_SCAN_NONE) {
        SCAN_HILOGE("Start Scan error");
        return status;
    }
    scannerState_.store(SCANNER_SCANING);
    scanPictureData_.PushScanPictureProgress();
    int32_t userId = GetCurrentUserId();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    auto exe = [=] () {
        ScanTask task(scannerId, userId, batchMode, callerPid);
        task.SetBinarize(needBinarize);
        StartScanTask(task);
    };
    {
        std::shared_ptr<AppExecFwk::EventHandler> handler;
        {
            std::lock_guard<std::recursive_mutex> lock(apiMutex_);
            handler = serviceHandler_;
        }
        SCAN_CHECK_NULL_AND_RETURN_WITH_FUNC(handler, E_SCAN_SERVER_FAILURE, __func__);
        handler->PostTask(exe, ASYNC_CMD_DELAY);
    }
    SCAN_HILOGI("StartScan successfully");
    return E_SCAN_NONE;
}

void ScanServiceAbility::StartScanTask(ScanTask &scanTask)
{
    if (scanTask.GetBatchMode()) {
        SCAN_HILOGI("start batch mode scan");
        GeneratePictureBatch(scanTask);
    } else {
        SCAN_HILOGI("start single mode scan");
        GeneratePictureSingle(scanTask);
    }
    SCAN_HILOGI("StartScanTask finished, doning scan task free");
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    SaneManagerClient::GetInstance().SaneCancel(scanTask.GetScannerId());
    SaneManagerClient::GetInstance().SaneClose(scanTask.GetScannerId());
    // Re-open for the next job; a 100 here still raises the dialog.
    HandleSaneStatus(scanTask.GetScannerId(),
        SaneManagerClient::GetInstance().SaneOpen(scanTask.GetScannerId()));
    colorModeSettings_.erase(scanTask.GetScannerId());
    if (scannerState_.load() == SCANNER_CANCELING) {
        scanPictureData_.CleanScanQueue();
    }
    scannerState_.store(SCANNER_READY);
    // Consume a deferred cleanup; release only if still this caller's handle.
    if (pendingCleanOwner_ == scanTask.GetCallerPid()) {
        if (openedScanner_.has_value() && openedScanner_->callerPid == scanTask.GetCallerPid()) {
            openedScanner_.reset();
        }
        scanPictureData_.CleanByOwner(scanTask.GetCallerPid());
        pendingCleanOwner_.reset();
    }
    SCAN_HILOGI("ScanServiceAbility StartScanTask end");
}

bool ScanServiceAbility::CreateAndOpenScanFile(ScanTask &scanTask)
{
    std::string filePath;
    if (!scanTask.CreateAndOpenScanFile(filePath)) {
        SCAN_HILOGI("ScanTask CreateAndOpenScanFile fail");
        return false;
    }
    
    std::string baseName = ScanServiceUtils::ExtractBaseName(filePath);

    {
        std::lock_guard<std::recursive_mutex> autoLock(lock_);
        scanPictureData_.RegisterCacheFiles(baseName, scanTask.GetCallerPid());
    }
    return true;
}

void ScanServiceAbility::GeneratePictureBatch(ScanTask &scanTask)
{
    bool firstScan = true;
    int32_t status = E_SCAN_NONE;
    do {
        if (!firstScan) {
            SCAN_HILOGI("not first scan");
            status = RestartScan(scanTask.GetScannerId());
            if (status != E_SCAN_NONE) {
                SCAN_HILOGW("RestartScan fail");
                break;
            }
        }
        if (!CreateAndOpenScanFile(scanTask)) {
            status = E_SCAN_SERVER_FAILURE;
            SCAN_HILOGE("CreateAndOpenScanFile fail");
            break;
        }
        status = DoScanTask(scanTask);
        firstScan = false;
    } while (status == E_SCAN_EOF);
    if (status == E_SCAN_NO_DOCS) {
        SCAN_HILOGI("GeneratePictureBatch exit successfully");
    } else {
        SCAN_HILOGE("GeneratePictureBatch fail, status = %{public}d", status);
        scanPictureData_.SetScanTaskCode(status);
    }
}

void ScanServiceAbility::GeneratePictureSingle(ScanTask &scanTask)
{
    int32_t status = E_SCAN_NONE;
    if (!CreateAndOpenScanFile(scanTask)) {
        status = E_SCAN_SERVER_FAILURE;
        SCAN_HILOGE("CreateAndOpenScanFile fail");
        return;
    }
    status = DoScanTask(scanTask);
    if (status == E_SCAN_EOF) {
        SCAN_HILOGI("GeneratePictureSingle exit successfully");
        scanPictureData_.SetNowScanProgressFinished(true);
    } else {
        SCAN_HILOGE("GeneratePictureSingle fail, status = %{public}d", status);
        scanPictureData_.SetScanTaskCode(status);
    }
}

int32_t ScanServiceAbility::DoScanTask(ScanTask &scanTask)
{
    bool isFirstFrame = true;
    int32_t scanStatus = E_SCAN_NONE;
    ScanParameters parm;
    do {
        SCAN_HILOGI("start DoScanTask");
        if (!isFirstFrame) {
            scanStatus = StartScanOnceInternal(scanTask.GetScannerId());
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGW("restart scanner fail");
                break;
            }
        }
        scanStatus = GetScanParametersInternal(scanTask.GetScannerId(), parm);
        if (scanStatus != E_SCAN_NONE) {
            SCAN_HILOGE("DoScanTask error, after GetScanParameters");
            break;
        }
        if (isFirstFrame) {
            int32_t dpi = 0;
            scanStatus = GetScannerImageDpi(scanTask.GetScannerId(), dpi);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGW("GetScannerImageDpi fail");
            }
            scanStatus = scanTask.WriteImageHeader(parm, static_cast<uint16_t>(dpi));
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGE("StartScanTask error exit after WriteiImageHeader");
                break;
            }
        }
        GetPicFrame(scanTask, scanStatus, parm);
        if (scanStatus != E_SCAN_EOF) {
            SCAN_HILOGE("get scanframe fail");
            break;
        }
        isFirstFrame = false;
    } while (!(parm.GetLastFrame()));
    CleanUpAfterScan(scanTask, scanStatus);
    return scanStatus;
}

int32_t ScanServiceAbility::RestartScan(const std::string &scannerId)
{
    SCAN_HILOGI("RestartScan");
    int32_t status = StartScanOnceInternal(scannerId);
    if (status == E_SCAN_NONE) {
        SCAN_HILOGD("ScanTask restart success");
        scanPictureData_.SetNowScanProgressFinished(false);
        scanPictureData_.PushScanPictureProgress();
    } else if (status == E_SCAN_NO_DOCS) {
        SCAN_HILOGD("The feeder is out of paper.");
        scanPictureData_.SetNowScanProgressFinished(true);
    } else {
        SCAN_HILOGE("restart scan fail");
        scanPictureData_.SetNowScanProgressFinished(false);
        scanPictureData_.PushScanPictureProgress();
        scanPictureData_.SetScanTaskCode(status);
    }
    return status;
}

void ScanServiceAbility::CleanUpAfterScan(ScanTask &scanTask, int32_t scanStatus)
{
    if (scanStatus != E_SCAN_EOF && scanStatus != E_SCAN_NO_DOCS) {
        scanTask.ImageDestroyCompress();
        SCAN_HILOGE("End of failed scan ");
    } else {
        scanTask.ImageFinishCompress();
        SCAN_HILOGI("End of normal scan");
    }
}

void ScanServiceAbility::GetPicFrame(ScanTask &scanTask, int32_t &scanStatus, ScanParameters &parm)
{
    int64_t totalBytes = 0;
    int64_t hundredPercent =
        ((int64_t)parm.GetBytesPerLine()) * parm.GetLines() *
        (((SaneFrame)parm.GetFormat() == SANE_FRAME_RGB || (SaneFrame)parm.GetFormat() == SANE_FRAME_GRAY)
                ? CHANNEL_ONE
                : CHANNEL_THREE);
    scanStatus = E_SCAN_NONE;
    while (scanStatus == E_SCAN_NONE) {
        SanePictureData pictureData;
        SaneStatus saneStatus = SaneManagerClient::GetInstance().SaneRead(scanTask.GetScannerId(),
            BUFFER_SIZE, pictureData);
        scanStatus = HandleSaneStatus(scanTask.GetScannerId(), saneStatus);
        if (pictureData.ret_ == SANE_READ_FAIL) {
            SCAN_HILOGE("sane_read failed, scanStatus: [%{public}d]", scanStatus);
            break;
        }
        scanPictureData_.SetScanProgr(totalBytes, hundredPercent, pictureData.dataBuffer_.size());
        int32_t writeImgDataRet = scanTask.WriteImageData(pictureData.dataBuffer_);
        if (writeImgDataRet != E_SCAN_NONE) {
            SCAN_HILOGE("WriteImageData fail");
            scanStatus = writeImgDataRet;
            break;
        }
        if (scanStatus == SANE_STATUS_EOF) {
            SCAN_HILOGI("sane_read finished.");
            break;
        }
    }
}

int32_t ScanServiceAbility::GetCurrentUserId()
{
    constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
    int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (userId <= 0) {
        SCAN_HILOGD("scan sa calling, use current active userId");
        std::vector<int32_t> userIds;
        AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            SCAN_HILOGE("get use current active userId failed");
            userId = AppExecFwk::Constants::INVALID_USERID;
        } else {
            userId = userIds[0];
        }
    }
    SCAN_HILOGD("Current userId = %{public}d.", userId);
    return userId;
}

int32_t ScanServiceAbility::CheckScannerOwner(const std::string& scannerId)
{
    if (openedScanner_.has_value()) {
        if (openedScanner_->scannerId != scannerId ||
            openedScanner_->callerPid != IPCSkeleton::GetCallingPid() ||
            openedScanner_->userId != GetCurrentUserId()) {
            SCAN_HILOGE("operation denied: scanner opened by another caller");
            return E_SCAN_ACCESS_DENIED;
        }
        return E_SCAN_NONE;
    }
    SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
    return E_SCAN_INVALID_PARAMETER;
}

void ScanServiceAbility::CleanupDeadCaller(int32_t deadPid)
{
    std::lock_guard<std::recursive_mutex> autoLock(lock_);
    if (openedScanner_.has_value() && openedScanner_->callerPid == deadPid) {
        SCAN_HILOGI("cleaning up scanner %{private}s for dead pid %{public}d",
                    openedScanner_->scannerId.c_str(), deadPid);
        SaneManagerClient::GetInstance().SaneCancel(openedScanner_->scannerId);
        SaneManagerClient::GetInstance().SaneClose(openedScanner_->scannerId);
        // Clear the queue so a stale front won't block the next owner.
        scanPictureData_.CleanScanQueue();
        if (scannerState_.load() != SCANNER_READY) {
            // Task still winding down: defer cleanup and release to task end.
            pendingCleanOwner_ = deadPid;
            scannerState_.store(SCANNER_CANCELING);
        } else {
            openedScanner_.reset();
        }
    }
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        for (auto it = registeredListeners_.begin(); it != registeredListeners_.end();) {
            int32_t listenerUserId = -1;
            int32_t listenerCallerPid = -1;
            if (!ScanServiceUtils::DecodeTaskEventId(it->first, listenerUserId, listenerCallerPid)) {
                ++it;
                continue;
            }
            if (listenerCallerPid == deadPid) {
                SCAN_HILOGI("remove listener %{public}s for dead pid %{public}d",
                            it->first.c_str(), deadPid);
                it = registeredListeners_.erase(it);
            } else {
                ++it;
            }
        }
    }
    // Clean now unless deferred to task end.
    if (pendingCleanOwner_ != deadPid) {
        scanPictureData_.CleanByOwner(deadPid);
    }
}

int32_t ScanServiceAbility::GetScannerImageDpi(const std::string& scannerId, int32_t& dpi)
{
    SaneControlParam controlParam;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    SaneOutParam outParam;
    SaneStatus status = SaneManagerClient::GetInstance().SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return HandleSaneStatus(scannerId, status);
    }
    if (outParam.valueNumber_ <= 0 || outParam.valueNumber_ > MAX_SCANNER_PARA_COUNT) {
        SCAN_HILOGE("Invalid option count: [%{public}d]", outParam.valueNumber_);
        return E_SCAN_INVALID_PARAMETER;
    }
    int32_t resolutionIndex = 0;
    for (int32_t optionIndex = 1; optionIndex < outParam.valueNumber_; optionIndex++) {
        SaneOptionDescriptor saneDesc;
        status = SaneManagerClient::GetInstance().SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
        if (status != SANE_STATUS_GOOD) {
            SCAN_HILOGE("SaneGetOptionDescriptor failed, status: [%{public}u]", status);
            return HandleSaneStatus(scannerId, status);
        }
        if ((saneDesc.optionType_ == SCAN_VALUE_NUM)
            && (saneDesc.optionUnit_ == SCANNER_UNIT_DPI)
            && (saneDesc.optionName_ == SANE_NAME_SCAN_RESOLUTION)) {
            resolutionIndex = optionIndex;
            break;
        }
    }
    if (resolutionIndex == 0) {
        SCAN_HILOGE("cannot find dpi option");
        return E_SCAN_SERVER_FAILURE;
    }
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    controlParam.option_ = resolutionIndex;
    status = SaneManagerClient::GetInstance().SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return HandleSaneStatus(scannerId, status);
    }
    dpi = outParam.valueNumber_;
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ExportScanPicture(const std::string scannerId,
    const std::vector<int32_t>& pictureFdList, const int32_t format,
    std::vector<int32_t>& exportedFdList)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ManualStart();
    std::lock_guard<std::recursive_mutex> autoLock(lock_);

    if (pictureFdList.empty()) {
        SCAN_HILOGE("pictureFdList is empty");
        return E_SCAN_INVALID_PARAMETER;
    }

    if (int32_t ownerRet = CheckScannerOwner(scannerId); ownerRet != E_SCAN_NONE) {
        return ownerRet;
    }

    for (int32_t jpegFd : pictureFdList) {
        std::string jpegPath = ScanServiceUtils::GetPathFromFd(jpegFd);
        if (jpegPath.empty()) {
            SCAN_HILOGE("Invalid fd %{public}d, cannot get file path", jpegFd);
            return E_SCAN_INVALID_PARAMETER;
        }
        
        char canonicalPath[PATH_MAX] = {0};
        if (realpath(jpegPath.c_str(), canonicalPath) == nullptr) {
            SCAN_HILOGE("Invalid jpegPath %{private}s, realpath failed", jpegPath.c_str());
            return E_SCAN_INVALID_PARAMETER;
        }
        std::string normalizedPath(canonicalPath);
        
        std::string cachePrefix = "/data/service/el2/" + std::to_string(GetCurrentUserId()) + "/print_service/";
        if (normalizedPath.find(cachePrefix) != 0) {
            SCAN_HILOGE("Invalid jpegPath %{private}s, not in cache directory", jpegPath.c_str());
            return E_SCAN_INVALID_PARAMETER;
        }
        
        std::string baseName = ScanServiceUtils::ExtractBaseName(jpegPath);
        if (baseName.empty() || baseName == jpegPath) {
            SCAN_HILOGE("ExtractBaseName failed for %{private}s", jpegPath.c_str());
            return E_SCAN_INVALID_PARAMETER;
        }
        
        int32_t exportedFd = INVALID_FD;
        int32_t ret = ImageExporter::ExportToFormat(baseName, format, exportedFd, scanPictureData_);
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("ExportToFormat failed, jpegFd=%{public}d, format=%{public}d, ret=%{public}d",
                        jpegFd, format, ret);
            return ret;
        }

        exportedFdList.push_back(exportedFd);
    }

    return E_SCAN_NONE;
}

bool ScanServiceAbility::PrepareBwScan(const std::string& scannerId)
{
    auto it = colorModeSettings_.find(scannerId);
    if (it == colorModeSettings_.end()) {
        return false;
    }

    for (auto& [idx, val] : it->second) {
        if (val.GetScanOptionValueType() != SCAN_VALUE_STR) {
            continue;
        }
        if (val.GetStrValue() != SCAN_MODE_LINEART) {
            continue;
        }
        bool needBinarize = EsclDriverManager::IsEsclScanner(scannerId);
        SCAN_HILOGI("PrepareBwScan: needBinarize=%{public}d", needBinarize);
        return needBinarize;
    }
    return false;
}
}  // namespace OHOS::Scan
