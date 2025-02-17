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
#include "file_ex.h"
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
#include "sane_manager_client.h"
#include "sane_option_descriptor.h"
#include "sane_device.h"
#include "sane_control_param.h"
#include "sane_picture_data.h"

namespace OHOS::Scan {
namespace {
static int32_t GetElapsedSeconds(const SteadyTimePoint& preTime)
{
    auto nowTime = std::chrono::steady_clock::now();
    auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(nowTime - preTime);
    return elapsedTime.count();
}

static int32_t GetRandomNumber(const int32_t& lowerBoundary, const int32_t& upperBoundary)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(lowerBoundary, upperBoundary);
    return dis(gen);
}

static std::string GetLastWord(const std::string& str)
{
    size_t pos = str.find_last_of(' ');
    if (pos == std::string::npos) {
        return str;
    }
    return str.substr(pos + 1);
}
};
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using SteadyTimePoint = std::chrono::steady_clock::time_point;

constexpr int ONE_KB = 1024; // default buffersize 1KB
constexpr int SCAN_PROGRESS_100 = 100;
constexpr int SCAN_PROGRESS_10 = 10;
constexpr int SCAN_PROGRESS_19 = 19;
constexpr int SCAN_PROGRESS_80 = 80;
constexpr int JPEG_QUALITY_SEVENTY_FIVE = 75;
constexpr int CHANNEL_ONE = 1;
constexpr int CHANNEL_THREE = 3;
const int64_t INIT_INTERVAL = 5000L;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t UNLOAD_SYSTEMABILITY_DELAY = 1000 * 30;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t START_USER_ID = 100;
constexpr int32_t MAX_USER_ID = 1099;

static int32_t g_scannerState = SCANNER_READY;
static bool g_hasIoFaild = false;
static bool g_isJpegWriteSuccess = false;
static const std::string PERMISSION_NAME_SCAN = "ohos.permission.SCAN";
static const std::string PERMISSION_NAME_SCAN_JOB = "ohos.permission.MANAGE_SCAN_JOB";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
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
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetUsbDeviceInfoMap;
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetTcpDeviceInfoMap;
std::map<std::string, std::string> ScanServiceAbility::usbSnMap;

ScanServiceAbility::ScanServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START),
    currentJobId_(SCAN_CONSTRAINT_NONE), currentUseScannerUserId_(INVALID_USER_ID)
{
    constexpr int32_t oneHundred = 100;
    buffer_size = ONE_KB * oneHundred;
    saneReadBuf = static_cast<uint8_t *>(malloc(buffer_size));
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
    DELETE_ARRAY_AND_NULLIFY(jpegbuf)
    DELETE_AND_NULLIFY(cinfoPtr);
    DELETE_AND_NULLIFY(ofp);
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
        SCAN_HILOGW("service is not running");
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
        this->ExitScan();
        SaneManagerClient::GetInstance()->UnloadSystemAbility();
        ScanMdnsService::OnStopDiscoverService();
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
        SCAN_HILOGI("unload system ability successfully");
    };
    serviceHandler_->PostTask(unloadTask, UNLOAD_SYSTEMABILITY_DELAY);
}

int32_t ScanServiceAbility::InitScan(int32_t &scanVersion)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    ExitScan();
    SCAN_HILOGI("ScanServiceAbility InitScan start");
    SaneStatus status = SaneManagerClient::GetInstance()->SaneInit();
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneInit failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }
    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    ScanSystemData::GetInstance().Init();
    ScanMdnsService::OnStartDiscoverService();
    SCAN_HILOGI("ScanServiceAbility InitScan end, scanVersion = [%{public}d]", scanVersion);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ExitScan()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility ExitScan start");
    std::lock_guard<std::mutex> autoLock(lock_);
    for (const auto& scannerId : openedScannerList_) {
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
        SaneManagerClient::GetInstance()->SaneClose(scannerId);
    }
    openedScannerList_.clear();
    SaneManagerClient::GetInstance()->SaneExit();
    g_scannerState = SCANNER_READY;
    std::queue<int32_t> empty;
    scanQueue.swap(empty);
    scanTaskMap.clear();
    for (const auto& [imagePath, fd] : imageFdMap_) {
        constexpr int32_t INVALID_FILE_DESCRIPTOR = -1;
        if (fd != INVALID_FILE_DESCRIPTOR) {
            close(fd);
        }
        if (FileExists(imagePath)) {
            unlink(imagePath.c_str());
        }
    }
    imageFdMap_.clear();
    SCAN_HILOGI("ScanServiceAbility ExitScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ReInitScan()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility ReInitScan start");
    SaneManagerClient::GetInstance()->SaneExit();
    openedScannerList_.clear();
    g_scannerState = SCANNER_READY;
    std::queue<int32_t> empty;
    scanQueue.swap(empty);
    scanTaskMap.clear();
    SaneStatus status = SaneManagerClient::GetInstance()->SaneInit();
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneInit failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }

    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    return E_SCAN_NONE;
}

bool ScanServiceAbility::GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId)
{
    static const std::regex pattern(R"(([a-zA-Z0-9_]+):(libusb):([0-9]{3}):([0-9]{3}))");
    std::smatch match;
    constexpr size_t STRING_POS_THREE = 3;
    constexpr size_t STRING_POS_FOUR = 4;
    if (!std::regex_match(deviceId, match, pattern) || match.size() <= STRING_POS_FOUR) {
        SCAN_HILOGE("In USB mode, the deviceId string format does not match");
        return false;
    }
    const std::string firstIdTmp = match[STRING_POS_THREE].str();
    const std::string secondIdTmp = match[STRING_POS_FOUR].str();
    int32_t firstNumTmp = 0;
    int32_t secondNumTmp = 0;
    if (!ScanUtil::ConvertToInt(firstIdTmp, firstNumTmp) ||
        !ScanUtil::ConvertToInt(secondIdTmp, secondNumTmp)) {
        SCAN_HILOGE("parse [%{public}s]:[%{public}s] fail", firstIdTmp.c_str(), secondIdTmp.c_str());
        return false;
    }
    firstId = std::to_string(firstNumTmp);
    secondId = std::to_string(secondNumTmp);
    return true;
}

bool ScanServiceAbility::GetTcpDeviceIp(const std::string &deviceId, std::string &ip)
{
    static const std::regex pattern(R"(([^ ]+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ([^ ]+))");
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

void ScanServiceAbility::SetScannerSerialNumberByTCP(ScanDeviceInfo &info)
{
    info.discoverMode = "TCP";
    std::string ip;
    if (!GetTcpDeviceIp(info.deviceId, ip)) {
        SCAN_HILOGE("cannot get device's ip");
        return;
    }
    int32_t count = 0;
    constexpr int32_t MAX_WAIT_COUNT = 5;
    constexpr int32_t WAIT_TIME = 1;
    ScanDeviceInfoTCP netScannerInfo;
    bool findNetScannerInfoByIp = ScanMdnsService::FindNetScannerInfoByIp(ip, netScannerInfo);
    do {
        sleep(WAIT_TIME);
        SCAN_HILOGW("wait a second");
        findNetScannerInfoByIp = ScanMdnsService::FindNetScannerInfoByIp(ip, netScannerInfo);
        count++;
    } while (!findNetScannerInfoByIp && count < MAX_WAIT_COUNT);
    info.uniqueId = ip;
    if (findNetScannerInfoByIp) {
        info.serialNumber = GetLastWord(netScannerInfo.deviceName);
        info.uuid = netScannerInfo.uuid;
        info.deviceName = netScannerInfo.deviceName;
    } else {
        info.deviceName = info.manufacturer + "-" + info.model;
    }
}

void ScanServiceAbility::SetScannerSerialNumberByUSB(ScanDeviceInfo &info)
{
    info.discoverMode = "USB";
    std::string firstId;
    std::string secondId;
    if (!GetUsbDevicePort(info.deviceId, firstId, secondId)) {
        SCAN_HILOGE("cannot get usb's port");
        return;
    }
    std::string usbScannerPort = firstId + "-" + secondId;
    DelayedSingleton<ScanUsbManager>::GetInstance()->RefreshUsbDevice();
    auto it = usbSnMap.find(usbScannerPort);
    if (it != usbSnMap.end() && it->second != "") {
        SCAN_HILOGD("set serialNumber [%{private}s]", it->second.c_str());
        info.serialNumber = it->second;
        info.uniqueId = it->second;
    } else {
        SCAN_HILOGE("usb can't find serialNumber");
    }
    info.deviceName = info.manufacturer + "-" + info.model + "-" + info.serialNumber;
}

void ScanServiceAbility::SetScannerSerialNumber(ScanDeviceInfo &info)
{
    if (info.deviceId.find(":tcp") != info.deviceId.npos) {
        SetScannerSerialNumberByTCP(info);
    } else if (info.deviceId.find(":libusb") != info.deviceId.npos) {
        SetScannerSerialNumberByUSB(info);
    }  else {
        SCAN_HILOGE("Unknown scanner connect method");
    }
}

void ScanServiceAbility::AddFoundScanner(ScanDeviceInfo& info)
{
    std::lock_guard<std::mutex> autoLock(clearMapLock_);
    if (info.discoverMode != "USB" && info.discoverMode != "TCP") {
        SCAN_HILOGE("discoverMode is invalid:[%{public}s]", info.discoverMode.c_str());
        return;
    }
    if (info.uniqueId.empty() && info.serialNumber.empty()) {
        SCAN_HILOGE("uniqueId and serialNumber are null");
        return;
    }
    std::string uniqueId = info.discoverMode + info.uniqueId;
    ScanSystemData& scanData = ScanSystemData::GetInstance();
    if (info.discoverMode == "USB") {
        scanData.UpdateScannerInfoByUniqueId(uniqueId, info);
    } else {
        scanData.UpdateNetScannerByUuid(info.uuid, info.uniqueId);
    }
    scanData.SaveScannerMap();
    std::map<std::string, ScanDeviceInfo>& deviceMap = info.discoverMode == "USB" ?
        saneGetUsbDeviceInfoMap : saneGetTcpDeviceInfoMap;
    deviceMap[info.serialNumber] = info;
    deviceMap[info.uniqueId] = info;
}

void ScanServiceAbility::SaneGetScanner()
{
    std::lock_guard<std::mutex> autoLock(lock_);
    clearMapLock_.lock();
    saneGetTcpDeviceInfoMap.clear();
    saneGetUsbDeviceInfoMap.clear();
    clearMapLock_.unlock();
    g_scannerState = SCANNER_SEARCHING;
    std::vector<SaneDevice> deviceInfos;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetDevices(deviceInfos);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetDevices failed, ret: [%{public}u]", status);
        g_scannerState = SCANNER_READY;
        return;
    }
    for (const auto& device: deviceInfos) {
        ScanDeviceInfo info;
        info.deviceId = device.name_;
        info.manufacturer = device.vendor_;
        info.model = device.model_;
        info.deviceType = device.type_;
        SetScannerSerialNumber(info);
        AddFoundScanner(info);
    }
    clearMapLock_.lock();
    for (auto &t : saneGetUsbDeviceInfoMap) {
        SendDeviceInfo(t.second, SCAN_DEVICE_FOUND);
        deviceInfos_.emplace_back(t.second);
    }
    for (auto &t : saneGetTcpDeviceInfoMap) {
        SendDeviceInfo(t.second, SCAN_DEVICE_FOUND);
        deviceInfos_.emplace_back(t.second);
    }
    clearMapLock_.unlock();
    g_scannerState = SCANNER_READY;
}

int32_t ScanServiceAbility::GetScannerList()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    auto exec_sane_getscaner = [=]() {
        deviceInfos_.clear();
        SaneGetScanner();
        std::string message = "EOF";
        SendDeviceSearchEnd(message, SCAN_DEVICE_FOUND);
        SendDeviceList(deviceInfos_, GET_SCANNER_DEVICE_LIST);
    };
    serviceHandler_->PostTask(exec_sane_getscaner, ASYNC_CMD_DELAY);
    SCAN_HILOGD("ScanServiceAbility GetScannerList end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StopDiscover()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility StopDiscover start");

    if (ScanMdnsService::OnStopDiscoverService()) {
        SCAN_HILOGD("ScanServiceAbility StopDiscover end successful.");
        return E_SCAN_NONE;
    } else {
        SCAN_HILOGE("ScanServiceAbility StopDiscover fail.");
        return E_SCAN_SERVER_FAILURE;
    }
}

int32_t ScanServiceAbility::OpenScanner(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    if (openedScannerList_.find(scannerId) != openedScannerList_.end()) {
        SCAN_HILOGD("scannerId %{public}s is already opened", scannerId.c_str());
        return E_SCAN_NONE;
    }
    SaneStatus status = SaneManagerClient::GetInstance()->SaneOpen(scannerId);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_open failed, ret: [%{public}u], retry one times", status);
        int32_t ret = ReInitScan();
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("ScanServiceAbility OpenScanner ReInitScan failed !!!");
            return ret;
        }
        status = SaneManagerClient::GetInstance()->SaneOpen(scannerId);
    }

    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneOpen failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }
    openedScannerList_.insert(scannerId);
    SCAN_HILOGI("ScanServiceAbility OpenScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CloseScanner(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility CloseScanner start");
    scanTaskMap.clear();
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    SaneStatus status = SaneManagerClient::GetInstance()->SaneClose(scannerId);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneClose failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }
    openedScannerList_.erase(scannerId);
    SCAN_HILOGI("ScanServiceAbility CloseScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetScanOptionDesc(
    const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility GetScanOptionDesc start");
    SCAN_HILOGD("optionIndex [%{public}d]", optionIndex);
    SaneOptionDescriptor saneDesc;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetOptionDescriptor failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }
    desc.SetOptionName(saneDesc.optionName_);
    desc.SetOptionTitle(saneDesc.optionTitle_);
    desc.SetOptionDesc(saneDesc.optionDesc_);
    desc.SetOptionType(saneDesc.optionType_);
    desc.SetOptionUnit(saneDesc.optionUnit_);
    desc.SetOptionSize(saneDesc.optionSize_);
    desc.SetOptionCap(saneDesc.optionCap_);
    desc.SetOptionConstraintType(saneDesc.optionConstraintType_);
    if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_RANGE) {
        ScanRange scanRange;
        scanRange.SetMinValue(saneDesc.minValue_);
        scanRange.SetMaxValue(saneDesc.maxValue_);
        scanRange.SetQuantValue(saneDesc.quantValue_);
        desc.SetOptionConstraintRange(scanRange);
    } else if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_WORD_LIST) {
        std::vector<int32_t> optionConstraintNumber;
        for (const auto& number : saneDesc.optionConstraintNumber_) {
            SCAN_HILOGD("SANE_CONSTRAINT_WORD_LIST : %{public}d", number);
            optionConstraintNumber.push_back(number);
        }
        desc.SetOptionConstraintNumber(optionConstraintNumber);
    } else if (saneDesc.optionConstraintType_ == SANE_CONSTRAINT_STRING_LIST) {
        std::vector<std::string> optionConstraintString;
        std::vector<std::string>& stringList = saneDesc.optionConstraintString_;
        for (auto& str : stringList) {
            SCAN_HILOGD("SANE_CONSTRAINT_STRING_LIST %{public}s", str.c_str());
            optionConstraintString.push_back(str);
        }
        desc.SetOptionConstraintString(optionConstraintString);
    }
    desc.Dump();
    SCAN_HILOGI("ScanServiceAbility GetScanOptionDesc end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ActionSetAuto(const std::string &scannerId, const int32_t &optionIndex)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_SET_AUTO");
    SaneStatus status = SANE_STATUS_GOOD;
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = static_cast<SaneAction>(SANE_ACTION_SET_AUTO);
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return ScanUtil::ConvertErro(status);
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ActionGetValue(const std::string &scannerId, ScanOptionValue &value,
    const int32_t &optionIndex)
{
    SCAN_HILOGD("Set OpScanOptionValue SCAN_ACTION_GET_VALUE");
    SaneStatus status = SANE_STATUS_GOOD;
    ScanOptionValueType valueType = value.GetScanOptionValueType();
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = static_cast<int32_t>(valueType);
    controlParam.valueSize_ = value.GetValueSize();
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_control_option failed, status: [%{public}d]", status);
        return ScanUtil::ConvertErro(status);
    }
    if (valueType == SCAN_VALUE_NUM) {
        value.SetNumValue(outParam.valueNumber_);
    } else if (valueType == SCAN_VALUE_NUM_LIST) {
        std::vector<int32_t> numListValue = outParam.valueNumList_;
        value.SetNumListValue(numListValue);
    } else if (valueType == SCAN_VALUE_STR) {
        value.SetStrValue(outParam.valueStr_);
    } else if (valueType == SCAN_VALUE_BOOL) {
        value.SetBoolValue(outParam.valueBool_);
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ActionSetValue(const std::string &scannerId, ScanOptionValue &value,
    const int32_t &optionIndex, int32_t &info)
{
    SCAN_HILOGI("Set OpScanOptionValue SCAN_ACTION_SET_VALUE");
    SaneStatus status = SANE_STATUS_GOOD;
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = static_cast<SaneAction>(SANE_ACTION_SET_VALUE);
    controlParam.valueType_ = static_cast<int32_t>(value.GetScanOptionValueType());
    int32_t numValue = value.GetNumValue();
    controlParam.valueNumber_ = numValue;
    constexpr int32_t MAX_PICTURE_DPI = 3000;
    dpi = numValue > 0 && numValue < MAX_PICTURE_DPI ? numValue : dpi;
    controlParam.valueStr_ = value.GetStrValue();
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, ret = [%{public}d]", status);
        return status;
    }
    info = outParam.info_;
    return status;
}

int32_t ScanServiceAbility::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value, int32_t &info)
{
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start");
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("optionIndex [%{public}d]", optionIndex);
    int32_t state = E_SCAN_NONE;

    if (g_hasIoFaild) {
        SCAN_HILOGI("OpScanOptionValue try to reOpenScanner start");
        int32_t openRet = SaneManagerClient::GetInstance()->SaneOpen(scannerId);
        if (openRet != E_SCAN_NONE) {
            SCAN_HILOGE("OpScanOptionValue try to reOpenScanner failed");
            return E_SCAN_DEVICE_BUSY;
        }
        g_hasIoFaild = false;
    }

    std::lock_guard<std::mutex> autoLock(lock_);

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
            state = ActionSetValue(scannerId, value, optionIndex, info);
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
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanParameters start");
    SaneParameters saneParams;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetParameters(scannerId, saneParams);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetParameters failed, status: [%{public}u]", status);
        return ScanUtil::ConvertErro(status);
    }
    para.SetFormat(static_cast<ScanFrame>(saneParams.format_));
    para.SetLastFrame(saneParams.lastFrame_);
    para.SetBytesPerLine(saneParams.bytesPerLine_);
    para.SetPixelsPerLine(saneParams.pixelsPerLine_);
    para.SetLines(saneParams.lines_);
    para.SetDepth(saneParams.depth_);
    para.Dump();
    SCAN_HILOGD("ScanServiceAbility GetScanParameters end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetSingleFrameFD start");
    SCAN_HILOGD("ScanServiceAbility GetSingleFrameFD end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::CancelScan(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan start");
    SaneStatus saneStatus = SaneManagerClient::GetInstance()->SaneCancel(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneCancel failed, status: [%{public}u]", saneStatus);
        return ScanUtil::ConvertErro(saneStatus);
    }
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    if (g_scannerState == SCANNER_SCANING) {
        SCAN_HILOGW("ScannerState change to SCANNER_CANCELING");
        g_scannerState = SCANNER_CANCELING;
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::SetScanIOMode(const std::string scannerId, const bool isNonBlocking)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility SetScanIOMode start");
    SCAN_HILOGE("ScanServiceAbility SetScanIOMode end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetScanSelectFd(const std::string scannerId, int32_t &fd)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanSelectFd start");
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
    constexpr int32_t MAX_LISTENERS_COUNT = 1000;
    if (registeredListeners_.size() > MAX_LISTENERS_COUNT) {
        SCAN_HILOGE("Exceeded the maximum number of registration.");
        return E_SCAN_GENERIC_FAILURE;
    }
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
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("%{public}s event not register", GET_FRAME_RES_EVENT_TYPE.c_str());
        return;
    }
    eventIt->second->OnGetFrameResCallback(isGetSucc, sizeRead);
}

void ScanServiceAbility::SendDeviceInfoTCP(const ScanDeviceInfoTCP &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoTCP parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("GetScannerList SendDeviceInfoTCP event not register");
        return;
    }
    eventIt->second->OnCallback(info.GetDeviceState(), info);
}

void ScanServiceAbility::SendDeviceInfo(const ScanDeviceInfo &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("GetScannerList SendDeviceInfo event not register");
        return;
    }
    eventIt->second->OnCallback(info.GetDeviceState(), info);
}

void ScanServiceAbility::SendDeviceList(std::vector<ScanDeviceInfo> &infos, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfo parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("GetScannerList SendDeviceList event not register");
        return;
    }
    eventIt->second->OnGetDevicesList(infos);
}

void ScanServiceAbility::SendDeviceInfoSync(const ScanDeviceInfoSync &info, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoSync parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("DealUsbDevStatusChange SendDeviceInfoSync event not register");
        return;
    }
    eventIt->second->OnCallbackSync(info.GetDeviceState(), info);
}

void ScanServiceAbility::DisConnectUsbScanner(std::string serialNumber, std::string deviceId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    SCAN_HILOGD("GetScannerList delete end serialNumber:%{private}s newDeviceId:%{public}s",
                serialNumber.c_str(), deviceId.c_str());
#endif
}

void ScanServiceAbility::UpdateScannerId(const ScanDeviceInfoSync& syncInfo)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return;
    }
    SCAN_HILOGD("UpdateScannerId start newDeviceId:[%{private}s]", syncInfo.deviceId.c_str());
    ScanDeviceInfoSync scanDeviceInfoSync = syncInfo;
    std::lock_guard<std::mutex> autoLock(clearMapLock_);
    if (scanDeviceInfoSync.discoverMode == "USB") {
        auto it = saneGetUsbDeviceInfoMap.find(scanDeviceInfoSync.serialNumber);
        if (it != saneGetUsbDeviceInfoMap.end()) {
            it->second.deviceId = syncInfo.deviceId;
        }
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else if (scanDeviceInfoSync.discoverMode == "TCP") {
        std::string oldIp;
        ScanUtil::ExtractIpAddresses(scanDeviceInfoSync.oldDeviceId, oldIp);
        auto it = saneGetTcpDeviceInfoMap.find(oldIp);
        if (it != saneGetTcpDeviceInfoMap.end()) {
            auto info = it->second;
            saneGetTcpDeviceInfoMap.erase(it);
            info.deviceId = scanDeviceInfoSync.deviceId;
            saneGetTcpDeviceInfoMap.insert(std::make_pair(scanDeviceInfoSync.uniqueId, info));
        }
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else {
        SCAN_HILOGE("invalid discover mode %{public}s", scanDeviceInfoSync.discoverMode.c_str());
    }
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("GetScannerList UpdateUsbScannerId serialNumber:%{private}s newDeviceId:%{private}s",
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
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("InitScan SendInitEvent event not register");
        return;
    }
    eventIt->second->OnScanInitCallback(scanVersion);
}

void ScanServiceAbility::SendDeviceSearchEnd(std::string &message, std::string event)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (message.empty() || event.empty()) {
        SCAN_HILOGE("SendDeviceSearchEnd parm has nullptr");
        return;
    }

    auto eventIt = registeredListeners_.find(event);
    if (eventIt == registeredListeners_.end() || eventIt->second == nullptr) {
        SCAN_HILOGE("SCAN_DEVICE_FOUND event not register");
        return;
    }
    eventIt->second->OnSendSearchMessage(message);
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

int32_t ScanServiceAbility::GetScannerState(int32_t &scannerState)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }

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
        SCAN_HILOGI("get scan picture successfully!");
        prog = frontProg;
        int32_t fd = open(prog.GetImageRealPath().c_str(), O_RDONLY);
        prog.SetScanPictureFd(fd);
        imageFdMap_[prog.GetImageRealPath()] = fd;
        prog.Dump();
        scanQueue.pop();
        return E_SCAN_NONE;
    }
    int32_t randomNumber = GetRandomNumber(SCAN_PROGRESS_10, SCAN_PROGRESS_19);
    auto preTime = scanTaskMap[frontPicId].GetScanTime();
    if (GetElapsedSeconds(preTime) >= 1 && scanProgress < SCAN_PROGRESS_80) {
        scanTaskMap[frontPicId].SetScanProgress(scanProgress + randomNumber);
        scanTaskMap[frontPicId].SetScanTime(std::chrono::steady_clock::now());
    }
    prog = scanTaskMap[frontPicId];
    prog.Dump();
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (discoverMode != "USB" && discoverMode != "TCP") {
        SCAN_HILOGE("discoverMode is a invalid parameter.");
        return E_SCAN_INVALID_PARAMETER;
    }
    auto addScannerExe = [=]() {
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
    };
    serviceHandler_->PostTask(addScannerExe, ASYNC_CMD_DELAY);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
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
    SendDeviceInfo(scannerInfo, SCAN_DEVICE_DEL);
    SCAN_HILOGI("ScanServiceAbility DeleteScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner start");
    ScanSystemData::GetInstance().GetAddedScannerInfoList(allAddedScanner);
    SCAN_HILOGI("ScanServiceAbility GetAddedScanner end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::UpdateScannerName(const std::string& serialNumber,
    const std::string& discoverMode, const std::string& deviceName)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility UpdateScannerName start");

    std::string uniqueId = discoverMode + serialNumber;
    if (!ScanSystemData::GetInstance().UpdateScannerNameByUniqueId(uniqueId, deviceName)) {
        SCAN_HILOGE("ScanServiceAbility UpdateScannerNameByUniqueId fail");
        return E_SCAN_INVALID_PARAMETER;
    }
    if (!ScanSystemData::GetInstance().SaveScannerMap()) {
        SCAN_HILOGE("ScanServiceAbility UpdateScannerName SaveScannerMap fail");
        return E_SCAN_GENERIC_FAILURE;
    }
    SCAN_HILOGI("ScanServiceAbility UpdateScannerName end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::OnStartScan(const std::string scannerId, const bool &batchMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    std::string userCachedImageDir = ObtainUserCacheDirectory(GetCurrentUserId());
    if (!std::filesystem::exists(userCachedImageDir)) {
        SCAN_HILOGE("The user directory %{public}s does not exist.", userCachedImageDir.c_str());
        return E_SCAN_GENERIC_FAILURE;
    }
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    int32_t status = StartScan(scannerId, batchMode_);
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("Start Scan error");
        return status;
    }
    currentUseScannerUserId_ = GetCurrentUserId();
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility StartScan start");

    if (g_scannerState == SCANNER_CANCELING) {
        SCAN_HILOGE("scan task is canceling");
        return E_SCAN_DEVICE_BUSY;
    }
    SaneStatus saneStatus = SaneManagerClient::GetInstance()->SaneStart(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneStart failed, status is %{public}u", saneStatus);
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
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
    SCAN_HILOGI("ScanServiceAbility StartScan end");
    return E_SCAN_NONE;
}

void ScanServiceAbility::StartScanTask(const std::string scannerId)
{
    SCAN_HILOGI("ScanServiceAbility StartScanTask start, batchMode_ = [%{public}d]", batchMode_);
    int32_t status = E_SCAN_NONE;
    std::string fileName;
    std::string outputFile;
    ScanProgress* scanProPtr = nullptr;
    if (batchMode_) {
        SCAN_HILOGI("start batch mode scan");
        GeneratePictureBatch(scannerId, fileName, outputFile, status, scanProPtr);
    } else {
        SCAN_HILOGI("start single mode scan");
        GeneratePictureSingle(scannerId, fileName, outputFile, status, scanProPtr);
    }
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        SCAN_HILOGI("StartScanTask finished, doning sane_cancel");
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
    }
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceAbility StartScanTask error, errorcode = [%{public}d]", status);
    }
    g_scannerState = SCANNER_READY;
    SCAN_HILOGI("ScanServiceAbility StartScanTask end");
}

bool ScanServiceAbility::CreateAndOpenScanFile(std::string &outputFile, const int32_t &nowScanId)
{
    std::string outputDir = ObtainUserCacheDirectory(currentUseScannerUserId_);
    char canonicalPath[PATH_MAX] = { 0 };
    if (realpath(outputDir.c_str(), canonicalPath) == nullptr) {
        SCAN_HILOGE("The real output dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    outputDir = canonicalPath;
    outputFile = outputDir.append("/scan_tmp").append(std::to_string(nowScanId)).append(".jpg");
    if ((ofp = fopen(outputFile.c_str(), "w")) == nullptr) {
        SCAN_HILOGE("file [%{private}s] open fail", outputFile.c_str());
        return false;
    }
    return true;
}

void ScanServiceAbility::GeneratePictureBatch(const std::string &scannerId, std::string &fileName,
    std::string &outputFile, int32_t &status, ScanProgress* &scanProPtr)
{
    bool firstScan = true;
    do {
        if (!firstScan) {
            SCAN_HILOGI("not first scan");
            if ((status = StartScan(scannerId, batchMode_)) != E_SCAN_NONE) {
                SCAN_HILOGW("ScanTask restart fail");
                break;
            }
            auto it = scanTaskMap.find(nextPicId - 2);  // nextPicId - 2 is to find a PicId before nowScanId.
            if (it != scanTaskMap.end()) {
                it->second.SetIsFinal(false);
                it->second.SetScanProgress(SCAN_PROGRESS_100);
            }
            SCAN_HILOGI("ScanTask restart success");
        }
        auto it = scanTaskMap.find(nextPicId - 1); // nextPicId - 2 is nowScanId
        if (it == scanTaskMap.end()) {
            SCAN_HILOGE("Scan task not found for PicId: %{public}d", nextPicId - 1);
            status = E_SCAN_GENERIC_FAILURE;
            break;
        }
        int32_t nowScanId = it->first;
        scanProPtr = &(it->second);
        if (!CreateAndOpenScanFile(outputFile, nowScanId)) {
            status = E_SCAN_GENERIC_FAILURE;
            break;
        }
        status = DoScanTask(scannerId, scanProPtr);
        if (ofp != nullptr) {
            fclose(ofp);
            ofp = nullptr;
        }
        scanProPtr->SetImageRealPath(outputFile);
        firstScan = false;
    } while (status == E_SCAN_EOF);
    if (status == E_SCAN_NO_DOCS) {
        auto it = scanTaskMap.find(nextPicId - 1);
        if (it != scanTaskMap.end()) {
            it->second.SetScanProgress(SCAN_PROGRESS_100);
        }
        status = E_SCAN_NONE;
        SCAN_HILOGI("ScanTask batch mode exit successfully.");
    } else {
        scanProPtr->SetTaskCode(static_cast<ScanErrorCode>(status));
    }
}

void ScanServiceAbility::GeneratePictureSingle(const std::string &scannerId, std::string &fileName,
    std::string &outputFile, int32_t &status, ScanProgress* &scanProPtr)
{
    auto it = scanTaskMap.find(nextPicId - 1);
    if (it == scanTaskMap.end()) {
        SCAN_HILOGE("Scan task not found for PicId: %{public}d", nextPicId - 1);
        status = E_SCAN_GENERIC_FAILURE;
        return;
    }
    int32_t nowScanId = it->first;
    scanProPtr = &(it->second);

    if (!CreateAndOpenScanFile(outputFile, nowScanId)) {
        status = E_SCAN_GENERIC_FAILURE;
        return;
    }

    status = DoScanTask(scannerId, scanProPtr);
    if (status == E_SCAN_EOF) {
        scanProPtr->SetImageRealPath(outputFile);
        scanProPtr->SetScanProgress(SCAN_PROGRESS_100);
        status = E_SCAN_NONE;
    }
    if (ofp != nullptr) {
        fclose(ofp);
        ofp = nullptr;
    }
}


int32_t ScanServiceAbility::DoScanTask(const std::string scannerId, ScanProgress* scanProPtr)
{
    bool isFirstFrame = true;
    int32_t scanStatus = E_SCAN_NONE;
    ScanParameters parm;
    struct jpeg_error_mgr jerr;
    do {
        SCAN_HILOGI("start DoScanTask");
        if (!isFirstFrame && (scanStatus = StartScan(scannerId, batchMode_)) != E_SCAN_NONE) {
            SCAN_HILOGW("restart scanner fail");
            break;
        }
        if ((scanStatus = GetScanParameters(scannerId, parm)) != E_SCAN_NONE) {
            SCAN_HILOGE("DoScanTask error, after GetScanParameters");
            break;
        }
        if (isFirstFrame) {
            scanStatus = WriteJpegHeader(parm, &jerr);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGE("StartScanTask error exit after WriteJpegHeader");
                break;
            }
            jpegbuf = new (std::nothrow) JSAMPLE[parm.GetBytesPerLine() / sizeof(JSAMPLE)]{};
            if (jpegbuf == nullptr) {
                SCAN_HILOGE("jpegbuf malloc fail");
                break;
            }
        }
        GetPicFrame(scannerId, scanProPtr, scanStatus, parm);
        if (scanStatus != E_SCAN_EOF) {
            SCAN_HILOGE("get scanframe fail");
            scanStatus = scanStatus == E_SCAN_CANCELLED ? E_SCAN_NONE : scanStatus;
            break;
        }
        isFirstFrame = false;
    } while (!(parm.GetLastFrame()));
    if (scanStatus != E_SCAN_EOF && scanStatus != E_SCAN_NO_DOCS) {
        jpeg_destroy_compress(cinfoPtr);
        scanProPtr->SetTaskCode(static_cast<ScanErrorCode>(scanStatus));
    } else {
        jpeg_finish_compress(cinfoPtr);
        fflush(ofp);
    }
    DELETE_ARRAY_AND_NULLIFY(jpegbuf)
    return scanStatus;
}

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

void ScanServiceAbility::SetScanProgr(int64_t &totalBytes, const int64_t& hundredPercent,
    ScanProgress* scanProPtr, const int32_t& curReadSize)
{
    if (hundredPercent == 0) {
        SCAN_HILOGE("hundredPercent equals zero.");
        return;
    }
    if (scanProPtr == nullptr) {
        SCAN_HILOGE("scanProPtr is a nullptr.");
        return;
    }
    totalBytes += static_cast<int64_t>(curReadSize);
    int64_t progr = ((totalBytes * SCAN_PROGRESS_100) / hundredPercent);
    if (progr >= SCAN_PROGRESS_100) {
        progr = SCAN_PROGRESS_100 - 1;
    }
    if (progr > (scanProPtr->GetScanProgress())) {
        scanProPtr->SetScanProgress(static_cast<int32_t>(progr));
    }
}

void ScanServiceAbility::GetPicFrame(const std::string scannerId, ScanProgress *scanProPtr,
    int32_t &scanStatus, ScanParameters &parm)
{
    int64_t totalBytes = 0;
    int jpegrow = 0;
    int64_t hundredPercent = ((int64_t)parm.GetBytesPerLine()) * parm.GetLines() * (((SaneFrame)parm.GetFormat()
        == SANE_FRAME_RGB || (SaneFrame)parm.GetFormat() == SANE_FRAME_GRAY) ? CHANNEL_ONE : CHANNEL_THREE);
    scanStatus = E_SCAN_GOOD;
    while (scanStatus == E_SCAN_GOOD) {
        SanePictureData pictureData;
        SaneStatus saneStatus = SaneManagerClient::GetInstance()->
            SaneRead(scannerId, buffer_size, pictureData);
        scanStatus = ScanUtil::ConvertErro(saneStatus);
        if (pictureData.size_ == INVALID_DATA) {
            SCAN_HILOGE("sane_read failed, scanStatus: [%{public}d]", scanStatus);
            if (scanStatus == E_SCAN_CANCELLED) {
                std::queue<int32_t> emptyQueue;
                scanQueue.swap(emptyQueue);
                nextPicId--;
                scanTaskMap.erase(nextPicId);
                SCAN_HILOGW("scan task is canceled");
                break;
            }
            if (scanStatus == E_SCAN_IO_ERROR || scanStatus == E_SCAN_JAMMED) {
                CleanScanTask(scannerId);
            }
            scanProPtr->SetTaskCode(static_cast<ScanErrorCode>(scanStatus));
            break;
        }
        auto ret = memcpy_s(saneReadBuf, buffer_size, pictureData.valueBuffer_.data(), pictureData.valueBuffer_.size());
        if (ret != ERR_OK) {
            scanProPtr->SetTaskCode(E_SCAN_GENERIC_FAILURE);
            scanStatus = E_SCAN_GENERIC_FAILURE;
            SCAN_HILOGE("memcpy_s failed, errorCode:[%{public}d]", ret);
            break;
        }
        SetScanProgr(totalBytes, hundredPercent, scanProPtr, pictureData.size_);
        if (!WritePicData(jpegrow, pictureData.size_, parm, scanProPtr)) {
            scanStatus = E_SCAN_GENERIC_FAILURE;
            SCAN_HILOGE("WritePicData fail");
            break;
        }
        if (scanStatus == SANE_STATUS_EOF) {
            SCAN_HILOGI("sane_read finished.");
            break;
        }
    }
}

bool ScanServiceAbility::WritePicData(int &jpegrow, int32_t curReadSize, ScanParameters &parm, ScanProgress *scanProPtr)
{
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
                buf8[col1 * byteBits + col8] = jpegbuf[col1] & (1 << (byteBits - col8 - bit)) ? 0 : 0xff;
            }
        }
        jpeg_write_scanlines(cinfoPtr, &buf8, bit);
        free(buf8);
        i += parm.GetBytesPerLine() - jpegrow;
        left -= parm.GetBytesPerLine() - jpegrow;
        jpegrow = 0;
    }
    if (memcpy_s(jpegbuf + jpegrow, parm.GetBytesPerLine(), saneReadBuf + i, left) != ERR_OK) {
        scanProPtr->SetTaskCode(E_SCAN_GENERIC_FAILURE);
        SCAN_HILOGE("memcpy_s failed");
        return false;
    }
    jpegrow += left;
    return true;
}

int32_t ScanServiceAbility::GetCurrentUserId()
{
    constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
    int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (userId < START_USER_ID || userId > MAX_USER_ID) {
        SCAN_HILOGE("userId %{public}d is out of range.", userId);
        return INVALID_USER_ID;
    }
    SCAN_HILOGD("Current userId = %{public}d.", userId);
    return userId;
}

std::string ScanServiceAbility::ObtainUserCacheDirectory(const int32_t& userId)
{
    if (userId < START_USER_ID || userId > MAX_USER_ID) {
        SCAN_HILOGE("Invalid userId %{public}d.", userId);
        return "";
    }
    std::ostringstream oss;
    oss << "/data/service/el2/" << userId << "/print_service";
    return oss.str();
}

}  // namespace OHOS::Scan