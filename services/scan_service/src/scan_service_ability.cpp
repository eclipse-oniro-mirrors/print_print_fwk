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
#include "scan_service_utils.h"
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
#include "scan_log.h"
#include "os_account_manager.h"

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

static int32_t g_scannerState = SCANNER_READY;
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
static const std::string GET_SCANNER_DEVICE_LIST = "GET_SCANNER_DEVICE_LIST";

std::map<std::string, sptr<IScanCallback>> OHOS::Scan::ScanServiceAbility::registeredListeners_;

REGISTER_SYSTEM_ABILITY_BY_ID(ScanServiceAbility, SCAN_SERVICE_ID, true);

std::mutex ScanServiceAbility::instanceLock_;
sptr<ScanServiceAbility> ScanServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> ScanServiceAbility::serviceHandler_;
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetUsbDeviceInfoMap;
std::map<std::string, ScanDeviceInfo> ScanServiceAbility::saneGetTcpDeviceInfoMap;

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
    auto unloadTask = [this]() {
        if (appCount_.load() != 0) {
            SCAN_HILOGW("appCount = %{public}d is not equal to zerro", appCount_.load());
            return;
        }
        SaneManagerClient::GetInstance()->UnloadSystemAbility();
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
    };
    serviceHandler_->PostTask(unloadTask, UNLOAD_SYSTEMABILITY_DELAY);
}

int32_t ScanServiceAbility::InitScan()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (appCount_.load() == 0) {
        InitializeScanService();
    }
    appCount_.fetch_add(1);
    SCAN_HILOGD("appCount = %{public}d", appCount_.load());
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::ExitScan()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    appCount_.fetch_sub(1);
    SCAN_HILOGD("appCount = %{public}d", appCount_.load());
    if (appCount_.load() == 0) {
        CleanupScanService();
        UnloadSystemAbility();
    }
    return E_SCAN_NONE;
}

void ScanServiceAbility::InitializeScanService()
{
    SaneManagerClient::GetInstance()->SaneInit();
    DelayedSingleton<ScanUsbManager>::GetInstance()->Init();
    ScanSystemData::GetInstance().Init();
    ScanMdnsService::OnStartDiscoverService();
}

void ScanServiceAbility::CleanupScanService()
{
    std::lock_guard<std::mutex> autoLock(lock_);
    for (const auto& scannerId : openedScannerList_) {
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
        SaneManagerClient::GetInstance()->SaneClose(scannerId);
    }
    openedScannerList_.clear();
    SaneManagerClient::GetInstance()->SaneExit();
    ScanMdnsService::OnStopDiscoverService();
    g_scannerState = SCANNER_READY;
    std::queue<int32_t> empty;
    scanQueue.swap(empty);
    scanTaskMap.clear();
    for (const auto& [imagePath, fd] : imageFdMap_) {
        constexpr int32_t INVALID_FILE_DESCRIPTOR = -1;
        if (fd != INVALID_FILE_DESCRIPTOR) {
            fdsan_close_with_tag(fd, SCAN_LOG_DOMAIN);
        }
        if (FileExists(imagePath)) {
            unlink(imagePath.c_str());
        }
    }
    imageFdMap_.clear();
}

bool ScanServiceAbility::GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId)
{
    std::vector<string> tokens;
    char delimiter = ':';
    size_t start = 0;
    size_t end = deviceId.find(delimiter);
    while(end != std::string::npos) {
        tokens.push_back(deviceId.substr(start, end - start));
        start = end + 1;
        end = deviceId.find(delimiter, start);
    }
    tokens.push_back(deviceId.substr(start));
    constexpr size_t TOKEN_SIZE_FOUR = 4;
    constexpr size_t STRING_POS_ONE = 1;
    constexpr size_t STRING_POS_TWO = 2;
    constexpr size_t STRING_POS_THREE = 3;
    if (tokens.size() < TOKEN_SIZE_FOUR || tokens[STRING_POST_ONE] != "libusb") {
        SCAN_HILOGE("parse [%{public}s] fail", deviceId.c_str());
        return false;
    }
    static const std::regex pattern(R"(([0-9]{3}))");
    if (!std::regex_match(tokens[STRING_POS_TWO], pattern) ||
        !std::regex_match(tokens[STRING_POS_THREE], pattern)) {
        SCAN_HILOGE("parse [%{public}s]:[%{public}s] fail", tokens[STRING_POS_TWO].c_str(), tokens[STRING_POS_THREE].c_str());
        return false;
    }
    int32_t firstNumTmp = 0;
    int32_t secondNumTmp = 0;
    const std::string firstIdTmp = tokens[STRING_POS_TWO];
    const std::string secondIdTmp = tokens[STRING_POS_THREE];
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
    std::vector <std::string> tokens;
    size_t start = 0;
    char delimiter = ' ';
    size_t end = deviceId.find(delimiter);
    while (end != std::string::npos) {
        tokens.push_back(deviceId.substr(start, end - start));
        start = end + 1;
        end = deviceId.find(delimiter, start);
    }
    tokens.push_back(deviceId.substr(start));
    constexpr size_t TOKEN_SIZE_2 = 2;
    if (tokens.size() < TOKEN_SIZE_2) {
        SCAN_HILOGE("In TCP mode, the deviceId string format does not match, size < 2");
        return false;
    }
    constexpr size_t STRING_POS_ONE = 1;
    std::string rawIp = tokens[STRING_POS_ONE];
    static const std::regex pattern(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    std::smatch match;
    if (std::regex_match(rawIp, match, pattern)) {
        constexpr
        size_t STRING_POS_ZERO = 0;
        ip = match[STRING_POS_ZERO];
        return true;
    } else {
        SCAN_HILOGE("In TCP mode, the deviceId string format does not match, ip invalid form");
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
    if (serialNumber.empty()) {
        std::ostringstream oss;
        oss << "USB-" << info.manufacturer << " " << info.model << " " << usbScannerPort;
        info.deviceName = oss.str();
    } else {
        info.serialNumber = serialNumber;
        info.uniqueId = serialNumber;
        info.deviceName = scanUsbManager->GetScannerNameBySn(serialNumber);
    }
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
    if (info.GetDeviceAvailable() == false) {
        SCAN_HILOGE("device is unavailable");
        return;
    }
    if (info.discoverMode != "USB" && info.discoverMode != "TCP") {
        SCAN_HILOGE("discoverMode is invalid:[%{public}s]", info.discoverMode.c_str());
        return;
    }
    std::map<std::string, ScanDeviceInfo>& deviceMap = info.discoverMode == "USB" ?
        saneGetUsbDeviceInfoMap : saneGetTcpDeviceInfoMap;
    if (info.uniqueId.empty()) {
        info.uniqueId = info.deviceId;
    } else {
        std::string uniqueId = info.discoverMode + info.uniqueId;
        ScanSystemData& scanData = ScanSystemData::GetInstance();
        if (info.discoverMode == "USB") {
            scanData.UpdateScannerInfoByUniqueId(uniqueId, info);
        } else {
            scanData.UpdateNetScannerByUuid(info.uuid, info.uniqueId);
        }
        scanData.SaveScannerMap();
    }
    deviceMap[info.uniqueId] = info;
}

void ScanServiceAbility::SaneGetScanner()
{
    clearMapLock_.lock();
    saneGetTcpDeviceInfoMap.clear();
    saneGetUsbDeviceInfoMap.clear();
    clearMapLock_.unlock();
    std::vector<SaneDevice> deviceInfos;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetDevices(deviceInfos);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetDevices failed, ret: [%{public}u]", status);
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
    CleanupScanService();
    InitializeScanService();
    SCAN_HILOGD("ScanServiceAbility GetScannerList start");
    std::lock_guard<std::mutex> autoLock(lock_);
    auto exec_sane_getscaner = [=]() {
        deviceInfos_.clear();
        SaneGetScanner();
        SendDeviceList(deviceInfos_, GET_SCANNER_DEVICE_LIST);
    };
    serviceHandler_->PostTask(exec_sane_getscaner, ASYNC_CMD_DELAY);
    SCAN_HILOGD("ScanServiceAbility GetScannerList end");
    return E_SCAN_NONE;
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
    if (openedScannerList_.find(scannerId) != openedScannerList_.end()) {
        SCAN_HILOGD("scannerId %{private}s is already opened", scannerId.c_str());
        return E_SCAN_NONE;
    }
    SaneStatus status = SaneManagerClient::GetInstance()->SaneOpen(scannerId);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("sane_open failed, ret: [%{public}u], retry one times", status);
        status = SaneManagerClient::GetInstance()->SaneOpen(scannerId);
    }

    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneOpen failed, status: [%{public}u]", status);
        return ScanServiceUtils::ConvertErro(status);
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
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    scanTaskMap.clear();
    std::queue<int32_t> emptyQueue;
    scanQueue.swap(emptyQueue);
    SaneStatus status = SaneManagerClient::GetInstance()->SaneClose(scannerId);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneClose failed, status: [%{public}u]", status);
        return ScanServiceUtils::ConvertErro(status);
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
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    SaneOptionDescriptor saneDesc;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetOptionDescriptor failed, status: [%{public}u]", status);
        return ScanServiceUtils::ConvertErro(status);
    }
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
        return ScanServiceUtils::ConvertErro(status);
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
        return ScanServiceUtils::ConvertErro(status);
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

int32_t ScanServiceAbility::ActionSetValue(const std::string &scannerId, ScanOptionValue &value,
    const int32_t &optionIndex)
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
        return ScanServiceUtils::ConvertErro(status);
    }
    return status;
}

int32_t ScanServiceAbility::OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value)
{
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start");
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    int32_t state = E_SCAN_NONE;
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
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    SCAN_HILOGD("ScanServiceAbility GetScanParameters start");
    SaneParameters saneParams;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetParameters(scannerId, saneParams);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetParameters failed, status: [%{public}u]", status);
        return ScanServiceUtils::ConvertErro(status);
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

int32_t ScanServiceAbility::CancelScan(const std::string scannerId)
{
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    SCAN_HILOGI("ScanServiceAbility CancelScan start");
    SaneStatus saneStatus = SaneManagerClient::GetInstance()->SaneCancel(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneCancel failed, status: [%{public}u]", saneStatus);
        return ScanServiceUtils::ConvertErro(saneStatus);
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

int32_t ScanServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
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
        SCAN_HILOGD("ScanServiceAbility::On Replace listener.");
        it->second = listener;
    }
    SCAN_HILOGD("ScanServiceAbility::On end.");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::Off(const std::string taskId, const std::string &type)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
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
    SCAN_HILOGI("SendDeviceInfo [%{private}s], event = %{public}s",
        info.deviceId.c_str(), event.c_str());
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

    if (event.empty()) {
        SCAN_HILOGE("SendDeviceInfoSync parm has nullptr");
        return;
    }

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
    ManualStart();
    std::lock_guard<std::mutex> autoLock(lock_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    if (scanQueue.empty()) {
        SCAN_HILOGE("Not exist scan progress");
        return E_SCAN_GENERIC_FAILURE;
    }
    int32_t frontPicId = scanQueue.front();
    SCAN_HILOGD("frontPicId : [%{public}d]", frontPicId);
    auto frontProg = scanTaskMap[frontPicId];
    auto taskCode = frontProg.GetTaskCode();
    if (taskCode != E_SCAN_NONE) {
        SCAN_HILOGE("scanprogress exception occurred:[%{public}u]", taskCode);
        scanQueue.pop();
        return taskCode;
    }
    auto scanProgress = frontProg.GetScanProgress();
    if (scanProgress == SCAN_PROGRESS_100) {
        SCAN_HILOGI("get scan picture successfully!");
        prog = frontProg;
        int32_t fd = open(prog.GetImageRealPath().c_str(), O_RDONLY);
        fdsan_exchange_owner_tag(fd, 0, SCAN_LOG_DOMAIN);
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

int32_t ScanServiceAbility::OnStartScan(const std::string scannerId, const bool &batchMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
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
        return ScanServiceUtils::ConvertErro(saneStatus);
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
    if (batchMode_) {
        SCAN_HILOGI("start batch mode scan");
        GeneratePictureBatch(scannerId);
    } else {
        SCAN_HILOGI("start single mode scan");
        GeneratePictureSingle(scannerId);
    }
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        SCAN_HILOGI("StartScanTask finished, doning sane_cancel");
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
    }
    g_scannerState = SCANNER_READY;
    SCAN_HILOGI("ScanServiceAbility StartScanTask end");
}

bool ScanServiceAbility::CreateAndOpenScanFile(std::string &outputFile)
{
    std::string outputDir = ObtainUserCacheDirectory(currentUseScannerUserId_);
    char canonicalPath[PATH_MAX] = { 0 };
    if (realpath(outputDir.c_str(), canonicalPath) == nullptr) {
        SCAN_HILOGE("The real output dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    outputDir = canonicalPath;
    std::ostringstream outputFileStream;
    int32_t nowScanId = nextPicId - 1;
    outputFileStream << outputDir << "/" << "scan_tmp" << std::to_string(nowScanId) << ".jpg";
    outputFile = outputFileStream.str();
    if ((ofp = fopen(outputFile.c_str(), "w")) == nullptr) {
        SCAN_HILOGE("file [%{private}s] open fail", outputFile.c_str());
        return false;
    }
    std::lock_guard<std::mutex> autoLock(lock_);
    auto it = scanTaskMap.find(nowScanId);
    if (it == scanTaskMap.end()) {
        SCAN_HILOGE("cannot find nowScanId %{private}d", nowScanId);
        return false;
    }
    it->second.SetImageRealPath(outputFile);
    return true;
}

void ScanServiceAbility::GeneratePictureBatch(const std::string &scannerId)
{
    bool firstScan = true;
    std::string outputFile;
    int32_t status = E_SCAN_NONE;
    do {
        if (!firstScan) {
            SCAN_HILOGI("not first scan");
            status = RestartScan(scannerId);
            if (status != E_SCAN_NONE) {
                SCAN_HILOGW("RestartScan fail");
                break;
            }
        }
        if (!CreateAndOpenScanFile(outputFile)) {
            status = E_SCAN_GENERIC_FAILURE;
            SCAN_HILOGE("CreateAndOpenScanFile fail");
            break;
        }
        status = DoScanTask(scannerId);
        firstScan = false;
    } while (status == E_SCAN_EOF);
    if (status == E_SCAN_NO_DOCS) {
        SCAN_HILOGI("GeneratePictureBatch exit successfully");
    } else {
        SCAN_HILOGE("GeneratePictureBatch fail, status = %{public}d", status);
    }
}

void ScanServiceAbility::GeneratePictureSingle(const std::string &scannerId)
{
    int32_t status = E_SCAN_NONE;
    std::string outputFile;
    if (!CreateAndOpenScanFile(outputFile)) {
        status = E_SCAN_GENERIC_FAILURE;
        SCAN_HILOGE("CreateAndOpenScanFile fail");
        return;
    }
    status = DoScanTask(scannerId);
    if (status == E_SCAN_EOF) {
        SCAN_HILOGI("GeneratePictureSingle exit successfully");
    } else {
        SCAN_HILOGE("GeneratePictureSingle fail, status = %{public}d", status);
    }
}

int32_t ScanServiceAbility::DoScanTask(const std::string &scannerId)
{
    bool isFirstFrame = true;
    int32_t scanStatus = E_SCAN_NONE;
    ScanParameters parm;
    struct jpeg_error_mgr jerr;
    do {
        SCAN_HILOGI("start DoScanTask");
        if (!isFirstFrame) {
            scanStatus = StartScan(scannerId, batchMode_);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGW("restart scanner fail");
                break;
            }
        }
        scanStatus = GetScanParameters(scannerId, parm);
        if (scanStatus != E_SCAN_NONE) {
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
        GetPicFrame(scannerId, scanStatus, parm);
        if (scanStatus != E_SCAN_EOF) {
            SCAN_HILOGE("get scanframe fail");
            break;
        }
        isFirstFrame = false;
    } while (!(parm.GetLastFrame()));
    CleanUpAfterScan(scanStatus);
    return scanStatus;
}

int32_t ScanServiceAbility::RestartScan(const std::string &scannerId)
{
    SCAN_HILOGI("not first scan");
    int32_t status = StartScan(scannerId, batchMode_);
    if (status == E_SCAN_NONE) {
        SCAN_HILOGI("ScanTask restart success");
        std::lock_guard<std::mutex> autoLock(lock_);
        auto it = scanTaskMap.find(nextPicId - 2);
        if (it != scanTaskMap.end()) {
            it->second.SetIsFinal(false);
        }
    } else if (status == E_SCAN_NO_DOCS) {
        SCAN_HILOGI("The feeder is out of paper.");
    } else {
        std::lock_guard<std::mutex> autoLock(lock_);
        SCAN_HILOGE("RestartScan fail");
        scanQueue.push(nextPicId);
        ScanProgress prog;
        auto result = scanTaskMap.insert({nextPicId, prog});
        if (result.second) {
            auto it = result.first;
            it->second.SetPictureId(nextPicId);
            auto nowTime = std::chrono::steady_clock::now();
            it->second.SetScanTime(nowTime);
        }
        nextPicId++;
    }
    return status;
}

void ScanServiceAbility::CleanUpAfterScan(int32_t scanStatus)
{
    int32_t nowScanId = nextPicId - 1;
    if (scanStatus != E_SCAN_EOF && scanStatus != E_SCAN_NO_DOCS) {
        std::lock_guard<std::mutex> autoLock(lock_);
        auto it = scanTaskMap.find(nowScanId);
        if (it != scanTaskMap.end()) {
            it->second.SetTaskCode(static_cast<ScanErrorCode>(scanStatus));
        }
        jpeg_destroy_compress(cinfoPtr);
        SCAN_HILOGE("DoScanTask fail, SetTaskCode : %{public}d", scanStatus);
    } else {
        std::lock_guard<std::mutex> autoLock(lock_);
        auto it = scanTaskMap.find(nowScanId);
        if (it != scanTaskMap.end()) {
            it->second.SetScanProgress(SCAN_PROGRESS_100);
        }
        jpeg_finish_compress(cinfoPtr);
        fflush(ofp);
        SCAN_HILOGD("End of normal scan");
    }
    DELETE_ARRAY_AND_NULLIFY(jpegbuf)
    if (ofp != nullptr) {
        fclose(ofp);
        ofp = nullptr;
    }
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

void ScanServiceAbility::SetScanProgr(int64_t &totalBytes, const int64_t& hundredPercent, const int32_t& curReadSize)
{
    if (hundredPercent == 0) {
        SCAN_HILOGE("hundredPercent equals zero.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(lock_);
    int32_t nowScanId = nextPicId - 1;
    auto it = scanTaskMap.find(nowScanId);
    if (it == scanTaskMap.end()) {
        SCAN_HILOGW("cannot find %{public}d", nowScanId);
        return;
    }
    totalBytes += static_cast<int64_t>(curReadSize);
    int64_t progr = ((totalBytes * SCAN_PROGRESS_100) / hundredPercent);
    if (progr >= SCAN_PROGRESS_100) {
        progr = SCAN_PROGRESS_100 - 1;
    }
    if (progr > (it->second.GetScanProgress())) {
        it->second.SetScanProgress(static_cast<int32_t>(progr));
    }
}

void ScanServiceAbility::GetPicFrame(const std::string scannerId,
    int32_t &scanStatus, ScanParameters &parm)
{
    int64_t totalBytes = 0;
    int jpegrow = 0;
    int64_t hundredPercent = ((int64_t)parm.GetBytesPerLine()) * parm.GetLines() * (((SaneFrame)parm.GetFormat()
        == SANE_FRAME_RGB || (SaneFrame)parm.GetFormat() == SANE_FRAME_GRAY) ? CHANNEL_ONE : CHANNEL_THREE);
    scanStatus = E_SCAN_NONE;
    while (scanStatus == E_SCAN_NONE) {
        SanePictureData pictureData;
        SaneStatus saneStatus = SaneManagerClient::GetInstance()->
            SaneRead(scannerId, buffer_size, pictureData);
        scanStatus = ScanServiceUtils::ConvertErro(saneStatus);
        if (pictureData.ret_ == SANE_READ_FAIL) {
            SCAN_HILOGE("sane_read failed, scanStatus: [%{public}d]", scanStatus);
            break;
        }
        auto ret = memcpy_s(saneReadBuf, buffer_size, pictureData.dataBuffer_.data(), pictureData.dataBuffer_.size());
        if (ret != ERR_OK) {
            scanStatus = E_SCAN_GENERIC_FAILURE;
            SCAN_HILOGE("memcpy_s failed, errorCode:[%{public}d]", ret);
            break;
        }
        SetScanProgr(totalBytes, hundredPercent, pictureData.dataBuffer_.size());
        if (!WritePicData(jpegrow, pictureData.dataBuffer_.size(), parm, scanStatus)) {
            SCAN_HILOGE("WritePicData fail");
            break;
        }
        if (scanStatus == SANE_STATUS_EOF) {
            SCAN_HILOGI("sane_read finished.");
            break;
        }
    }
}

bool ScanServiceAbility::WritePicData(int &jpegrow, int32_t curReadSize,
    ScanParameters &parm, int32_t &scanStatus)
{
    constexpr int bit = 1;
    int i = 0;
    int left = curReadSize;
    while (jpegrow + left >= parm.GetBytesPerLine()) {
        if (!g_isJpegWriteSuccess) {
            scanStatus = E_SCAN_NO_MEM;
            return false;
        }
        int ret = memcpy_s(jpegbuf + jpegrow, parm.GetBytesPerLine(),
            saneReadBuf + i, parm.GetBytesPerLine() - jpegrow);
        if (ret != ERR_OK) {
            scanStatus = E_SCAN_GENERIC_FAILURE;
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
            scanStatus = E_SCAN_GENERIC_FAILURE;
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
        scanStatus = E_SCAN_GENERIC_FAILURE;
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
    if (userId <= 0) {
        SCAN_HILOGD("scan sa calling, use current active userId");
        std::vector<int32_t> userIds;
        AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            SCAN_HILOGE("get use current active userId failed");
            userId = INVALID_USER_ID;
        } else {
            userId = userIds[0];
        }
    }
    SCAN_HILOGD("Current userId = %{public}d.", userId);
    return userId;
}

std::string ScanServiceAbility::ObtainUserCacheDirectory(const int32_t& userId)
{
    std::ostringstream oss;
    oss << "/data/service/el2/" << userId << "/print_service";
    return oss.str();
}

}  // namespace OHOS::Scan