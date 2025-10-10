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
#include "saneopts.h"

namespace OHOS::Scan {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using SteadyTimePoint = std::chrono::steady_clock::time_point;

const int64_t INIT_INTERVAL = 5000L;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t UNLOAD_SYSTEMABILITY_DELAY = 1000 * 30;

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
    {SCAN_DEVICE_DEL, PERMISSION_NAME_PRINT_JOB}};

std::map<std::string, sptr<IScanCallback>> OHOS::Scan::ScanServiceAbility::registeredListeners_;

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
    bool ret = Publish(ScanServiceAbility::GetInstance());
    if (!ret) {
        SCAN_HILOGE("ScanServiceAbility Publish failed.");
        return E_SCAN_SERVER_FAILURE;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    SCAN_HILOGD("state_ is %{public}d.", static_cast<int>(state_.load()));
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
        CleanupScanService();
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
    for (const auto &scannerId : openedScannerList_) {
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
        SaneManagerClient::GetInstance()->SaneClose(scannerId);
    }
    openedScannerList_.clear();
    SaneManagerClient::GetInstance()->SaneExit();
    ScanMdnsService::OnStopDiscoverService();
    scannerState_.store(SCANNER_READY);
    scanPictureData_.CleanPictureData();
}

bool ScanServiceAbility::GetUsbDevicePort(const std::string &deviceId, std::string &firstId, std::string &secondId)
{
    constexpr int32_t TOKEN_SIZE_FOUR = 4;
    std::vector<std::string> tokens = ScanServiceUtils::ExtractIpOrPortFromUrl(deviceId, ':', TOKEN_SIZE_FOUR);
    if (tokens.empty()) {
        SCAN_HILOGE("split [%{private}s] fail ", deviceId.c_str());
        return false;
    }
    constexpr size_t STRING_POS_ONE = 1;
    constexpr size_t STRING_POS_TWO = 2;
    constexpr size_t STRING_POS_THREE = 3;
    if (tokens[STRING_POS_ONE] != "libusb") {
        SCAN_HILOGE("parse [%{private}s] fail since no libusb", deviceId.c_str());
        return false;
    }
    static const std::regex pattern(R"(([0-9]{3}))");
    if (!std::regex_match(tokens[STRING_POS_TWO], pattern) ||
        !std::regex_match(tokens[STRING_POS_THREE], pattern)) {
        SCAN_HILOGE("parse [%{public}s]:[%{public}s] fail", tokens[STRING_POS_TWO].c_str(),
                    tokens[STRING_POS_THREE].c_str());
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
    constexpr int32_t TOKEN_SIZE_TWO = 2;
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
            scanDeviceInfoSync.oldDeviceId = scannerInfo.deviceId;
            scanData.UpdateScannerInfoByUniqueId(uniqueId, info);
            SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
        }
    } else {
        auto updateResult = scanData.UpdateNetScannerByUuid(info.uuid, info.uniqueId);
        if (updateResult.has_value()) {
            scanDeviceInfoSync.oldDeviceId = updateResult.value().first;
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
    scannerState_.store(SCANNER_SEARCHING);
    deviceInfos_.clear();
    SaneManagerClient::GetInstance()->SaneInit();
    std::vector<SaneDevice> deviceInfos;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneGetDevices(deviceInfos);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneGetDevices failed, ret: [%{public}u]", status);
        return;
    }
    std::vector<ScanDeviceInfo> scanDeviceInfos;
    for (const auto &device : deviceInfos) {
        ScanDeviceInfo info;
        info.deviceId = device.name_;
        info.manufacturer = device.vendor_;
        info.model = device.model_;
        info.deviceType = device.type_;
        SetScannerSerialNumber(info);
        AddFoundScanner(info, scanDeviceInfos);
    }
    for (auto& scanDeviceInfo : scanDeviceInfos) {
        SendDeviceInfo(scanDeviceInfo, SCAN_DEVICE_FOUND);
        deviceInfos_.emplace_back(scanDeviceInfo);
    }
    SendDeviceList(deviceInfos_, GET_SCANNER_DEVICE_LIST);
    scannerState_.store(SCANNER_READY);
}

int32_t ScanServiceAbility::GetScannerList()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        return E_SCAN_NO_PERMISSION;
    }
    if (scannerState_.load() == SCANNER_SEARCHING) {
        SCAN_HILOGD("is searching");
        return E_SCAN_NONE;
    }
    if (scannerState_.load() != SCANNER_READY) {
        SCAN_HILOGW("is working");
        return E_SCAN_DEVICE_BUSY;
    }
    SCAN_HILOGD("ScanServiceAbility GetScannerList start");
    auto exec_sane_getscaner = [=]() {
        SaneGetScanner();
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
    scanPictureData_.CleanPictureData();
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

int32_t ScanServiceAbility::ActionGetValue(
    const std::string &scannerId, ScanOptionValue &value, const int32_t &optionIndex)
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

int32_t ScanServiceAbility::ActionSetValue(
    const std::string &scannerId, ScanOptionValue &value, const int32_t &optionIndex)
{
    SCAN_HILOGI("Set OpScanOptionValue SCAN_ACTION_SET_VALUE");
    SaneStatus status = SANE_STATUS_GOOD;
    SaneControlParam controlParam;
    controlParam.option_ = optionIndex;
    controlParam.action_ = static_cast<SaneAction>(SANE_ACTION_SET_VALUE);
    controlParam.valueType_ = static_cast<int32_t>(value.GetScanOptionValueType());
    int32_t numValue = value.GetNumValue();
    controlParam.valueNumber_ = numValue;
    controlParam.valueStr_ = value.GetStrValue();
    SaneOutParam outParam;
    status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, ret = [%{public}d]", status);
        return ScanServiceUtils::ConvertErro(status);
    }
    return status;
}

int32_t ScanServiceAbility::OpScanOptionValue(
    const std::string scannerId, const int32_t optionIndex, const ScanOptionOpType op, ScanOptionValue &value)
{
    SCAN_HILOGD("ScanServiceAbility OpScanOptionValue start");
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    std::lock_guard<std::mutex> autoLock(lock_);
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
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
    scanPictureData_.CleanPictureData();
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
    const std::string &permission = (SCAN_PERMISSION_MAP.find(type) != SCAN_PERMISSION_MAP.end())
                                        ? SCAN_PERMISSION_MAP.at(type)
                                        : PERMISSION_NAME_PRINT_JOB;
    if (!CheckPermission(permission)) {
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
    SCAN_HILOGI("SendDeviceInfo [%{private}s], event = %{public}s", info.deviceId.c_str(), event.c_str());
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
    scanDeviceInfoSync.uniqueId = serialNumber;
    scanDeviceInfoSync.deviceId = deviceId;
    scanDeviceInfoSync.discoverMode = ScannerDiscoveryMode::USB_MODE;
    scanDeviceInfoSync.syncMode = ScannerSyncMode::DELETE_MODE;
    scanDeviceInfoSync.deviceState = 0;
    SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
#ifdef DEBUG_ENABLE
    SCAN_HILOGD("GetScannerList delete end serialNumber:%{private}s newDeviceId:%{public}s",
        serialNumber.c_str(),
        deviceId.c_str());
#endif
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
        if (scannerDiscoverData_.HasUsbDevice(scanDeviceInfoSync.uniqueId)) {
            ScanDeviceInfo info;
            scannerDiscoverData_.GetUsbDevice(syncInfo.uniqueId, info);
            info.deviceId = scanDeviceInfoSync.deviceId;
            scannerDiscoverData_.SetUsbDevice(scanDeviceInfoSync.uniqueId, info);
        }
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else if (scanDeviceInfoSync.discoverMode == ScannerDiscoveryMode::TCP_MODE) {
        std::string oldIp;
        ScanUtil::ExtractIpAddresses(scanDeviceInfoSync.oldDeviceId, oldIp);
        if (scannerDiscoverData_.HasTcpDevice(oldIp)) {
            ScanDeviceInfo info;
            scannerDiscoverData_.GetTcpDevice(oldIp, info);
            info.deviceId = scanDeviceInfoSync.deviceId;
            scannerDiscoverData_.SetTcpDevice(scanDeviceInfoSync.uniqueId, info);
        }
        SendDeviceInfoSync(scanDeviceInfoSync, SCAN_DEVICE_SYNC);
    } else {
        SCAN_HILOGE("invalid discover mode %{public}s", scanDeviceInfoSync.discoverMode.c_str());
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
    int32_t status = scanPictureData_.GetPictureProgressInQueue(prog);
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("scanprogress exception occurred:[%{public}u]", status);
        return status;
    }
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::AddScanner(const std::string &serialNumber, const std::string &discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    if (discoverMode != ScannerDiscoveryMode::USB_MODE && discoverMode != ScannerDiscoveryMode::TCP_MODE) {
        SCAN_HILOGE("discoverMode is a invalid parameter.");
        return E_SCAN_INVALID_PARAMETER;
    }
    auto addScannerExe = [=]() {
        std::string uniqueId = discoverMode + serialNumber;
        ScanSystemData &scanData = ScanSystemData::GetInstance();
        if (discoverMode == ScannerDiscoveryMode::USB_MODE) {
            if (!scannerDiscoverData_.HasUsbDevice(serialNumber) || scanData.IsContainScanner(uniqueId)) {
                SCAN_HILOGE("Failed to add usb scanner.");
                return;
            }
            ScanDeviceInfo info;
            scannerDiscoverData_.GetUsbDevice(serialNumber, info);
            scanData.InsertScannerInfo(uniqueId, info);
            if (!scanData.SaveScannerMap()) {
                SCAN_HILOGE("ScanServiceAbility AddScanner SaveScannerMap fail");
                return;
            }
            SendDeviceInfo(info, SCAN_DEVICE_ADD);
        } else if (discoverMode == ScannerDiscoveryMode::TCP_MODE) {
            if (!scannerDiscoverData_.HasTcpDevice(serialNumber) || scanData.IsContainScanner(uniqueId)) {
                SCAN_HILOGE("Failed to add tcp scanner.");
                return;
            }
            ScanDeviceInfo info;
            scannerDiscoverData_.GetTcpDevice(serialNumber, info);
            scanData.InsertScannerInfo(uniqueId, info);
            if (!scanData.SaveScannerMap()) {
                SCAN_HILOGE("ScanServiceAbility AddScanner SaveScannerMap fail");
                return;
            }
            SendDeviceInfo(info, SCAN_DEVICE_ADD);
        } else {
            SCAN_HILOGE("discoverMode is invalid.");
        }
    };
    serviceHandler_->PostTask(addScannerExe, ASYNC_CMD_DELAY);
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::DeleteScanner(const std::string &serialNumber, const std::string &discoverMode)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
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

int32_t ScanServiceAbility::GetAddedScanner(std::vector<ScanDeviceInfo> &allAddedScanner)
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

int32_t ScanServiceAbility::StartScanOnce(const std::string scannerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    SCAN_HILOGI("ScanServiceAbility StartScan start");

    if (scannerState_.load() == SCANNER_CANCELING) {
        SCAN_HILOGE("scan task is canceling");
        return E_SCAN_DEVICE_BUSY;
    }
    SaneStatus saneStatus = SaneManagerClient::GetInstance()->SaneStart(scannerId);
    if (saneStatus != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneStart failed, status is %{public}u", saneStatus);
        SaneManagerClient::GetInstance()->SaneCancel(scannerId);
        return ScanServiceUtils::ConvertErro(saneStatus);
    }
    SCAN_HILOGI("ScanServiceAbility StartScan end");
    return E_SCAN_NONE;
}

int32_t ScanServiceAbility::StartScan(const std::string scannerId, const bool &batchMode)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        SCAN_HILOGE("no permission to access scan service");
        return E_SCAN_NO_PERMISSION;
    }
    std::lock_guard<std::mutex> autoLock(lock_);
    if (openedScannerList_.find(scannerId) == openedScannerList_.end()) {
        SCAN_HILOGE("scannerId %{private}s is not opened", scannerId.c_str());
        return E_SCAN_INVALID_PARAMETER;
    }
    scanPictureData_.CleanPictureData();
    int32_t status = StartScanOnce(scannerId);
    if (status != E_SCAN_NONE) {
        SCAN_HILOGE("Start Scan error");
        return status;
    }
    scannerState_.store(SCANNER_SCANING);
    scanPictureData_.PushScanPictureProgress();
    int32_t userId = GetCurrentUserId();
    auto exe = [=] () {
        ScanTask task(scannerId, userId, batchMode);
        StartScanTask(task);
    };
    serviceHandler_->PostTask(exe, ASYNC_CMD_DELAY);
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
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        SCAN_HILOGI("StartScanTask finished, doning sane_cancel");
        SaneManagerClient::GetInstance()->SaneCancel(scanTask.GetScannerId());
    }
    scannerState_.store(SCANNER_READY);
    SCAN_HILOGI("ScanServiceAbility StartScanTask end");
}

bool ScanServiceAbility::CreateAndOpenScanFile(ScanTask &scanTask)
{
    std::string filePath;
    if (!scanTask.CreateAndOpenScanFile(filePath)) {
        SCAN_HILOGI("ScanTask CreateAndOpenScanFile fail");
        return false;
    }
    scanPictureData_.SetImageRealPath(filePath);
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
            status = E_SCAN_GENERIC_FAILURE;
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
        status = E_SCAN_GENERIC_FAILURE;
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
            scanStatus = StartScanOnce(scanTask.GetScannerId());
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGW("restart scanner fail");
                break;
            }
        }
        scanStatus = GetScanParameters(scanTask.GetScannerId(), parm);
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
            scanStatus = scanTask.WriteJpegHeader(parm, dpi);
            if (scanStatus != E_SCAN_NONE) {
                SCAN_HILOGE("StartScanTask error exit after WriteJpegHeader");
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
    int32_t status = StartScanOnce(scannerId);
    if (status == E_SCAN_NONE) {
        SCAN_HILOGD("ScanTask restart success");
        scanPictureData_.SetNowScanProgressFinished(false);
        scanPictureData_.PushScanPictureProgress();
    } else if (status == E_SCAN_NO_DOCS) {
        SCAN_HILOGD("The feeder is out of paper.");
        scanPictureData_.SetNowScanProgressFinished(true);
    } else {
        SCAN_HILOGE("restart scan fail");
        scanPictureData_.SetNowScanProgressFinished(true);
        scanPictureData_.PushScanPictureProgress();
        scanPictureData_.SetScanTaskCode(status);
    }
    return status;
}

void ScanServiceAbility::CleanUpAfterScan(ScanTask &scanTask, int32_t scanStatus)
{
    if (scanStatus != E_SCAN_EOF && scanStatus != E_SCAN_NO_DOCS) {
        scanTask.JpegDestroyCompress();
        SCAN_HILOGE("End of failed scan ");
    } else {
        scanTask.JpegFinishCompress();
        SCAN_HILOGD("End of normal scan");
    }
}

void ScanServiceAbility::GetPicFrame(ScanTask &scanTask, int32_t &scanStatus, ScanParameters &parm)
{
    int64_t totalBytes = 0;
    int32_t jpegrow = 0;
    int64_t hundredPercent =
        ((int64_t)parm.GetBytesPerLine()) * parm.GetLines() *
        (((SaneFrame)parm.GetFormat() == SANE_FRAME_RGB || (SaneFrame)parm.GetFormat() == SANE_FRAME_GRAY)
                ? CHANNEL_ONE
                : CHANNEL_THREE);
    scanStatus = E_SCAN_NONE;
    while (scanStatus == E_SCAN_NONE) {
        SanePictureData pictureData;
        SaneStatus saneStatus = SaneManagerClient::GetInstance()->SaneRead(scanTask.GetScannerId(),
            BUFFER_SIZE, pictureData);
        scanStatus = ScanServiceUtils::ConvertErro(saneStatus);
        if (pictureData.ret_ == SANE_READ_FAIL) {
            SCAN_HILOGE("sane_read failed, scanStatus: [%{public}d]", scanStatus);
            break;
        }
        scanPictureData_.SetScanProgr(totalBytes, hundredPercent, pictureData.dataBuffer_.size());
        if (scanTask.WritePicData(jpegrow, pictureData.dataBuffer_, parm) != E_SCAN_NONE) {
            SCAN_HILOGE("WritePicData fail");
            scanStatus = E_SCAN_GENERIC_FAILURE;
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

int32_t ScanServiceAbility::GetScannerImageDpi(const std::string& scannerId, int32_t& dpi)
{
    SaneControlParam controlParam;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    SaneOutParam outParam;
    SaneStatus status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return ScanServiceUtils::ConvertErro(status);
    }
    int32_t resolutionIndex = 0;
    for (int32_t optionIndex = 1; optionIndex < outParam.valueNumber_; optionIndex++) {
        SaneOptionDescriptor saneDesc;
        status = SaneManagerClient::GetInstance()->SaneGetOptionDescriptor(scannerId, optionIndex, saneDesc);
        if (status != SANE_STATUS_GOOD) {
            SCAN_HILOGE("SaneGetOptionDescriptor failed, status: [%{public}u]", status);
            return ScanServiceUtils::ConvertErro(status);
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
        return E_SCAN_GENERIC_FAILURE;
    }
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    controlParam.option_ = resolutionIndex;
    status = SaneManagerClient::GetInstance()->SaneControlOption(scannerId, controlParam, outParam);
    if (status != SANE_STATUS_GOOD) {
        SCAN_HILOGE("SaneControlOption failed, status: [%{public}d]", status);
        return ScanServiceUtils::ConvertErro(status);
    }
    dpi = outParam.valueNumber_;
    return E_SCAN_NONE;
}
}  // namespace OHOS::Scan