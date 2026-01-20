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

#include <ipc_skeleton.h>
#include <system_ability_definition.h>
#include <iservice_registry.h>
#include <thread>
#include "accesstoken_kit.h"
#include "directory_ex.h"
#include "sane/sane.h"
#include "sane/saneopts.h"
#include "sane_service_ability.h"
#include "sane_device.h"

namespace OHOS {
namespace Scan {

constexpr int32_t SANE_SERVICE_ID = 3709;

REGISTER_SYSTEM_ABILITY_BY_ID(SaneServerManager, SANE_SERVICE_ID, true);

SaneServerManager::SaneServerManager(int32_t saId, bool runOnCreate) : SystemAbility(SANE_SERVICE_ID, true)
{
    SCAN_HILOGI("SaneServerManager init");
}

void SaneServerManager::OnStart()
{
    SCAN_HILOGI("SaneServerManager::OnStart()");
    if (!Publish(this)) {
        SCAN_HILOGE("SaneServerManager::OnStart() failed");
        return;
    }
    SCAN_HILOGI("SaneServerManager start success");
}

SANE_Handle SaneServerManager::GetScanHandle(const std::string &scannerId)
{
    std::lock_guard<std::mutex> autoLock(scannerHandleListlock_);
    auto it = scannerHandleList_.find(scannerId);
    if (it == scannerHandleList_.end()) {
        SCAN_HILOGE("ScannerId is not openned!");
        return nullptr;
    }
    return it->second;
}

bool SaneServerManager::CheckPermission()
{
    using namespace Security::AccessToken;
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != TOKEN_NATIVE) {
        SCAN_HILOGE("invalid tokenType, type = [%{public}u]", tokenType);
        return false;
    }
    static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
    int result = AccessTokenKit::VerifyAccessToken(tokenId, PERMISSION_NAME_PRINT);
    if (result != PERMISSION_GRANTED) {
        SCAN_HILOGE("Current tokenId permission is denied.");
        return false;
    }
    return true;
}

ErrCode SaneServerManager::SaneInit(int32_t &status)
{
    SCAN_HILOGI("SaneInit start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    int32_t scanVersion = 0;
    SANE_Status saneStatus = sane_init(&scanVersion, nullptr);
    status = static_cast<int32_t>(saneStatus);
    SCAN_HILOGI("sane_init successfully, version [%{public}d]", scanVersion);
    return ERR_OK;
}

ErrCode SaneServerManager::SaneExit()
{
    SCAN_HILOGI("SaneExit start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    sane_exit();
    SCAN_HILOGI("SaneExit end");
    return ERR_OK;
}

ErrCode SaneServerManager::SaneOpen(const std::string &scannerId, int32_t &status)
{
    SCAN_HILOGI("SaneOpen start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    std::lock_guard<std::mutex> autoLock(scannerHandleListlock_);
    if (scannerHandleList_.find(scannerId) != scannerHandleList_.end()) {
        status = SANE_STATUS_GOOD;
        return ERR_OK;
    }
    SANE_Handle handle = nullptr;
    SANE_Status saneStatus = sane_open(scannerId.c_str(), &handle);
    if (saneStatus != ::SANE_STATUS_GOOD) {
        status = static_cast<int32_t>(saneStatus);
        SCAN_HILOGE("sane_open error, ret = [%{public}d]", status);
        return ERR_OK;
    }
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr.");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    scannerHandleList_.insert({scannerId, handle});
    SCAN_HILOGI("sane_open end, ret = [%{public}d]", status);
    return ERR_OK;
}

ErrCode SaneServerManager::SaneClose(const std::string &scannerId)
{
    SCAN_HILOGI("SaneClose start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    std::lock_guard<std::mutex> autoLock(scannerHandleListlock_);
    auto it = scannerHandleList_.find(scannerId);
    if (it != scannerHandleList_.end()) {
        sane_close(it->second);
        scannerHandleList_.erase(it);
    }
    SCAN_HILOGI("SaneClose end");
    return ERR_OK;
}

ErrCode SaneServerManager::SaneStart(const std::string &scannerId, int32_t &status)
{
    SCAN_HILOGI("SaneStart start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    SANE_Status saneStatus = sane_start(handle);
    status = static_cast<int32_t>(saneStatus);
    SCAN_HILOGI("sane_start end, ret = [%{public}d]", status);
    return ERR_OK;
}

ErrCode SaneServerManager::SaneCancel(const std::string &scannerId)
{
    SCAN_HILOGI("SaneCancel start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        return ERR_OK;
    }
    sane_cancel(handle);
    SCAN_HILOGI("sane_cancel end");
    return ERR_OK;
}

ErrCode SaneServerManager::SaneGetOptionDescriptor(
    const std::string &scannerId, int32_t saneOption, SaneOptionDescriptor &saneOptDes, int32_t &status)
{
    SCAN_HILOGI("SaneGetOptionDescriptor start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    SCAN_HILOGD("saneOption %{public}d", saneOption);
    const SANE_Option_Descriptor *saneDesc = sane_get_option_descriptor(handle, saneOption);
    if (saneDesc == nullptr) {
        SCAN_HILOGE("saneDesc is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    ConvertSaneDescriptor(saneDesc, saneOptDes);
    saneOptDes.Dump();
    SCAN_HILOGI("SaneGetOptionDescriptor end");
    status = SANE_STATUS_GOOD;
    return ERR_OK;
}

void SaneServerManager::ConvertSaneDescriptor(const SANE_Option_Descriptor *saneDesc, SaneOptionDescriptor &saneOptDes)
{
    SCAN_HILOGI("ConvertSaneDescriptor start");
    if (saneDesc == nullptr) {
        SCAN_HILOGE("saneDesc is a nullptr");
        return;
    }
    if (saneDesc->name != nullptr) {
        saneOptDes.optionName_ = std::string(saneDesc->name);
    }
    if (saneDesc->title != nullptr) {
        saneOptDes.optionTitle_ = std::string(saneDesc->title);
    }
    if (saneDesc->desc != nullptr) {
        saneOptDes.optionDesc_ = std::string(saneDesc->desc);
    }
    saneOptDes.optionType_ = static_cast<int32_t>(saneDesc->type);
    saneOptDes.optionUnit_ = static_cast<int32_t>(saneDesc->unit);
    saneOptDes.optionSize_ = saneDesc->size;
    saneOptDes.optionCap_ = saneDesc->cap;
    saneOptDes.optionConstraintType_ = static_cast<int32_t>(saneDesc->constraint_type);
    if (saneDesc->constraint_type == ::SANE_CONSTRAINT_RANGE && saneDesc->constraint.range != nullptr) {
        saneOptDes.minValue_ = saneDesc->constraint.range->min;
        saneOptDes.maxValue_ = saneDesc->constraint.range->max;
        saneOptDes.quantValue_ = saneDesc->constraint.range->quant;
    } else if (saneDesc->constraint_type == ::SANE_CONSTRAINT_WORD_LIST && saneDesc->constraint.word_list != nullptr) {
        saneOptDes.optionConstraintNumber_.clear();
        int32_t sizeNumber = saneDesc->constraint.word_list[0];
        for (int32_t i = 1; i <= sizeNumber; i++) {
            SCAN_HILOGD("SANE_CONSTRAINT_WORD_LIST: %{public}d", saneDesc->constraint.word_list[i]);
            saneOptDes.optionConstraintNumber_.push_back(saneDesc->constraint.word_list[i]);
        }
    } else if (saneDesc->constraint_type == ::SANE_CONSTRAINT_STRING_LIST &&
               saneDesc->constraint.string_list != nullptr) {
        for (int32_t i = 0; saneDesc->constraint.string_list[i] != nullptr; i++) {
            SCAN_HILOGD("SANE_CONSTRAINT_STRING_LIST: %{public}s", saneDesc->constraint.string_list[i]);
            saneOptDes.optionConstraintString_.push_back(std::string(saneDesc->constraint.string_list[i]));
        }
    }
    SCAN_HILOGI("ConvertSaneDescriptor end");
}

ErrCode SaneServerManager::SaneGetParameters(const std::string &scannerId, SaneParameters &spm, int32_t &status)
{
    SCAN_HILOGI("SaneGetParameters start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    SANE_Parameters params;
    SANE_Status saneStatus = sane_get_parameters(handle, &params);
    if (saneStatus != ::SANE_STATUS_GOOD) {
        status = static_cast<int32_t>(saneStatus);
        SCAN_HILOGE("sane_get_parameters error, ret = [%{public}d]", status);
        return ERR_OK;
    }
    spm.format_ = static_cast<SaneFrame>(params.format);
    spm.lastFrame_ = params.last_frame;
    spm.bytesPerLine_ = params.bytes_per_line;
    spm.pixelsPerLine_ = params.pixels_per_line;
    spm.lines_ = params.lines;
    spm.depth_ = params.depth;
    status = SANE_STATUS_GOOD;
    SCAN_HILOGI("SaneGetParameters end");
    return ERR_OK;
}

ErrCode SaneServerManager::SaneGetDevices(std::vector<SaneDevice> &deviceInfos, int32_t &status)
{
    SCAN_HILOGI("SaneGetDevices start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    const SANE_Device **deviceList = nullptr;
    SANE_Status saneStatus = sane_get_devices(&deviceList, SANE_FALSE);
    if (saneStatus != ::SANE_STATUS_GOOD) {
        status = static_cast<int32_t>(saneStatus);
        SCAN_HILOGE("sane_get_devices error, ret = [%{public}d]", status);
        return ERR_OK;
    }
    for (int32_t i = 0; deviceList[i] != nullptr; i++) {
        SaneDevice device;
        if (deviceList[i]->name != nullptr) {
            device.name_ = std::string(deviceList[i]->name);
        }
        if (deviceList[i]->vendor != nullptr) {
            device.vendor_ = std::string(deviceList[i]->vendor);
        }
        if (deviceList[i]->model != nullptr) {
            device.model_ = std::string(deviceList[i]->model);
        }
        if (deviceList[i]->type != nullptr) {
            device.type_ = std::string(deviceList[i]->type);
        }
        device.Dump();
        deviceInfos.push_back(device);
    }
    status = SANE_STATUS_GOOD;
    SCAN_HILOGI("SaneGetDevices end");
    return ERR_OK;
}

ErrCode SaneServerManager::SaneControlOption(
    const std::string &scannerId, const SaneControlParam &controlParam, SaneOutParam &outParam, int32_t &status)
{
    SCAN_HILOGI("SaneControlOption start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    SANE_Int option = controlParam.option_;
    SANE_Action action = static_cast<SANE_Action>(controlParam.action_);
    if (controlParam.action_ == SANE_ACTION_SET_AUTO) {
        SANE_Status saneStatus = sane_control_option(handle, option, action, nullptr, nullptr);
        if (saneStatus != ::SANE_STATUS_GOOD) {
            status = static_cast<int32_t>(saneStatus);
            SCAN_HILOGE("sane_control_option error, ret = [%{public}d]", status);
            return ERR_OK;
        }
    } else if (controlParam.action_ == SANE_ACTION_GET_VALUE) {
        SaneStatus saneStatus = GetControlOption(handle, controlParam, outParam);
        if (saneStatus != SANE_STATUS_GOOD) {
            status = static_cast<int32_t>(saneStatus);
            SCAN_HILOGE("Get sane_control_option error, ret = [%{public}d]", status);
            return ERR_OK;
        }
    } else if (controlParam.action_ == SANE_ACTION_SET_VALUE) {
        SaneStatus saneStatus = SetControlOption(handle, controlParam, outParam);
        if (saneStatus != SANE_STATUS_GOOD) {
            status = static_cast<int32_t>(saneStatus);
            SCAN_HILOGE("Set sane_control_option error, ret = [%{public}d]", status);
            return ERR_OK;
        }
    } else {
        status = SANE_STATUS_INVAL;
        SCAN_HILOGE("action is invalid, action = [%{public}u]", controlParam.action_);
        return ERR_OK;
    }
    SCAN_HILOGI("SaneControlOption end");
    return ERR_OK;
}

SaneStatus SaneServerManager::GetControlOption(
    SANE_Handle &handle, const SaneControlParam &controlParam, SaneOutParam &outParam)
{
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        return SANE_STATUS_INVAL;
    }
    SANE_Int option = controlParam.option_;
    int32_t valueType = controlParam.valueType_;
    SANE_Status saneStatus = ::SANE_STATUS_GOOD;
    SCAN_HILOGD("valueSize_ = [%{public}d], valueType = [%{public}u]", controlParam.valueSize_, valueType);
    if (valueType == SCAN_VALUE_NUM) {
        int32_t value = 0;
        saneStatus = sane_control_option(handle, option, ::SANE_ACTION_GET_VALUE, &value, nullptr);
        outParam.valueNumber_ = value;
    } else if (valueType == SCAN_VALUE_STR) {
        std::string value;
        value.resize(controlParam.valueSize_ + 1);
        saneStatus = sane_control_option(handle, option, ::SANE_ACTION_GET_VALUE, &value.front(), nullptr);
        outParam.valueStr_ = value;
    } else if (valueType == SCAN_VALUE_BOOL) {
        int32_t value = 0;
        saneStatus = sane_control_option(handle, option, ::SANE_ACTION_GET_VALUE, &value, nullptr);
        outParam.valueBool_ = value > 0 ? true : false;
    }
    if (saneStatus != ::SANE_STATUS_GOOD) {
        SCAN_HILOGE("Get sane_control_option error, ret = [%{public}u]", saneStatus);
        return static_cast<SaneStatus>(saneStatus);
    }
    return SANE_STATUS_GOOD;
}

SaneStatus SaneServerManager::SetControlOption(
    SANE_Handle &handle, const SaneControlParam &controlParam, SaneOutParam &outParam)
{
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        return SANE_STATUS_INVAL;
    }
    SANE_Int option = controlParam.option_;
    SANE_Action action = static_cast<SANE_Action>(controlParam.action_);
    SANE_Int &info = outParam.info_;
    int32_t valueType = controlParam.valueType_;
    SCAN_HILOGD("valueType = [%{public}d], option = [%{public}d], action = [%{public}u]", valueType, option, action);
    SANE_Status saneStatus = ::SANE_STATUS_GOOD;
    if (valueType == SCAN_VALUE_STR) {
        std::string value = controlParam.valueStr_;
        saneStatus = sane_control_option(handle, option, action, const_cast<char *>(&value.front()), &info);
        SCAN_HILOGD("SetControlOption, value = [%{public}s]", value.c_str());
    } else {
        int32_t value = controlParam.valueNumber_;
        saneStatus = sane_control_option(handle, option, action, &value, &info);
        SCAN_HILOGD("SetControlOption, value = [%{public}d]", value);
    }
    if (saneStatus != ::SANE_STATUS_GOOD) {
        SCAN_HILOGE("Set sane_control_option error, ret = [%{public}u]", saneStatus);
        return static_cast<SaneStatus>(saneStatus);
    }
    return SANE_STATUS_GOOD;
}

ErrCode SaneServerManager::SaneRead(
    const std::string &scannerId, const int32_t buflen, SanePictureData &pictureData, int32_t &status)
{
    SCAN_HILOGI("SaneRead start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    if (buflen <= 0 || buflen > MAX_BUFLEN) {
        SCAN_HILOGE("invalid buflen, buflen = %{public}d", buflen);
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    SANE_Handle handle = GetScanHandle(scannerId);
    if (handle == nullptr) {
        SCAN_HILOGE("handle is a nullptr");
        status = SANE_STATUS_INVAL;
        return ERR_OK;
    }
    constexpr int32_t zero = 0;
    SANE_Int curReadSize = zero;
    std::vector<SANE_Byte> valueBuffer(buflen);
    SANE_Status saneStatus = ::SANE_STATUS_GOOD;
    do {
        saneStatus = sane_read(handle, valueBuffer.data(), buflen, &curReadSize);
    } while (saneStatus == ::SANE_STATUS_GOOD && curReadSize == zero);
    status = static_cast<int32_t>(saneStatus);
    if (saneStatus != ::SANE_STATUS_GOOD && saneStatus != ::SANE_STATUS_EOF) {
        SCAN_HILOGE("sane_read error, ret = [%{public}d]", status);
        pictureData.ret_ = SANE_READ_FAIL;
        return ERR_OK;
    }
    if (curReadSize > 0) {
        valueBuffer.resize(curReadSize);
    }
    pictureData.dataBuffer_ = std::move(valueBuffer);
    pictureData.ret_ = SANE_READ_OK;
    SCAN_HILOGI("SaneRead end");
    return ERR_OK;
}

ErrCode SaneServerManager::UnloadSystemAbility()
{
    SCAN_HILOGI("UnloadSystemAbility start");
    if (!CheckPermission()) {
        SCAN_HILOGE("no permission to access sane_service");
        return SANE_STATUS_NO_PERMISSION;
    }
    std::lock_guard<std::mutex> autoLock(scannerHandleListlock_);
    for (const auto &scanner : scannerHandleList_) {
        sane_cancel(scanner.second);
        sane_close(scanner.second);
    }
    scannerHandleList_.clear();
    sane_exit();
    const std::string dataTmpDir = PRINTER_SERVICE_SANE_TEMPORARY_PATH;
    std::vector<std::string> files;
    GetDirFiles(dataTmpDir, files);
    for (const auto &file : files) {
        if (!RemoveFile(file)) {
            SCAN_HILOGW("RemoveFile failed");
        }
    }
    auto task = [this]() {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SCAN_HILOGE("get samgr failed");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(SANE_SERVICE_ID);
        if (ret != ERR_OK) {
            SCAN_HILOGE("unload sane_service failed");
            return;
        }
        SCAN_HILOGI("unload sane_service successfull.");
    };
    std::thread unloadThead(task);
    unloadThead.detach();
    return ERR_OK;
}
}  // namespace Scan
}  // namespace OHOS