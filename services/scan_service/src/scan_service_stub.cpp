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

#include "scan_service_stub.h"
#include "ipc_skeleton.h"
#include "iscan_service.h"
#include "message_parcel.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "scanner_info.h"
#include "scan_service_ability.h"

namespace OHOS::Scan {
using namespace OHOS::HiviewDFX;

ScanServiceStub::ScanServiceStub()
{
    cmdMap_[CMD_INIT_SCAN] = &ScanServiceStub::OnInitScan;
    cmdMap_[CMD_EXIT_SCAN] = &ScanServiceStub::OnExitScan;
    cmdMap_[CMD_GET_SCANNER_LIST] = &ScanServiceStub::OnGetScannerList;
    cmdMap_[CMD_STOP_DISCOVER] = &ScanServiceStub::OnStopDiscover;
    cmdMap_[CMD_OPEN_SCANNER] = &ScanServiceStub::OnOpenScanner;
    cmdMap_[CMD_CLOSE_SCANNER] = &ScanServiceStub::OnCloseScanner;
    cmdMap_[CMD_GET_SCAN_OPTION_DESC] = &ScanServiceStub::OnGetScanOptionDesc;
    cmdMap_[CMD_OP_SCAN_OPTION_VALUE] = &ScanServiceStub::OnOpScanOptionValue;
    cmdMap_[CMD_GET_SCAN_PARAMETERS] = &ScanServiceStub::OnGetScanParameters;
    cmdMap_[CMD_START_SCAN] = &ScanServiceStub::OnStartScan;
    cmdMap_[CMD_GET_SINGLE_FRAME_FD] = &ScanServiceStub::OnGetSingleFrameFD;
    cmdMap_[CMD_CANCEL_SCAN] = &ScanServiceStub::OnCancelScan;
    cmdMap_[CMD_SET_SCAN_IO_MODE] = &ScanServiceStub::OnSetScanIOMode;
    cmdMap_[CMD_GET_SCAN_SELECT_FD] = &ScanServiceStub::OnGetScanSelectFd;
    cmdMap_[CMD_GET_SCANNER_STATE] = &ScanServiceStub::OnGetScannerState;
    cmdMap_[CMD_GET_SCAN_PROGRESS] = &ScanServiceStub::OnGetScanProgress;
    cmdMap_[CMD_CONNECT_SCANNER] = &ScanServiceStub::OnConnectScanner;
    cmdMap_[CMD_DISCONNECT_SCANNER] = &ScanServiceStub::OnDisConnectScanner;
    cmdMap_[CMD_GET_CONNECTED_SCANNER] = &ScanServiceStub::OnGetConnectedScanner;
    cmdMap_[CMD_UPDATE_SCANNER_NAME] = &ScanServiceStub::OnUpdateScannerName;
    cmdMap_[CMD_ON] = &ScanServiceStub::OnEventOn;
    cmdMap_[CMD_OFF] = &ScanServiceStub::OnEventOff;
}

int32_t ScanServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SCAN_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        SCAN_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_SCAN_RPC_FAILURE;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_SCAN_NONE : E_SCAN_SERVER_FAILURE;
        }
    }
    SCAN_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool ScanServiceStub::OnInitScan(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnInitScan start");
    int32_t ret = E_SCAN_RPC_FAILURE;
    int32_t scanVersion = 0;
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        ScanServiceAbility::appCount_++;
        SCAN_HILOGI("ScanServiceAbility::appCount_= %{public}d", ScanServiceAbility::appCount_);
    }
    if (isSaneInit_) {
        SCAN_HILOGW("is isSaneInit_ed");
        return E_SCAN_NONE;
    }
    ret = InitScan(scanVersion);
    isSaneInit_ = true;
    reply.WriteInt32(ret);
    reply.WriteInt32(scanVersion);
    SCAN_HILOGI("ScanServiceStub::OnInitScan end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnExitScan(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnExitScan start");
    auto scanServiceAbilityPtr = ScanServiceAbility::GetInstance();
    if (scanServiceAbilityPtr == nullptr) {
        SCAN_HILOGE("scanServiceAbilityPtr is a nullptr");
        reply.WriteInt32(E_SCAN_GENERIC_FAILURE);
        return false;
    }
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        ScanServiceAbility::appCount_ = ScanServiceAbility::appCount_ - 1 >= 0 ? ScanServiceAbility::appCount_ - 1 : 0;
        SCAN_HILOGI("appCount = %{public}d", ScanServiceAbility::appCount_);
        if (ScanServiceAbility::appCount_ == 0) {
            SCAN_HILOGI("connected app number = 0, start unloadSA");
            scanServiceAbilityPtr->UnloadSystemAbility();
        }
    }
    reply.WriteInt32(E_SCAN_NONE);
    SCAN_HILOGI("ScanServiceStub::OnExitScan end");
    return true;
}

bool ScanServiceStub::OnGetScannerList(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnGetScannerList start");
    int32_t ret = GetScannerList();
    reply.WriteInt32(ret);
    SCAN_HILOGI("ScanServiceStub::OnGetScannerList end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnStopDiscover(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnStopDiscover start");
    int32_t ret = StopDiscover();
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnStopDiscover end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnOpenScanner(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnOpenScanner start");
    std::string scannerId = data.ReadString();
    int32_t ret = OpenScanner(scannerId);
    reply.WriteInt32(ret);
    SCAN_HILOGI("ScanServiceStub::OnOpenScanner end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnCloseScanner(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnCloseScanner start");
    std::string scannerId = data.ReadString();
    int32_t ret = CloseScanner(scannerId);
    reply.WriteInt32(ret);
    SCAN_HILOGI("ScanServiceStub::OnCloseScanner end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetScanOptionDesc(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnGetScanOptionDesc start");
    std::string scannerId = data.ReadString();
    int32_t optionIndex = data.ReadInt32();
    ScanOptionDescriptor desc;
    int32_t ret = GetScanOptionDesc(scannerId, optionIndex, desc);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        desc.Marshalling(reply);
    }
    SCAN_HILOGI("ScanServiceStub::OnGetScanOptionDesc end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnOpScanOptionValue(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnOpScanOptionValue start");
    std::string scannerId = data.ReadString();
    int32_t optionIndex = data.ReadInt32();
    ScanOptionOpType op = (ScanOptionOpType) data.ReadUint32();
    ScanOptionValue value;
    auto scanOptionValue = ScanOptionValue::Unmarshalling(data);
    if (scanOptionValue == nullptr) {
        SCAN_HILOGE("scanOptionValue is a nullptr.");
        return false;
    }
    value = *scanOptionValue;
    int32_t info;
    int32_t ret = OpScanOptionValue(scannerId, optionIndex, op, value, info);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        value.Marshalling(reply);
        if (op == SCAN_ACTION_GET_VALUE) {
            reply.WriteInt32(info);
        }
    }
    SCAN_HILOGD("ScanServiceStub::OnOpScanOptionValue end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetScanParameters(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetScanParameters start");
    std::string scannerId = data.ReadString();
    ScanParameters para;
    int32_t ret = GetScanParameters(scannerId, para);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        para.Marshalling(reply);
    }
    SCAN_HILOGD("ScanServiceStub::OnGetScanParameters end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnStartScan(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnStartScan start");
    std::string scannerId = data.ReadString();
    bool batchMode = data.ReadBool();
    int32_t ret = ScanServiceAbility::GetInstance()->OnStartScan(scannerId, batchMode);
    reply.WriteInt32(ret);
    SCAN_HILOGI("ScanServiceStub::OnStartScan end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetSingleFrameFD(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetSingleFrameFD start");
    std::string scannerId = data.ReadString();
    int32_t fd = data.ReadFileDescriptor();
    uint32_t frameSize = 0;
    int32_t ret = GetSingleFrameFD(scannerId, frameSize, fd);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        reply.WriteInt32(frameSize);
    }
    SCAN_HILOGD("ScanServiceStub::OnGetSingleFrameFD end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnCancelScan(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGI("ScanServiceStub::OnCancelScan start");
    std::string scannerId = data.ReadString();
    int32_t ret = CancelScan(scannerId);
    reply.WriteInt32(ret);
    SCAN_HILOGI("ScanServiceStub::OnCancelScan end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnSetScanIOMode(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnSetScanIOMode start");
    std::string scannerId = data.ReadString();
    bool isNonBlocking = data.ReadBool();
    int32_t ret = SetScanIOMode(scannerId, isNonBlocking);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnSetScanIOMode end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetScanSelectFd(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetScanSelectFd start");
    std::string scannerId = data.ReadString();
    int32_t fd = 0;
    int32_t ret = GetScanSelectFd(scannerId, fd);
    reply.WriteInt32(ret);
    reply.WriteInt32(fd);
    SCAN_HILOGD("ScanServiceStub::OnGetScanSelectFd end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    std::string taskId = data.ReadString();
    std::string type = data.ReadString();
    SCAN_HILOGD("ScanServiceStub::OnEventOn type=%{public}s ", type.c_str());
    if (type.empty()) {
        SCAN_HILOGE("ScanServiceStub::OnEventOn type is null.");
        reply.WriteInt32(E_SCAN_RPC_FAILURE);
        return false;
    }
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceStub::OnEventOn remote is nullptr");
        reply.WriteInt32(E_SCAN_RPC_FAILURE);
        return false;
    }
    sptr<IScanCallback> listener = iface_cast<IScanCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        SCAN_HILOGE("ScanServiceStub::OnEventOn listener is null");
        reply.WriteInt32(E_SCAN_RPC_FAILURE);
        return false;
    }
    int32_t ret = On(taskId, type, listener);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnEventOn out");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnEventOff in");
    std::string taskId = data.ReadString();
    std::string type = data.ReadString();
    SCAN_HILOGD("ScanServiceStub::OnEventOff type=%{public}s ", type.c_str());
    int32_t ret = Off(taskId, type);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnEventOff out");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetScannerState(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetScannerState start");
    int32_t ret = E_SCAN_RPC_FAILURE;
    int32_t scannerState = 0;
    ret = GetScannerState(scannerState);
    reply.WriteInt32(ret);
    reply.WriteInt32(scannerState);
    SCAN_HILOGD("ScanServiceStub::OnGetScannerState end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetScanProgress(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetScanProgress start");
    std::string scannerId = data.ReadString();
    ScanProgress prog;
    int32_t ret = GetScanProgress(scannerId, prog);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        prog.Marshalling(reply);
    }
    SCAN_HILOGD("ScanServiceStub::OnGetScanProgress end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnConnectScanner(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnConnectScanner start");
    std::string serialNumber = data.ReadString();
    std::string discoverMode = data.ReadString();
    int32_t ret = AddScanner(serialNumber, discoverMode);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnConnectScanner end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnDisConnectScanner(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnDisConnectScanner start");
    std::string serialNumber = data.ReadString();
    std::string discoverMode = data.ReadString();
    int32_t ret = DeleteScanner(serialNumber, discoverMode);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnDisConnectScanner end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnGetConnectedScanner(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnGetConnectedScanner start");
    std::vector<ScanDeviceInfo> allAddedScanner;
    int32_t ret = GetAddedScanner(allAddedScanner);
    reply.WriteInt32(ret);
    if (ret == E_SCAN_NONE) {
        uint32_t size = static_cast<uint32_t>(allAddedScanner.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            allAddedScanner[index].Marshalling(reply);
        }
    }
    SCAN_HILOGD("ScanServiceStub::OnGetConnectedScanner end");
    return ret == E_SCAN_NONE;
}

bool ScanServiceStub::OnUpdateScannerName(MessageParcel &data, MessageParcel &reply)
{
    SCAN_HILOGD("ScanServiceStub::OnUpdateScannerName start");
    std::string serialNumber = data.ReadString();
    std::string discoverMode = data.ReadString();
    std::string deviceName = data.ReadString();
    int32_t ret = UpdateScannerName(serialNumber, discoverMode, deviceName);
    reply.WriteInt32(ret);
    SCAN_HILOGD("ScanServiceStub::OnUpdateScannerName end");
    return ret == E_SCAN_NONE;
}

} // namespace OHOS::Scan
