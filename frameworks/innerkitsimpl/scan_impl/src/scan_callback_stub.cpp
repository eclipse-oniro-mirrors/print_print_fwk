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

#include "scan_callback_stub.h"

#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanCallbackStub::ScanCallbackStub()
{
    cmdMap_[SCAN_CALLBACK_DEVICE_TCP] = &ScanCallbackStub::HandleDeviceInfoTcpEvent;
    cmdMap_[SCAN_CALLBACK_DEVICE] = &ScanCallbackStub::HandleDeviceInfoEvent;
    cmdMap_[SCAN_CALLBACK_DEVICE_SYNC] = &ScanCallbackStub::HandleDeviceInfoSyncEvent;
    cmdMap_[SCAN_CALLBACK_GET_FRAME_RES] = &ScanCallbackStub::HandleGetFrameResEvent;
    cmdMap_[SCAN_CALLBACK_SCAN_INIT] = &ScanCallbackStub::HandleGetFrameResEvent;
    cmdMap_[SCAN_CALLBACK_SEND_MESSAGE] = &ScanCallbackStub::HandleSendSearchMessage;
    cmdMap_[SCAN_CALLBACK_DEVICE_LIST] = &ScanCallbackStub::HandleSendDeviceList;
}

int32_t ScanCallbackStub::OnRemoteRequest(
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
            return static_cast<int32_t>((this->*requestFunc)(data, reply));
        }
    }
    SCAN_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool ScanCallbackStub::HandleDeviceInfoTcpEvent(MessageParcel &data, MessageParcel &reply)
{
    uint32_t state = data.ReadUint32();
    auto info = ScanDeviceInfoTCP::Unmarshalling(data);
    if (info == nullptr) {
        SCAN_HILOGE("invalid scaner info object");
        return false;
    }
    bool result = OnCallback(state, *info);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleDeviceInfoEvent(MessageParcel &data, MessageParcel &reply)
{
    uint32_t state = data.ReadUint32();
    auto info = ScanDeviceInfo::Unmarshalling(data);
    if (info == nullptr) {
        SCAN_HILOGE("invalid scaner info object");
        return false;
    }
    bool result = OnCallback(state, *info);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleDeviceInfoSyncEvent(MessageParcel &data, MessageParcel &reply)
{
    uint32_t state = data.ReadUint32();
    auto info = ScanDeviceInfoSync::Unmarshalling(data);
    if (info == nullptr) {
        SCAN_HILOGE("invalid scaner info object");
        return false;
    }
    bool result = OnCallbackSync(state, *info);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleGetFrameResEvent(MessageParcel &data, MessageParcel &reply)
{
    bool isGetSucc = data.ReadBool();
    int32_t sizeRead = data.ReadInt32();
    bool result = OnGetFrameResCallback(isGetSucc, sizeRead);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleScanInitEvent(MessageParcel &data, MessageParcel &reply)
{
    int32_t scanVersion = data.ReadInt32();
    bool result = OnScanInitCallback(scanVersion);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleSendSearchMessage(MessageParcel &data, MessageParcel &reply)
{
    std::string message = data.ReadString();
    bool result = OnSendSearchMessage(message);
    reply.WriteBool(result);
    return true;
}

bool ScanCallbackStub::HandleSendDeviceList(MessageParcel &data, MessageParcel &reply)
{
    std::vector<ScanDeviceInfo> infos;
    int infosSize = data.ReadInt32();
    CHECK_IS_EXCEED_SCAN_RANGE_BOOL(infosSize);
    SCAN_HILOGI("get infosSize : %{public}d", infosSize);
    for (auto i = 0; i < infosSize; i++) {
        auto info = ScanDeviceInfo::Unmarshalling(data);
        if (info == nullptr) {
            SCAN_HILOGE("invalid scaner info object");
            return false;
        }
        infos.emplace_back(*info);
    }
    bool result = OnGetDevicesList(infos);
    reply.WriteBool(result);
    return true;
}

}  // namespace OHOS::Scan

// namespace OHOS::Scan
