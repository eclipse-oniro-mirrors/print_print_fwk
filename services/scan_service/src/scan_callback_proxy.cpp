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
#include "scan_callback_proxy.h"

#include "message_parcel.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanCallbackProxy::ScanCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IScanCallback>(impl) {}


bool ScanCallbackProxy::OnCallback(uint32_t state, const ScanDeviceInfoTCP &info)
{
    SCAN_HILOGD("GetScannerList ScanCallbackProxy::OnCallback");
    SCAN_HILOGD("ScanCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteUint32(state);
    info.Marshalling(data);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnCallback remote is null");
        return false;
    }

    int error = remote->SendRequest(SCAN_CALLBACK_DEVICE_TCP, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }

    SCAN_HILOGD("ScanCallbackProxy::OnCallback End");
    return true;
}

bool ScanCallbackProxy::OnCallback(uint32_t state, const ScanDeviceInfo &info)
{
    SCAN_HILOGD("GetScannerList ScanCallbackProxy::OnCallback");
    SCAN_HILOGD("ScanCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteUint32(state);
    info.Marshalling(data);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnCallback remote is null");
        return false;
    }

    int error = remote->SendRequest(SCAN_CALLBACK_DEVICE, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }

    SCAN_HILOGD("ScanCallbackProxy::OnCallback End");
    return true;
}

bool ScanCallbackProxy::OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info)
{
    SCAN_HILOGD("ScanCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }
    data.WriteUint32(state);
    info.Marshalling(data);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnCallbackSync remote is null");
        return false;
    }

    int error = remote->SendRequest(SCAN_CALLBACK_DEVICE_SYNC, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }

    SCAN_HILOGD("ScanCallbackProxy::OnCallbackSync End");
    return true;
}

bool ScanCallbackProxy::OnGetFrameResCallback(bool isGetSucc, int32_t sizeRead)
{
    SCAN_HILOGD("ScanCallbackProxy::OnGetFrameResCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteBool(isGetSucc);
    data.WriteInt32(sizeRead);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnGetFrameResCallback remote is null");
        return false;
    }

    int error = remote->SendRequest(SCAN_CALLBACK_GET_FRAME_RES, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    SCAN_HILOGD("ScanCallbackProxy::OnGetFrameResCallback End");
    return true;
}

bool ScanCallbackProxy::OnScanInitCallback(int32_t &scanVersion)
{
    SCAN_HILOGE("Enter OnScanInitCallback");
    SCAN_HILOGD("ScanCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteUint32(scanVersion);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnScanInitCallback remote is null");
        return false;
    }

    int error = remote->SendRequest(SCAN_CALLBACK_SCAN_INIT, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }

    SCAN_HILOGD("ScanCallbackProxy::OnCallback End");
    return true;
}

bool ScanCallbackProxy::OnSendSearchMessage(std::string &message)
{
    SCAN_HILOGD("Enter OnSendSearchMessage");
    SCAN_HILOGD("ScanCallbackProxy::OnSendSearchMessage Start");
    MessageParcel data;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteString(message);
    auto remotePtr = Remote();
    if (!remotePtr) {
        SCAN_HILOGE("Remote() nullptr failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    int error = remotePtr->SendRequest(SCAN_CALLBACK_SEND_MESSAGE, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    SCAN_HILOGD("ScanCallbackProxy::OnSendSearchMessage End");
    return true;
}

bool ScanCallbackProxy::OnGetDevicesList(std::vector<ScanDeviceInfo> &infos)
{
    SCAN_HILOGI("Enter OnGetDevicesList");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SCAN_HILOGE("write descriptor failed");
        return false;
    }
    data.WriteInt32(infos.size());
    for (size_t i = 0; i < infos.size(); i++) {
        infos[i].Marshalling(data);
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanCallbackProxy::OnGetDevicesList remote is null");
        return false;
    }
    int error = remote->SendRequest(SCAN_CALLBACK_DEVICE_LIST, data, reply, option);
    if (error != 0) {
        SCAN_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }

    SCAN_HILOGI("ScanCallbackProxy::OnCallback End");
    return true;
}
} // namespace OHOS::Scan
