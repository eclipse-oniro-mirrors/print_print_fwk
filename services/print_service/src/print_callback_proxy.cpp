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
#include "print_callback_proxy.h"

#include "message_parcel.h"
#include "print_log.h"

namespace OHOS::Print {
PrintCallbackProxy::PrintCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IPrintCallback>(impl) {}

bool PrintCallbackProxy::OnCallback()
{
    PRINT_HILOGD("PrintCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(PRINT_CALLBACK_TASK, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintCallbackProxy::OnCallback End");
    return true;
}

bool PrintCallbackProxy::OnCallback(uint32_t state, const PrinterInfo &info)
{
    PRINT_HILOGD("PrintCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    PRINT_HILOGD("Printer Event argument:[%{public}d], printerId [%{private}s]", state, info.GetPrinterId().c_str());
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(state);
    info.Marshalling(data);

    int error = Remote()->SendRequest(PRINT_CALLBACK_PRINTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintCallbackProxy::OnCallback End");
    return true;
}

bool PrintCallbackProxy::OnCallback(uint32_t state, const PrintJob &info)
{
    PRINT_HILOGD("PrintCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    PRINT_HILOGD("PrintJob Event state:[%{public}d], subState [%{public}d]", state, info.GetSubState());
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(state);
    info.Marshalling(data);

    int error = Remote()->SendRequest(PRINT_CALLBACK_PRINT_JOB, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintCallbackProxy::OnCallback End");
    return true;
}

bool PrintCallbackProxy::OnCallback(const std::string &extensionId, const std::string &info)
{
    PRINT_HILOGD("PrintCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionId);
    data.WriteString(info);

    int error = Remote()->SendRequest(PRINT_CALLBACK_EXTINFO, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintCallbackProxy::OnCallback End");
    return true;
}

bool PrintCallbackProxy::OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterLayout Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteString(jobId);
    oldAttrs.Marshalling(data);
    newAttrs.Marshalling(data);
    data.WriteFileDescriptor(fd);

    int error = Remote()->SendRequest(PRINT_CALLBACK_PRINT_JOB_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterLayout End");
    return true;
}

bool PrintCallbackProxy::onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    PRINT_HILOGI("PrintCallbackProxy::onCallbackAdapterJobStateChanged Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteString(jobId);
    data.WriteUint32(state);
    data.WriteUint32(subState);

    int error = Remote()->SendRequest(PRINT_CALLBACK_PRINT_JOB_CHANGED_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::onCallbackAdapterJobStateChanged End");
    return true;
}

bool PrintCallbackProxy::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterGetFile Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

    data.WriteUint32(state);

    int error = Remote()->SendRequest(PRINT_CALLBACK_PRINT_GET_FILE_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterGetFile End");
    return true;
}
} // namespace OHOS::Print
