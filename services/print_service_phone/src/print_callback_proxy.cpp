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
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintCallbackProxy::PrintCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IPrintCallback>(impl) {}

bool PrintCallbackProxy::OnCallback()
{
    PRINT_HILOGD("PrintCallbackProxy::OnCallback Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_TASK, data, reply, option);
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
    MessageOption option(MessageOption::TF_ASYNC);

    PRINT_HILOGD("Printer Event argument:[%{public}d], printerId [%{private}s]", state, info.GetPrinterId().c_str());
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(state), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(info.Marshalling(data), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINTER, data, reply, option);
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
    MessageOption option(MessageOption::TF_ASYNC);

    PRINT_HILOGD("PrintJob Event state:[%{public}d], subState [%{public}d]", state, info.GetSubState());
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(state), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(info.Marshalling(data), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINT_JOB, data, reply, option);
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
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteString(extensionId), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteString(info), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_EXTINFO, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintCallbackProxy::OnCallback End");
    return true;
}

bool PrintCallbackProxy::OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallback printer driver Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(info.Marshalling(data), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(ppds.size()), false);
    for (const auto &ppd : ppds) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(ppd.Marshalling(data), false);
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINT_QUERY_INFO, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallback printer driver End");
    return true;
}

bool PrintCallbackProxy::OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterLayout Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteString(jobId), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(oldAttrs.Marshalling(data), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(newAttrs.Marshalling(data), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteFileDescriptor(fd), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINT_JOB_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterLayout End");
    return true;
}

bool PrintCallbackProxy::OnCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterJobStateChanged Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteString(jobId), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(state), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(subState), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINT_JOB_CHANGED_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterJobStateChanged End");
    return true;
}

bool PrintCallbackProxy::OnCallbackAdapterGetFile(uint32_t state)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterGetFile Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(state), false);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_PRINT_GET_FILE_ADAPTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallbackAdapterGetFile End");
    return true;
}

bool PrintCallbackProxy::OnCallback(const std::vector<PrintSharedHost> &sharedHosts)
{
    PRINT_HILOGI("PrintCallbackProxy::OnCallback sharedHosts Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteInterfaceToken(GetDescriptor()), false);

    if (sharedHosts.size() > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("too much sharedHosts");
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.WriteUint32(sharedHosts.size()), false);
    for (const auto &host : sharedHosts) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(host.Marshalling(data), false);
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("SendRequest failed, error: remote is null");
        return false;
    }
    int error = remote->SendRequest(PRINT_CALLBACK_SHARED_HOST_DISCOVER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGI("PrintCallbackProxy::OnCallback sharedHosts End");
    return true;
}
} // namespace OHOS::Print

