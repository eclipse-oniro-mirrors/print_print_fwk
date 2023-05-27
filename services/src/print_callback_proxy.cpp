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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

    PRINT_HILOGD("Printer Event argument:[%{public}d], printerId [%{private}s]", state, info.GetPrinterId().c_str());
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

    PRINT_HILOGD("PrintJob Event argument:[%{public}d], subState [%{public}d]", state, info.GetSubState());
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

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return false;
    }

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
} // namespace OHOS::Print
