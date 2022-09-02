/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "print_extcb_proxy.h"
#include "print_log.h"
#include "message_parcel.h"

namespace OHOS::Print {
PrintExtcbProxy::PrintExtcbProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<PrintExtcbInterface>(impl)
{
}

bool PrintExtcbProxy::OnCallback()
{
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(PRINT_EXTCB, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack End");
    return true;
}

bool PrintExtcbProxy::OnCallback(uint32_t printerId)
{
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(printerId);

    int error = Remote()->SendRequest(PRINT_EXTCB_PRINTER, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack End");
    return true;
}

bool PrintExtcbProxy::OnCallback(const PrintJob &job)
{
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(PRINT_EXTCB_PRINTJOB, data, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
        return false;
    }
    PRINT_HILOGD("PrintExtcbProxy::OnCallBack End");
    return true;
}
} // namespace OHOS::Print
