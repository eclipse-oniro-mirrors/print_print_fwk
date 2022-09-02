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
#include "print_notify_proxy.h"

#include "message_parcel.h"
#include "print_log.h"

namespace OHOS::Print {
PrintNotifyProxy::PrintNotifyProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<PrintNotifyInterface>(impl) {}

void PrintNotifyProxy::OnCallBack(MessageParcel &data)
{
    PRINT_HILOGD("PrintNotifyProxy::OnCallBack Start");
    PRINT_HILOGD("data should be filled within service module");
    MessageParcel realData;
    MessageParcel reply;
    MessageOption option;

    if (!realData.WriteInterfaceToken(PrintNotifyProxy::GetDescriptor())) {
        PRINT_HILOGE("write descriptor failed");
        return;
    }
    uint32_t argv1 = data.ReadUint32();
    uint32_t argv2 = data.ReadUint32();
    PRINT_HILOGD("notification's argument:[%{public}d, %{public}d]", argv1, argv2);
    realData.WriteUint32(argv1);
    realData.WriteUint32(argv2);

    int error = Remote()->SendRequest(PRINT_NOTIFY, realData, reply, option);
    if (error != 0) {
        PRINT_HILOGE("SendRequest failed, error %{public}d", error);
    }
    PRINT_HILOGD("PrintNotifyProxy::OnCallBack End");
}
} // namespace OHOS::Print
