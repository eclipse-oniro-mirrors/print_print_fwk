/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "../include/kia_interceptor_callback_proxy.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
KiaInterceptorCallbackProxy::KiaInterceptorCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IKiaInterceptorCallback>(object)
{
}

bool KiaInterceptorCallbackProxy::OnCheckPrintJobNeedReject(const int32_t &pid, const std::string &callerAppId)
{
    PRINT_HILOGI("KiaInterceptorCallbackProxy OnCheckPrintJobNeedReject Start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("Write descriptor failed");
        return false;
    }
    data.WriteInt32(pid);
    data.WriteString(callerAppId);

    auto remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("Remote is null");
        return false;
    }

    int32_t ret = remote->SendRequest(KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT, data, reply, option);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("SendRequest failed, ret = %{public}d", ret);
        return false;
    }

    bool result = reply.ReadBool();
    PRINT_HILOGD("KiaInterceptorCallbackProxy OnCheckPrintJobNeedReject End, result = %{public}d", result);
    return result;
}
} // namespace OHOS::Print
