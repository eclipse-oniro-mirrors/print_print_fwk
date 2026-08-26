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

#include "kia_interceptor_callback_stub.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
KiaInterceptorCallbackStub::KiaInterceptorCallbackStub()
{
    cmdMap_[KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT] = &KiaInterceptorCallbackStub::HandleCheckRejectEvent;
}

int32_t KiaInterceptorCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("KiaInterceptorCallbackStub::OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_PRINT_NONE : E_PRINT_SERVER_FAILURE;
        }
    }
    PRINT_HILOGW("KiaInterceptorCallbackStub default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool KiaInterceptorCallbackStub::HandleCheckRejectEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("KiaInterceptorCallbackStub HandleCheckRejectEvent start");
    int32_t pid = data.ReadInt32();
    std::string callerAppId = data.ReadString();
    PRINT_HILOGD("KiaInterceptorCallbackStub pid:%{public}d, callerAppId:%{public}s", pid, callerAppId.c_str());
    bool result = OnCheckPrintJobNeedReject(pid, callerAppId);
    reply.WriteBool(result);
    PRINT_HILOGI("KiaInterceptorCallbackStub HandleCheckRejectEvent end");
    return true;
}
} // namespace OHOS::Print
