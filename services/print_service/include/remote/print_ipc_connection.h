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

#ifndef PRINT_IPC_CONNECTION_H
#define PRINT_IPC_CONNECTION_H

#include <condition_variable>
#include <mutex>
#include <string>
#include "ability_connect_callback_stub.h"
#include "element_name.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"
#include "noncopyable.h"
#include "print_log.h"

namespace OHOS::Print {

class PrintIpcConnection : public AAFwk::AbilityConnectionStub {
public:
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject,
        int32_t resultCode) override;

    void OnAbilityDisconnectDone(
        const AppExecFwk::ElementName &element,
        int32_t resultCode) override;

    bool IsConnected();

    sptr<IRemoteObject> GetRemoteObject();

    bool WaitForConnection(int32_t timeoutMs = 5000);

    int32_t SendData(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    sptr<IRemoteObject> remoteObject_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

} // namespace OHOS::Print

#endif // PRINT_IPC_CONNECTION_H