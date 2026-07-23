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

#ifndef PRINT_FUZZTEST_ABILITY_MANAGER_ADAPTER_FUZZER_H
#define PRINT_FUZZTEST_ABILITY_MANAGER_ADAPTER_FUZZER_H

#include <ipc_object_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include <want.h>
#include <ability_connect_callback_interface.h>
#include "ability_manager_adapter.h"

#define FUZZ_PROJECT_NAME "ability_manager_adapter_fuzzer"

namespace OHOS {
namespace Print {

class MockAbilityConnectCallback : public AAFwk::IAbilityConnection {
public:
    ~MockAbilityConnectCallback() override = default;
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    sptr<IRemoteObject> AsObject() override;
};

class MockRemoteObject : public IPCObjectStub {
public:
    MockRemoteObject();
    ~MockRemoteObject() override;

    bool IsProxyObject() const override;
    bool CheckObjectLegality() const override;
    sptr<IRemoteBroker> AsInterface() override;
};

}  // namespace Print
}  // namespace OHOS

#endif  // PRINT_FUZZTEST_ABILITY_MANAGER_ADAPTER_FUZZER_H