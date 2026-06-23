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

#ifndef PRINT_ABILITY_MANAGER_ADAPTER_H
#define PRINT_ABILITY_MANAGER_ADAPTER_H

#include <mutex>

#include "ability_connect_callback_interface.h"
#include "extension_ability_info.h"
#include "want.h"

namespace OHOS {
namespace Print {
using namespace AAFwk;

constexpr int32_t DEFAULT_INVAL_VALUE = -1;

class AbilityManagerAdapter {
private:
    AbilityManagerAdapter();
    virtual ~AbilityManagerAdapter();
    DISALLOW_COPY_AND_MOVE(AbilityManagerAdapter);

public:
    static AbilityManagerAdapter &GetInstance();

    ErrCode Connect();

    ErrCode StartAbility(const Want &want, int requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE,
        uint64_t specifiedFullTokenId = 0);

    ErrCode ConnectAbility(const Want &want, sptr<IAbilityConnection> connect, int32_t userId);

    ErrCode ConnectAbilityWithExtensionType(const Want &want, sptr<IAbilityConnection> connect,
        sptr<IRemoteObject> callerToken, int32_t userId = DEFAULT_INVAL_VALUE,
        AppExecFwk::ExtensionAbilityType extensionType = AppExecFwk::ExtensionAbilityType::SERVICE);

    ErrCode DisconnectAbility(sptr<IAbilityConnection> connect);

private:
    /**
     * Connect ability common method.
     *
     * @param want, special want for service type's ability.
     * @param connect, callback used to notify caller the result of connecting or disconnecting.
     * @param callerToken, caller ability token.
     * @param extensionType, type of the extension.
     * @param userId, the service user ID.
     * @param specifiedFullTokenId, The specified full token ID.
     * @param loadTimeout, timeout multiply for ability loading stage, range 1-30, not work on asan.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectAbilityCommon(const Want &want, const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, AppExecFwk::ExtensionAbilityType extensionType,
        int32_t userId = DEFAULT_INVAL_VALUE, bool isQueryExtensionOnly = false, uint64_t specifiedFullTokenId = 0,
        int32_t loadTimeout = 0);

private:
    class AbilityMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AbilityMgrDeathRecipient() = default;
        ~AbilityMgrDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AbilityMgrDeathRecipient);
    };

    sptr<IRemoteObject> GetAbilityManagerProxy();
    void ResetProxy(const wptr<IRemoteObject> &remote);

    std::mutex proxyMutex_;
    sptr<IRemoteObject> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_ABILITY_MANAGER_ADAPTER_H