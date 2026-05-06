/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_SERVICE_HELPER_H
#define PRINT_SERVICE_HELPER_H

#include <string>
#include <atomic>
#include <list>
#include "ability_manager_client.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_client.h"
#include "ability_connect_callback_stub.h"
#include "system_ability.h"
#include "print_log.h"
#include "print_event_subscriber.h"

namespace OHOS::Print {
enum class ExtensionAbilityType {
    PRINT_EXTENSION_ABILITY = 0,
    SERVICE_EXTENSION_ABILITY = 1
};
class PrintServiceHelper {
public:
    virtual ~PrintServiceHelper();
    virtual bool CheckPermission(const std::string &name);
    virtual bool StartAbility(const AAFwk::Want &want);
    virtual sptr<IRemoteObject> GetBundleMgr();
    virtual bool QueryAccounts(std::vector<int> &accountList);
    virtual bool QueryExtension(sptr<AppExecFwk::IBundleMgr> mgr, int userId,
                                    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos);
    virtual bool QueryNameForUid(sptr<AppExecFwk::IBundleMgr> mgr, int32_t userId, std::string& name);
    virtual bool IsSyncMode();
    virtual bool StartExtensionAbility(const AAFwk::Want &want, std::function<void()> deathCallback);
    virtual bool StartPluginPrintExtAbility(const AAFwk::Want &want);
    virtual void PrintSubscribeCommonEvent();
    virtual bool DisconnectAbility(ExtensionAbilityType extensionAbilityType);
    virtual bool CheckPluginPrintConnected();

private:
    class PrintConnectCallbackRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit PrintConnectCallbackRecipient(std::function<void()> func) : func_(std::move(func))
        {}
        ~PrintConnectCallbackRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            PRINT_HILOGI("extension connection died.");
            if (func_) {
                func_();
            }
        }

    private:
        std::function<void()> func_ = nullptr;
    };

    class PrintAbilityConnection : public AAFwk::AbilityConnectionStub {
    public:
        PrintAbilityConnection() = default;
        PrintAbilityConnection(std::function<void()> func) : func_(std::move(func))
        {
            deathRecipient_ = new (std::nothrow) PrintConnectCallbackRecipient(func_);
        }

    private:
        void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
            int32_t resultCode) override
        {
            if (resultCode == ERR_OK) {
                PRINT_HILOGI("connect done");
                isConnected_ = true;
                if (remoteObject == nullptr || deathRecipient_ == nullptr) {
                    PRINT_HILOGE("fail to create DeathRecipient");
                    return;
                }
                remoteObject->AddDeathRecipient(deathRecipient_);
            } else {
                PRINT_HILOGI("connect failed, ret = %{public}d", resultCode);
            }
        }
        void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override
        {
            if (resultCode == ERR_OK) {
                PRINT_HILOGI("disconnect done");
                isDisonnected_ = true;
            } else {
                PRINT_HILOGI("disconnect failed, ret = %{public}d", resultCode);
            }
        }

    public:
        bool IsConnected() { return isConnected_.load(); }
        bool IsDisonnected() { return isConnected_.load(); }

    private:
        std::atomic<bool> isConnected_ = false;
        std::atomic<bool> isDisonnected_ = false;
        std::function<void()> func_ = nullptr;
        sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    };

private:
    std::shared_ptr<PrintEventSubscriber> userStatusListener;
    bool isSubscribeCommonEvent = false;
    static std::mutex connectionListLock_;
    std::map<ExtensionAbilityType, std::list<sptr<PrintAbilityConnection>>> extConnectionMap_;
};
}  // namespace OHOS
#endif  // PRINT_SERVICE_HELPER_H
