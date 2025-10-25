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
#include <queue>
#include "ability_manager_client.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_client.h"
#include "ability_connect_callback_stub.h"
#include "system_ability.h"
#include "print_log.h"
#include "print_event_subscriber.h"

namespace OHOS::Print {
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
    virtual bool StartExtensionAbility(const AAFwk::Want &want);
    virtual bool StartPluginPrintExtAbility(const AAFwk::Want &want);
    virtual void PrintSubscribeCommonEvent();
    virtual bool DisconnectAbility();
    virtual bool CheckPluginPrintConnected();

private:
    class PrintAbilityConnection : public AAFwk::AbilityConnectionStub {
        void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
            int32_t resultCode) override
        {
            if (resultCode == ERR_OK) {
                PRINT_HILOGI("connect done");
                isConnected_ = true;
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
    };

private:
    std::shared_ptr<PrintEventSubscriber> userStatusListener;
    bool isSubscribeCommonEvent = false;
    sptr<PrintAbilityConnection> printAbilityConnection_ = nullptr;
    static std::mutex connectionListLock_;
    std::queue<sptr<PrintAbilityConnection>> pluginPrintConnectionList_;
};
}  // namespace OHOS
#endif  // PRINT_SERVICE_HELPER_H
