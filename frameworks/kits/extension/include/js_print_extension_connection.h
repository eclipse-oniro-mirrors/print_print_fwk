/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef JS_PRINT_EXTENSION_CONNECTION_H
#define JS_PRINT_EXTENSION_CONNECTION_H

#include <memory>
#include <shared_mutex>

#include "ability_connect_callback.h"
#include "event_handler.h"
#include "print_extension_context.h"
#include "napi/native_api.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class JSPrintExtensionConnection : public AbilityConnectCallback {
public:
    explicit JSPrintExtensionConnection(napi_env engine);
    ~JSPrintExtensionConnection();
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    void HandleOnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode);
    void HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode);
    void SetJsConnectionObject(napi_value jsConnectionObject);
    void CallJsFailed(int32_t errorCode);
private:
    napi_env engine_;
    std::unique_ptr<NativeReference> jsConnectionObject_ = nullptr;
    std::shared_timed_mutex managersMutex_;
};

struct ConnecttionKey {
    AAFwk::Want want;
    int64_t id;
};

struct key_compare {
    bool operator()(const ConnecttionKey &key1, const ConnecttionKey &key2) const
    {
        if (key1.id < key2.id) {
            return true;
        }
        return false;
    }
};

static std::map<ConnecttionKey, sptr<JSPrintExtensionConnection>, key_compare> connects_;
static int64_t serialNumber_ = 0;
static std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // JS_PRINT_EXTENSION_CONNECTION_H