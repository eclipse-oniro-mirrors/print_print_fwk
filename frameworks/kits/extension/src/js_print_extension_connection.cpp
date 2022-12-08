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

#include "js_print_extension_connection.h"
#include "js_data_struct_converter.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_start_options.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_print_utils.h"
#include "napi_remote_object.h"
#include "print_log.h"
#include "start_options.h"

using namespace OHOS::Print;

namespace OHOS {
namespace AbilityRuntime {
JSPrintExtensionConnection::JSPrintExtensionConnection(NativeEngine& engine) : engine_(engine) {}

JSPrintExtensionConnection::~JSPrintExtensionConnection() = default;

void JSPrintExtensionConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    PRINT_HILOGD("OnAbilityConnectDone begin, resultCode:%{public}d", resultCode);
    if (handler_ == nullptr) {
        PRINT_HILOGD("handler_ nullptr");
        return;
    }
    wptr<JSPrintExtensionConnection> connection = this;
    auto task = [connection, element, remoteObject, resultCode]() {
        sptr<JSPrintExtensionConnection> connectionSptr = connection.promote();
        if (!connectionSptr) {
            PRINT_HILOGD("connectionSptr nullptr");
            return;
        }
        connectionSptr->HandleOnAbilityConnectDone(element, remoteObject, resultCode);
    };
    handler_->PostTask(task, "OnAbilityConnectDone");
}

void JSPrintExtensionConnection::HandleOnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    PRINT_HILOGD("HandleOnAbilityConnectDone begin, resultCode:%{public}d", resultCode);
    // wrap ElementName
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(reinterpret_cast<napi_env>(&engine_), element);
    NativeValue* nativeElementName = reinterpret_cast<NativeValue*>(napiElementName);

    // wrap RemoteObject
    PRINT_HILOGD("OnAbilityConnectDone begin NAPI_ohos_rpc_CreateJsRemoteObject");
    napi_value napiRemoteObject = NAPI_ohos_rpc_CreateJsRemoteObject(
        reinterpret_cast<napi_env>(&engine_), remoteObject);
    NativeValue* nativeRemoteObject = reinterpret_cast<NativeValue*>(napiRemoteObject);
    NativeValue* argv[] = {nativeElementName, nativeRemoteObject};
    if (jsConnectionObject_ == nullptr) {
        PRINT_HILOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue* value = jsConnectionObject_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get object");
        return;
    }
    NativeValue* methodOnConnect = obj->GetProperty("onConnect");
    if (methodOnConnect == nullptr) {
        PRINT_HILOGE("Failed to get onConnect from object");
        return;
    }
    PRINT_HILOGD("JSPrintExtensionConnection::CallFunction onConnect, success");
    engine_.CallFunction(value, methodOnConnect, argv, NapiPrintUtils::ARGC_TWO);
    PRINT_HILOGD("OnAbilityConnectDone end");
}

void JSPrintExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    PRINT_HILOGD("OnAbilityDisconnectDone begin, resultCode:%{public}d", resultCode);
    if (handler_ == nullptr) {
        PRINT_HILOGD("handler_ nullptr");
        return;
    }
    wptr<JSPrintExtensionConnection> connection = this;
    auto task = [connection, element, resultCode]() {
        sptr<JSPrintExtensionConnection> connectionSptr = connection.promote();
        if (!connectionSptr) {
            PRINT_HILOGD("connectionSptr nullptr");
            return;
        }
        connectionSptr->HandleOnAbilityDisconnectDone(element, resultCode);
    };
    handler_->PostTask(task, "OnAbilityDisconnectDone");
}

void JSPrintExtensionConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int resultCode)
{
    PRINT_HILOGD("HandleOnAbilityDisconnectDone begin, resultCode:%{public}d", resultCode);
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(reinterpret_cast<napi_env>(&engine_), element);
    NativeValue* nativeElementName = reinterpret_cast<NativeValue*>(napiElementName);
    NativeValue* argv[] = {nativeElementName};
    if (jsConnectionObject_ == nullptr) {
        PRINT_HILOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue* value = jsConnectionObject_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get object");
        return;
    }

    NativeValue* method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onDisconnect from object");
        return;
    }

    // release connect
    PRINT_HILOGD("OnAbilityDisconnectDone connects_.size:%{public}zu", connects_.size());
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    auto item = std::find_if(connects_.begin(),
        connects_.end(),
        [bundleName, abilityName](
            const std::map<ConnecttionKey, sptr<JSPrintExtensionConnection>>::value_type &obj) {
            return (bundleName == obj.first.want.GetBundle()) &&
                   (abilityName == obj.first.want.GetElement().GetAbilityName());
        });
    if (item != connects_.end()) {
        // match bundlename && abilityname
        connects_.erase(item);
        PRINT_HILOGD("OnAbilityDisconnectDone erase connects_.size:%{public}zu", connects_.size());
    }
    PRINT_HILOGD("OnAbilityDisconnectDone CallFunction success");
    engine_.CallFunction(value, method, argv, NapiPrintUtils::ARGC_ONE);
}

void JSPrintExtensionConnection::SetJsConnectionObject(NativeValue* jsConnectionObject)
{
    jsConnectionObject_ = std::unique_ptr<NativeReference>(engine_.CreateReference(jsConnectionObject, 1));
}

void JSPrintExtensionConnection::CallJsFailed(int32_t errorCode)
{
    PRINT_HILOGD("CallJsFailed begin");
    if (jsConnectionObject_ == nullptr) {
        PRINT_HILOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue* value = jsConnectionObject_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get object");
        return;
    }

    NativeValue* method = obj->GetProperty("onFailed");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onFailed from object");
        return;
    }
    NativeValue* argv[] = {engine_.CreateNumber(errorCode)};
    PRINT_HILOGD("CallJsFailed CallFunction success");
    engine_.CallFunction(value, method, argv, NapiPrintUtils::ARGC_ONE);
    PRINT_HILOGD("CallJsFailed end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS