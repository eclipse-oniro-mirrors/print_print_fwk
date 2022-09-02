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

#include "js_print_extension.h"

#include "ability_info.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_print_extension_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "napi_common_util.h"
#include "print_manager_client.h"
#include "print_extcb_interface.h"
#include "print_napi_utils.h"
#include "print_log.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
}
JsPrintExtension* JsPrintExtension::jsExtension_ = nullptr;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;

JsPrintExtension* JsPrintExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    PRINT_HILOGD("jws JsPrintExtension begin Create");
    jsExtension_ = new JsPrintExtension(static_cast<JsRuntime&>(*runtime));
    return jsExtension_;
}

JsPrintExtension::JsPrintExtension(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}
JsPrintExtension::~JsPrintExtension() = default;

void JsPrintExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    PRINT_HILOGD("jws JsPrintExtension begin Init");
    PrintExtension::Init(record, application, handler, token);
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        PRINT_HILOGE("Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    PRINT_HILOGD("JsPrintExtension::Init module:%{public}s,srcPath:%{public}s.", moduleName.c_str(), srcPath.c_str());
    HandleScope handleScope(jsRuntime_);
    auto& engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath);
    if (jsObj_ == nullptr) {
        PRINT_HILOGE("Failed to get jsObj_");
        return;
    }
    PRINT_HILOGD("JsPrintExtension::Init ConvertNativeValueTo.");
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get JsPrintExtension object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        PRINT_HILOGE("Failed to get context");
        return;
    }
    PRINT_HILOGD("JsPrintExtension::Init CreateJsPrintExtensionContext.");
    NativeValue* contextObj = CreateJsPrintExtensionContext(engine, context);
    auto shellContextRef = jsRuntime_.LoadSystemModule("PrintExtensionContext", &contextObj, ARGC_ONE);
    contextObj = shellContextRef->Get();
    PRINT_HILOGD("JsPrintExtension::Init Bind.");
    context->Bind(jsRuntime_, shellContextRef.release());
    PRINT_HILOGD("JsPrintExtension::SetProperty.");
    obj->SetProperty("context", contextObj);

    auto nativeObj = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to get Print extension native object");
        return;
    }

    PRINT_HILOGD("Set Print extension context pointer: %{public}p", context.get());

    nativeObj->SetNativePointer(new std::weak_ptr<AbilityRuntime::Context>(context),
        [](NativeEngine*, void* data, void*) {
            PRINT_HILOGD("Finalizer for weak_ptr Print extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context>*>(data);
        }, nullptr);

    PRINT_HILOGD("JsPrintExtension::Init end.");
}

void JsPrintExtension::OnStart(const AAFwk::Want &want)
{
    Extension::OnStart(want);
    PRINT_HILOGD("jws JsPrintExtension OnStart begin..");
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    CallObjectMethod("onCreated", argv, ARGC_ONE);
    PRINT_HILOGD("%{public}s end.", __func__);
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_START_DISCOVERY,
        []()->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            jsExtension_->CallObjectMethod("onStartDiscoverPrinter");
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_STOP_DISCOVERY,
        []()->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            jsExtension_->CallObjectMethod("onStopDiscoverPrinter");
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_CONNECT_PRINTER,
        [](uint32_t printId)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId = OHOS::AppExecFwk::WrapInt32ToJS(reinterpret_cast<napi_env>(nativeEng),
                static_cast<int32_t>(printId));
            NativeValue* nativePrintId = reinterpret_cast<NativeValue*>(jsPrintId);
            NativeValue* arg[] = { nativePrintId };

            jsExtension_->CallObjectMethod("onConnectPrinter", arg, ARGC_ONE);
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_DISCONNECT_PRINTER,
        [](uint32_t printId)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId = OHOS::AppExecFwk::WrapInt32ToJS(reinterpret_cast<napi_env>(nativeEng),
                static_cast<int32_t>(printId));
            NativeValue* nativePrintId = reinterpret_cast<NativeValue*>(jsPrintId);
            NativeValue* arg[] = { nativePrintId };

            jsExtension_->CallObjectMethod("onDisconnectPrinter", arg, ARGC_ONE);
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_START_PRINT,
        [](const PrintJob& job)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = PrintNapiUtils::Convert2JsObj(reinterpret_cast<napi_env>(nativeEng), job);
            NativeValue* nativeJob = reinterpret_cast<NativeValue*>(jobObject);
            NativeValue* arg[] = { nativeJob };

            jsExtension_->CallObjectMethod("onConnectPrinter", arg, ARGC_ONE);
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_CANCEL_PRINT,
        [](const PrintJob& job)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = PrintNapiUtils::Convert2JsObj(reinterpret_cast<napi_env>(nativeEng), job);
            NativeValue* nativeJob = reinterpret_cast<NativeValue*>(jobObject);
            NativeValue* arg[] = { nativeJob };

            jsExtension_->CallObjectMethod("onCancelPrintJob", arg, ARGC_ONE);
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_REQUEST_CAP,
        [](uint32_t printId)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId = OHOS::AppExecFwk::WrapInt32ToJS(reinterpret_cast<napi_env>(nativeEng),
                static_cast<int32_t>(printId));
            NativeValue* nativePrintId = reinterpret_cast<NativeValue*>(jsPrintId);
            NativeValue* arg[] = { nativePrintId };
            jsExtension_->CallObjectMethod("onRequestPrinterCapability", arg, ARGC_ONE);
            return true;
        });
    PrintManagerClient::GetInstance()->RegisterExtCallback(PRINT_EXTCB_REQUEST_PREVIEW,
        [](const PrintJob& job)->bool {
            PRINT_HILOGD("jsExtension_->CallObjectMethod");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine* nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = PrintNapiUtils::Convert2JsObj(reinterpret_cast<napi_env>(nativeEng), job);
            NativeValue* nativeJob = reinterpret_cast<NativeValue*>(jobObject);
            NativeValue* arg[] = { nativeJob };

            jsExtension_->CallObjectMethod("onRequestPreview", arg, ARGC_ONE);
            return true;
        });
}

void JsPrintExtension::OnStop()
{
    PrintExtension::OnStop();
    PRINT_HILOGD("jws JsPrintExtension OnStop begin.");
    CallObjectMethod("onDestroy");
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(GetContext()->GetToken());
    if (ret) {
        PRINT_HILOGD("The Print extension connection is not disconnected.");
    }
    PRINT_HILOGD("%{public}s end.", __func__);
}

sptr<IRemoteObject> JsPrintExtension::OnConnect(const AAFwk::Want &want)
{
    PRINT_HILOGD("jws JsPrintExtension OnConnect begin.");
    Extension::OnConnect(want);
    PRINT_HILOGD("%{public}s begin.", __func__);
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return nullptr;
    }

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty("onConnect");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onConnect from PrintExtension object");
        return nullptr;
    }
    PRINT_HILOGD("JsPrintExtension::CallFunction onConnect, success");
    NativeValue* remoteNative = nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
    if (remoteNative == nullptr) {
        PRINT_HILOGE("remoteNative nullptr.");
    }
    auto remoteObj = NAPI_ohos_rpc_getNativeRemoteObject(
        reinterpret_cast<napi_env>(nativeEngine), reinterpret_cast<napi_value>(remoteNative));
    if (remoteObj == nullptr) {
        PRINT_HILOGE("remoteObj nullptr.");
    }
    return remoteObj;
}

void JsPrintExtension::OnDisconnect(const AAFwk::Want &want)
{
    PRINT_HILOGD("jws JsPrintExtension OnDisconnect begin.");
    Extension::OnDisconnect(want);
    PRINT_HILOGD("%{public}s begin.", __func__);
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return;
    }

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return;
    }

    NativeValue* method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onDisconnect from PrintExtension object");
        return;
    }
    nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
    PRINT_HILOGD("%{public}s end.", __func__);
}

void JsPrintExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    PRINT_HILOGD("jws JsPrintExtension OnCommand begin.");
    Extension::OnCommand(want, restart, startId);
    PRINT_HILOGD("%{public}s begin restart=%{public}s,startId=%{public}d.",
        __func__,
        restart ? "true" : "false",
        startId);
    PRINT_HILOGD("%{public}s end.", __func__);
}

NativeValue* JsPrintExtension::CallObjectMethod(const char* name, NativeValue* const* argv, size_t argc)
{
    PRINT_HILOGD("jws JsPrintExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto& nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty(name);
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get '%{public}s' from PrintExtension object", name);
        return nullptr;
    }
    PRINT_HILOGD("JsPrintExtension::CallFunction(%{public}s), success", name);
    return nativeEngine.CallFunction(value, method, argv, argc);
}

void JsPrintExtension::GetSrcPath(std::string &srcPath)
{
    PRINT_HILOGD("jws JsPrintExtension GetSrcPath begin.");
    if (!Extension::abilityInfo_->isModuleJson) {
        /* temporary compatibility api8 + config.json */
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        srcPath.erase(srcPath.rfind('.'));
        srcPath.append(".abc");
    }
}
}
}
