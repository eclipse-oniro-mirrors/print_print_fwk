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

#include "js_print_extension.h"

#include "ability_info.h"
#include "iprint_extension_callback.h"
#include "js_print_callback.h"
#include "js_print_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_print_utils.h"
#include "napi_remote_object.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "printer_capability.h"

namespace OHOS {
namespace AbilityRuntime {

JsPrintExtension *JsPrintExtension::jsExtension_ = nullptr;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;

JsPrintExtension *JsPrintExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    PRINT_HILOGD("jws JsPrintExtension begin Create");
    jsExtension_ = new JsPrintExtension(static_cast<JsRuntime &>(*runtime));
    return jsExtension_;
}

JsPrintExtension::JsPrintExtension(JsRuntime &jsRuntime) : jsRuntime_(jsRuntime), extensionId_("") {}
JsPrintExtension::~JsPrintExtension() = default;

void JsPrintExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    PRINT_HILOGD("jws JsPrintExtension begin Init");
    PrintExtension::Init(record, application, handler, token);

    if (!InitExtensionObj(jsRuntime_)) {
        PRINT_HILOGE("Failed to init extension object");
        return;
    }

    PRINT_HILOGD("JsPrintExtension::Init ConvertNativeValueTo.");
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get JsPrintExtension object");
        return;
    }

    if (!InitContextObj(jsRuntime_, obj, extensionId_)) {
        PRINT_HILOGE("Failed to init extension context object");
        return;
    }

    PRINT_HILOGD("JsPrintExtension::Init end.");
}

bool JsPrintExtension::InitExtensionObj(JsRuntime &jsRuntime)
{
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        PRINT_HILOGE("Failed to get srcPath");
        return false;
    }

    std::string moduleName(abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    PRINT_HILOGD("Init module:%{public}s,srcPath:%{public}s.", moduleName.c_str(), srcPath.c_str());
    HandleScope handleScope(jsRuntime_);

    jsObj_ = jsRuntime.LoadModule(moduleName, srcPath, abilityInfo_->hapPath);
    if (jsObj_ == nullptr) {
        PRINT_HILOGE("Failed to get jsObj_");
        return false;
    }
    return true;
}

bool JsPrintExtension::InitContextObj(JsRuntime &jsRuntime, NativeObject *&extObj, std::string &extensionId)
{
    auto context = GetContext();
    if (context == nullptr) {
        PRINT_HILOGE("Failed to get context");
        return false;
    }
    PRINT_HILOGD("CreateJsPrintExtensionContext.");
    auto &engine = jsRuntime.GetNativeEngine();
    NativeValue *contextObj = CreateJsPrintExtensionContext(engine, context, extensionId);
    auto shellContextRef = jsRuntime.LoadSystemModule("PrintExtensionContext", &contextObj, NapiPrintUtils::ARGC_ONE);
    contextObj = shellContextRef->Get();
    PRINT_HILOGD("JsPrintExtension::Init Bind.");
    context->Bind(jsRuntime, shellContextRef.release());
    PRINT_HILOGD("JsPrintExtension::SetProperty.");
    extObj->SetProperty("context", contextObj);

    auto nativeObj = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to get Print extension native object");
        return false;
    }

    PRINT_HILOGD("Set Print extension context pointer: %{public}p", context.get());

    nativeObj->SetNativePointer(
        new std::weak_ptr<AbilityRuntime::Context>(context),
        [](NativeEngine *, void *data, void *) {
            PRINT_HILOGD("Finalizer for weak_ptr Print extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context> *>(data);
        },
        nullptr);
    return true;
}

void JsPrintExtension::OnStart(const AAFwk::Want &want)
{
    Extension::OnStart(want);
    PRINT_HILOGD("jws JsPrintExtension OnStart begin..");
    HandleScope handleScope(jsRuntime_);
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue *>(napiWant);
    NativeValue *argv[] = { nativeWant };
    CallObjectMethod("onCreated", argv, NapiPrintUtils::ARGC_ONE);
    RegisterDiscoveryCb();
    RegisterConnectionCb();
    RegisterPrintJobCb();
    RegisterPreviewCb();
    RegisterQueryCapCb();
    PrintManagerClient::GetInstance()->LoadExtSuccess(extensionId_);
    PRINT_HILOGD("%{public}s end.", __func__);
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
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue *>(napiWant);
    NativeValue *argv[] = { nativeWant };
    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return nullptr;
    }

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty("onConnect");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onConnect from PrintExtension object");
        return nullptr;
    }
    PRINT_HILOGD("JsPrintExtension::CallFunction onConnect, success");
    NativeValue *remoteNative = nativeEngine->CallFunction(value, method, argv, NapiPrintUtils::ARGC_ONE);
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
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue *>(napiWant);
    NativeValue *argv[] = { nativeWant };
    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return;
    }

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return;
    }

    NativeValue *method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        PRINT_HILOGE("Failed to get onDisconnect from PrintExtension object");
        return;
    }
    nativeEngine->CallFunction(value, method, argv, NapiPrintUtils::ARGC_ONE);
    PRINT_HILOGD("%{public}s end.", __func__);
}

void JsPrintExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    PRINT_HILOGD("jws JsPrintExtension OnCommand begin.");
    Extension::OnCommand(want, restart, startId);
    PRINT_HILOGD("begin restart=%{public}s,startId=%{public}d.", restart ? "true" : "false", startId);
    if (startId <= 1) {
        PRINT_HILOGD("%{public}s ignore.", __func__);
        return;
    }
    PrintManagerClient::GetInstance()->LoadExtSuccess(extensionId_);
    PRINT_HILOGD("%{public}s end.", __func__);
}

NativeValue *JsPrintExtension::CallObjectMethod(const char *name, NativeValue *const *argv, size_t argc)
{
    PRINT_HILOGD("jws JsPrintExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty(name);
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

void JsPrintExtension::RegisterDiscoveryCb()
{
    PRINT_HILOGD("Register Print Extension Callback");
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_DISCOVERY,
        []() -> bool {
            PRINT_HILOGD("Start Print Discovery");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onStartDiscoverPrinter");
            return true;
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_STOP_DISCOVERY,
        []() -> bool {
            PRINT_HILOGD("Stop Print Discovery");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onStopDiscoverPrinter");
        return true;
    });
}

void JsPrintExtension::RegisterConnectionCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CONNECT_PRINTER,
        [](const std::string &printId) -> bool {
            PRINT_HILOGD("Connect Printer");
            std::string realPrinterId = NapiPrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId =
                OHOS::AppExecFwk::WrapStringToJS(reinterpret_cast<napi_env>(nativeEng), realPrinterId);
            NativeValue *nativePrintId = reinterpret_cast<NativeValue *>(jsPrintId);
            NativeValue *arg[] = { nativePrintId };
            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onConnectPrinter", arg, NapiPrintUtils::ARGC_ONE);
            return true;
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_DISCONNECT_PRINTER,
        [](const std::string &printId) -> bool {
            PRINT_HILOGD("Disconnect Printer");
            std::string realPrinterId = NapiPrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId =
                OHOS::AppExecFwk::WrapStringToJS(reinterpret_cast<napi_env>(nativeEng), realPrinterId);
            NativeValue *nativePrintId = reinterpret_cast<NativeValue *>(jsPrintId);
            NativeValue *arg[] = { nativePrintId };
            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onDisconnectPrinter", arg, NapiPrintUtils::ARGC_ONE);
            return true;
    });
}

void JsPrintExtension::RegisterPrintJobCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_PRINT,
        [](const PrintJob &job) -> bool {
            PRINT_HILOGD("Start Print Job");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = job.ToJsObject(reinterpret_cast<napi_env>(nativeEng));
            NativeValue *nativeJob = reinterpret_cast<NativeValue *>(jobObject);
            NativeValue *arg[] = { nativeJob };

            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onStartPrintJob", arg, NapiPrintUtils::ARGC_ONE);
            return true;
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CANCEL_PRINT,
        [](const PrintJob &job) -> bool {
            PRINT_HILOGD("Cancel Print Job");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = job.ToJsObject(reinterpret_cast<napi_env>(nativeEng));
            NativeValue *nativeJob = reinterpret_cast<NativeValue *>(jobObject);
            NativeValue *arg[] = { nativeJob };

            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onCancelPrintJob", arg, NapiPrintUtils::ARGC_ONE);
            return true;
    });
}

void JsPrintExtension::RegisterPreviewCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_PREVIEW,
        [](const PrintJob &job) -> bool {
            PRINT_HILOGD("Requet preview");
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jobObject = job.ToJsObject(reinterpret_cast<napi_env>(nativeEng));
            NativeValue *nativeJob = reinterpret_cast<NativeValue *>(jobObject);
            NativeValue *arg[] = { nativeJob };

            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onRequestPreview", arg, NapiPrintUtils::ARGC_ONE);
            return true;
    });
}

void JsPrintExtension::RegisterQueryCapCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_CAP,
        [](const std::string &printId) -> bool {
            PRINT_HILOGD("Request Capability");
            std::string realPrinterId = NapiPrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            HandleScope handleScope(jsExtension_->jsRuntime_);
            NativeEngine *nativeEng = &(jsExtension_->jsRuntime_).GetNativeEngine();
            napi_value jsPrintId =
                OHOS::AppExecFwk::WrapStringToJS(reinterpret_cast<napi_env>(nativeEng), realPrinterId);
            NativeValue *nativePrintId = reinterpret_cast<NativeValue *>(jsPrintId);
            NativeValue *arg[] = { nativePrintId };
            auto callback = std::make_shared<JsPrintCallback>(jsExtension_->jsRuntime_);
            NativeValue *value = jsExtension_->jsObj_->Get();
            callback->Exec(value, "onRequestPrinterCapability", arg, NapiPrintUtils::ARGC_ONE);
            PRINT_HILOGD("Request Capability Success");
            return true;
    });
}
} // namespace AbilityRuntime
} // namespace OHOS
