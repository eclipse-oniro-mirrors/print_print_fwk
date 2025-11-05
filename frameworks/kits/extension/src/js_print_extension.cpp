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
#include "print_job_helper.h"
#include "print_extension_ability_stub.h"
#include "print_utils.h"

namespace OHOS {
namespace AbilityRuntime {
JsPrintExtension *JsPrintExtension::jsExtension_ = nullptr;
std::mutex JsPrintExtension::mtx;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;

JsPrintExtension *JsPrintExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    PRINT_HILOGI("JsPrintExtension begin Create");
    jsExtension_ = new JsPrintExtension(static_cast<JsRuntime &>(*runtime));
    return jsExtension_;
}

JsPrintExtension::JsPrintExtension(JsRuntime &jsRuntime) : jsRuntime_(jsRuntime),
    extensionId_("") {}
JsPrintExtension::~JsPrintExtension()
{
    std::lock_guard<std::mutex> lock(mtx);
    if (jsExtension_ != nullptr) {
        jsExtension_ = nullptr;
    }
    if (jsObj_) {
        jsRuntime_.FreeNativeReference(std::move(jsObj_));
    }
    PRINT_HILOGI("JsPrintExtension destroyed");
}


void JsPrintExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    PRINT_HILOGI("JsPrintExtension begin Init");
    PrintExtension::Init(record, application, handler, token);

    if (!InitExtensionObj(jsRuntime_)) {
        PRINT_HILOGE("Failed to init extension object");
        return;
    }

    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get JsPrintExtension object");
        return;
    }

    if (!InitContextObj(jsRuntime_, obj, extensionId_)) {
        PRINT_HILOGE("Failed to init extension context object");
        return;
    }
    PRINT_HILOGI("JsPrintExtension::Init end.");
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

    jsObj_ = jsRuntime.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        PRINT_HILOGE("Failed to get jsObj_");
        return false;
    }
    return true;
}

bool JsPrintExtension::InitContextObj(JsRuntime &jsRuntime, napi_value &extObj, std::string &extensionId)
{
    auto context = GetContext();
    if (context == nullptr) {
        PRINT_HILOGE("Failed to get context");
        return false;
    }
    PRINT_HILOGD("CreateJsPrintExtensionContext.");
    napi_env engine = jsRuntime.GetNapiEnv();
    napi_value contextObj = CreateJsPrintExtensionContext(engine, context, extensionId);
    auto shellContextRef = jsRuntime.LoadSystemModule("PrintExtensionContext", &contextObj, NapiPrintUtils::ARGC_ONE);
    if (shellContextRef == nullptr) {
        PRINT_HILOGE("Failed to load print extension context ref");
        return false;
    }
    contextObj = shellContextRef->GetNapiValue();
    if (contextObj == nullptr) {
        PRINT_HILOGE("Failed to get Print extension native object");
        return false;
    }
    PRINT_HILOGD("JsPrintExtension::Init Bind.");
    context->Bind(jsRuntime, shellContextRef.release());
    PRINT_HILOGD("JsPrintExtension::napi_set_named_property.");
    napi_set_named_property(engine, extObj, "context", contextObj);

    napi_wrap(engine, contextObj, new std::weak_ptr<AbilityRuntime::Context>(context),
        [](napi_env, void *data, void *) {
            PRINT_HILOGI("Finalizer for weak_ptr Print extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context> *>(data);
        },
        nullptr, nullptr);
    return true;
}

void JsPrintExtension::OnStart(const AAFwk::Want &want)
{
    Extension::OnStart(want);
    PRINT_HILOGI("JsPrintExtension OnStart begin..");
    HandleScope handleScope(jsRuntime_);
    napi_env nativeEngine = jsRuntime_.GetNapiEnv();
    napi_value nativeWant = OHOS::AppExecFwk::WrapWant(nativeEngine, want);
    napi_value argv[] = { nativeWant };
    CallObjectMethod("onCreate", argv, NapiPrintUtils::ARGC_ONE);
    if (!RegisterCb()) {	
        OnStop();
        return;
    }
    PrintManagerClient::GetInstance()->LoadExtSuccess(extensionId_);
    PRINT_HILOGD("%{public}s end.", __func__);
}

bool JsPrintExtension::RegisterCb()	
{	
    return RegisterHelper({
        { &JsPrintExtension::RegisterDiscoveryCb, "RegisterDiscoveryCb" },	
        { &JsPrintExtension::RegisterConnectionCb, "RegisterConnectionCb" },	
        { &JsPrintExtension::RegisterPrintJobCb, "RegisterPrintJobCb" },	
        { &JsPrintExtension::RegisterPreviewCb, "RegisterPreviewCb" },	
        { &JsPrintExtension::RegisterQueryCapCb, "RegisterQueryCapCb" },	
        { &JsPrintExtension::RegisterExtensionCb, "RegisterExtensionCb" }
    });
}

bool JsPrintExtension::RegisterHelper(
    const std::initializer_list<std::pair<int32_t (JsPrintExtension::*)(), const char*>>& funcList)
{
    for (const auto& [func, funcName] : funcList) {
        int32_t ret = (this->*func)();
        if (ret != 0) {
            PRINT_HILOGE("%s failed, errCode: %{public}d", funcName, ret);
            return false;
        }
    }
    return true;
}

void JsPrintExtension::OnStop()
{
    PrintExtension::OnStop();
    PRINT_HILOGI("JsPrintExtension OnStop begin.");
    auto context = GetContext();
    if (context == nullptr) {
        PRINT_HILOGE("Failed to get context");
        return;
    }
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(context->GetToken());
    if (ret) {
        PRINT_HILOGD("The Print extension connection is not disconnected.");
    }
    PRINT_HILOGD("%{public}s end.", __func__);
}

sptr<IRemoteObject> JsPrintExtension::OnConnect(const AAFwk::Want &want)
{
    PRINT_HILOGI("JsPrintExtension OnConnect begin.");
    Extension::OnConnect(want);
    auto remoteObj = new (std::nothrow) Print::PrintExtensionAbilityStub();
    if (remoteObj == nullptr) {
        PRINT_HILOGE("remoteObj nullptr.");
        return nullptr;
    }
    return remoteObj;
}

void JsPrintExtension::OnDisconnect(const AAFwk::Want &want)
{
    PRINT_HILOGI("JsPrintExtension OnDisconnect begin.");
    Extension::OnDisconnect(want);
}

void JsPrintExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    PRINT_HILOGI("JsPrintExtension OnCommand begin.");
    Extension::OnCommand(want, restart, startId);
    PRINT_HILOGD("begin restart=%{public}s,startId=%{public}d.", restart ? "true" : "false", startId);
    if (startId <= 1) {
        PRINT_HILOGD("%{public}s ignore.", __func__);
        return;
    }
    HandleScope handleScope(jsRuntime_);
    napi_env nativeEngine = jsRuntime_.GetNapiEnv();
    napi_value nativeWant = OHOS::AppExecFwk::WrapWant(nativeEngine, want);
    napi_value argv[] = { nativeWant };
    CallObjectMethod("onCreate", argv, NapiPrintUtils::ARGC_ONE);
    RegisterCb();
    PrintManagerClient::GetInstance()->LoadExtSuccess(extensionId_);
    PRINT_HILOGD("%{public}s end.", __func__);
}

napi_value JsPrintExtension::CallObjectMethod(const char *name, napi_value const *argv, size_t argc)
{
    PRINT_HILOGI("JsPrintExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        PRINT_HILOGW("Not found PrintExtension.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    napi_env nativeEngine = jsRuntime_.GetNapiEnv();

    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        PRINT_HILOGE("Failed to get PrintExtension object");
        return nullptr;
    }

    napi_value method = nullptr;
    if (napi_get_named_property(nativeEngine, obj, name, &method) != napi_ok ||	
        method == nullptr) {
        PRINT_HILOGE("Failed to get '%{public}s' from PrintExtension object", name);
        return nullptr;
    }
    PRINT_HILOGD("JsPrintExtension::napi_call_function(%{public}s), success", name);
    napi_value callResult = nullptr;
    napi_call_function(nativeEngine, obj, method, argc, argv, &callResult);
    return callResult;
}

void JsPrintExtension::GetSrcPath(std::string &srcPath)
{
    PRINT_HILOGI("JsPrintExtension GetSrcPath begin.");
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

bool JsPrintExtension::Callback(std::string funcName)
{
    PRINT_HILOGI("JsPrintExtension call %{public}s", funcName.c_str());
    std::lock_guard<std::mutex> lock(mtx);
    if (JsPrintExtension::jsExtension_ == nullptr) {
        return false;
    }
    napi_env env = (JsPrintExtension::jsExtension_->jsRuntime_).GetNapiEnv();
    WorkParam *workParam = new (std::nothrow) WorkParam(env, funcName);
    if (workParam == nullptr) {
        PRINT_HILOGE("workParam is a nullptr");
        return false;
    }
    auto workCb = [](WorkParam *param) {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");	
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            PRINT_HILOGE("scope is a nullptr");
            return;
        }
        napi_value arg[] = { 0 };
        std::lock_guard<std::mutex> lock(mtx);
        if (JsPrintExtension::jsExtension_ != nullptr) {
            JsPrintExtension::jsExtension_->CallObjectMethod(param->funcName.c_str(), arg, NapiPrintUtils::ARGC_ZERO);
        }
        napi_close_handle_scope(param->env, scope);
    };
    bool ret = JsPrintCallback::Call(env, workParam, workCb);
    if (!ret) {
        PRINT_HILOGE("Callback fail, delete param");
        delete workParam;
        return false;
    }
    return true;
}

bool JsPrintExtension::Callback(const std::string funcName, const std::string &printerId)
{
    PRINT_HILOGD("call %{public}s", funcName.c_str());
    std::lock_guard<std::mutex> lock(mtx);
    if (JsPrintExtension::jsExtension_ == nullptr) {
        return false;
    }
    napi_env env = (JsPrintExtension::jsExtension_->jsRuntime_).GetNapiEnv();
    WorkParam *workParam = new (std::nothrow) WorkParam(env, funcName);
    if (workParam == nullptr) {
        PRINT_HILOGE("workParam is a nullptr");
        return false;
    }
    workParam->printerId = printerId;
    
    auto workCb = [](WorkParam *param) {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            PRINT_HILOGE("scope is a nullptr");
            return;
        }
        napi_value id = OHOS::AppExecFwk::WrapStringToJS(param->env, param->printerId);
        napi_value arg[] = { id };
        std::lock_guard<std::mutex> lock(mtx);
        if (JsPrintExtension::jsExtension_ != nullptr) {
            JsPrintExtension::jsExtension_->CallObjectMethod(param->funcName.c_str(), arg, NapiPrintUtils::ARGC_ONE);
        }
        napi_close_handle_scope(param->env, scope);
    };
    
    bool ret = JsPrintCallback::Call(env, workParam, workCb);
    if (!ret) {
        PRINT_HILOGE("Callback fail, delete param");
        delete workParam;
        return false;
    }
    return true;
}

bool JsPrintExtension::Callback(const std::string funcName, const Print::PrintJob &job)
{
    PRINT_HILOGD("call %{public}s", funcName.c_str());
    std::lock_guard<std::mutex> lock(mtx);
    if (JsPrintExtension::jsExtension_ == nullptr) {
        return false;
    }
    napi_env env = (JsPrintExtension::jsExtension_->jsRuntime_).GetNapiEnv();
    WorkParam *workParam = new (std::nothrow) WorkParam(env, funcName);
    if (workParam == nullptr) {
        PRINT_HILOGE("workParam is a nullptr");
        return false;
    }
    workParam->job = job;
    
    auto workCb = [](WorkParam *param) {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        if (scope == nullptr) {
            PRINT_HILOGE("scope is a nullptr");
            return;
        }
        napi_value jobObject = PrintJobHelper::MakeJsObject(param->env, param->job);
        napi_value arg[] = { jobObject };
        std::lock_guard<std::mutex> lock(mtx);
        if (JsPrintExtension::jsExtension_ != nullptr) {
            JsPrintExtension::jsExtension_->CallObjectMethod(param->funcName.c_str(), arg, NapiPrintUtils::ARGC_ONE);
        }
        napi_close_handle_scope(param->env, scope);
    };
    
    bool ret = JsPrintCallback::Call(env, workParam, workCb);
    if (!ret) {
        PRINT_HILOGE("Callback fail, delete param");
        workParam = nullptr;
        return false;
    }
    return true;
}

int32_t JsPrintExtension::RegisterDiscoveryCb()	
{
    PRINT_HILOGD("Register Print Extension Callback");
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_DISCOVERY,
        []() -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            return JsPrintExtension::jsExtension_->Callback("onStartDiscoverPrinter");
    });
    if (ret) {
        return ret;
    }
    ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_STOP_DISCOVERY,
        []() -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            return JsPrintExtension::jsExtension_->Callback("onStopDiscoverPrinter");
    });
    return ret;
}

int32_t JsPrintExtension::RegisterConnectionCb()
{
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CONNECT_PRINTER,	
        [](const std::string &printId) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            return JsPrintExtension::jsExtension_->Callback("onConnectPrinter", realPrinterId);
    });
    if (ret) {
        return ret;
    }
    ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_DISCONNECT_PRINTER,
        [](const std::string &printId) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            return JsPrintExtension::jsExtension_->Callback("onDisconnectPrinter", realPrinterId);
    });
    return ret;
}

int32_t JsPrintExtension::RegisterPrintJobCb()
{
    int32_t ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_PRINT,	
        [](const PrintJob &job) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            return JsPrintExtension::jsExtension_->Callback("onStartPrintJob", job);
    });
    if (ret) {	
        return ret;
    }
    ret = PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CANCEL_PRINT,
        [](const PrintJob &job) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            return JsPrintExtension::jsExtension_->Callback("onCancelPrintJob", job);
    });
    return ret;
}

int32_t JsPrintExtension::RegisterPreviewCb()
{
    return PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_PREVIEW,	
        [](const PrintJob &job) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            return JsPrintExtension::jsExtension_->Callback("onRequestPreview", job);
    });
}

int32_t JsPrintExtension::RegisterQueryCapCb()
{
    return PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_CAP,
        [](const std::string &printId) -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, jsExtension_->extensionId_);
            return JsPrintExtension::jsExtension_->Callback("onRequestPrinterCapability", realPrinterId);
    });
}

int32_t JsPrintExtension::RegisterExtensionCb()
{
    return PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_DESTROY_EXTENSION,
        []() -> bool {
            if (JsPrintExtension::jsExtension_ == nullptr) {
                return false;
            }
            JsPrintExtension::jsExtension_->OnStop();
            return true;
    });
}
} // namespace AbilityRuntime
} // namespace OHOS
