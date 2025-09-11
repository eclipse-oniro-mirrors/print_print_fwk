/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sts_print_extension.h"
#include "print_manager_client.h"
#include "print_log.h"
#include "print_utils.h"
#include "common_fun_ani.h"
#include "ohos_application.h"
#include "print_extension_context.h"
#include "print_base_ani_util.h"
#include "ani_print_job_helper.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;
StsPrintExtension *StsPrintExtension::stsExtension_ = nullptr;

StsPrintExtension* StsPrintExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    PRINT_HILOGD("StsPrintExtension begin Create");
    stsExtension_ = new (std::nothrow) StsPrintExtension(static_cast<ETSRuntime&>(*runtime));
    return stsExtension_;
}

StsPrintExtension::StsPrintExtension(ETSRuntime &etsRuntime) : etsRuntime_(etsRuntime) {}

StsPrintExtension::~StsPrintExtension()
{
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
}

void StsPrintExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    PRINT_HILOGI("PrintExtension Init begin");
    if (record == nullptr) {
        PRINT_HILOGE("record null");
        return;
    }
    PrintExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        PRINT_HILOGE("StsPrintExtension Init abilityInfo error");
        return;
    }

    if (record != nullptr) {
        token_ = record->GetToken();
    }
    // initialize etsObj_
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    auto pos = srcPath.rfind(".");
    if (pos != std::string::npos) {
        srcPath.erase(pos);
        srcPath.append(".abc");
    }
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    PRINT_HILOGD("srcPath: %{public}s, moduleName:%{public}s", srcPath.c_str(), moduleName.c_str());
    etsObj_ = etsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo_->srcEntrance);
    if (etsObj_ == nullptr) {
        PRINT_HILOGE("etsObj_ null");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return;
    }
    BindContext(env, record->GetWant(), application);
    PRINT_HILOGI("PrintExtension Init end");
}

void StsPrintExtension::ResetEnv(ani_env* env)
{
    env->DescribeError();
    env->ResetError();
}

void StsPrintExtension::OnStart(const AAFwk::Want &want)
{
    PRINT_HILOGI("PrintExtension begin OnStart");
    auto env = etsRuntime_.GetAniEnv();
    if (!env) {
        PRINT_HILOGE("env not found Ability.sts");
        return;
    }
    const char *signature =
        "C{@ohos.app.ability.Want.Want}:";
    CallObjectMethod(false, "onCreate", signature, nullptr);
    PrintManagerClient::GetInstance()->LoadExtSuccess(extensionId_);
    RegisterCb();
    PRINT_HILOGD("%{public}s end.", __func__);
}

void StsPrintExtension::OnStop()
{
    PRINT_HILOGI("PrintExtension begin OnStop");
    CallObjectMethod(false, "onDestroy", nullptr);
    OnStopCallBack();
}

sptr<IRemoteObject> StsPrintExtension::OnConnect(const AAFwk::Want &want)
{
    PRINT_HILOGI("PrintExtension begin OnConnect");
    sptr<IRemoteObject> remoteObj = nullptr;
    return remoteObj;
}

void StsPrintExtension::OnDisconnect(const AAFwk::Want &want)
{
    PRINT_HILOGI("PrintExtension begin OnDisconnect");
    Extension::OnDisconnect(want);
}

void StsPrintExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    PRINT_HILOGI("PrintExtension begin OnCommand");
}

bool StsPrintExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    if (etsObj_ == nullptr) {
        PRINT_HILOGE("etsObj_ nullptr");
        return false;
    }

    auto env = etsRuntime_.GetAniEnv();
    ResetEnv(env);
    ani_status status = ANI_OK;
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(etsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return false;
    }
    env->ResetError();
    if (withResult) {
        ani_boolean res = 0;
        va_list args;
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Boolean(etsObj_->aniObj, method, &res, args)) != ANI_OK) {
            PRINT_HILOGE("status: %{public}d", status);
            etsRuntime_.HandleUncaughtError();
        }
        va_end(args);
        return res;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObj_->aniObj, method, args)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        etsRuntime_.HandleUncaughtError();
        return false;
    }
    va_end(args);
    return false;
}

void StsPrintExtension::BindExtensionInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    PRINT_HILOGI("BindExtensionInfo enter");
    auto hapModuleInfo = context->GetHapModuleInfo();
    ani_status status = ANI_OK;
    if (abilityInfo && hapModuleInfo) {
        auto isExist = [&abilityInfo](const OHOS::AppExecFwk::ExtensionAbilityInfo& info) {
            PRINT_HILOGE("%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
            return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
        };
        auto infoIter = std::find_if(
            hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
        if (infoIter == hapModuleInfo->extensionInfos.end()) {
            PRINT_HILOGE("set extensionAbilityInfo fail");
            return;
        }
        ani_field extensionAbilityInfoField;
        status = aniEnv->Class_FindField(contextClass, "extensionAbilityInfo", &extensionAbilityInfoField);
        if (status != ANI_OK) {
            PRINT_HILOGE("status: %{public}d", status);
            return;
        }
        ani_object extAbilityInfoObj = OHOS::AppExecFwk::CommonFunAni::ConvertExtensionInfo(aniEnv, *infoIter);
        status = aniEnv->Object_SetField_Ref(contextObj, extensionAbilityInfoField,
            reinterpret_cast<ani_ref>(extAbilityInfoObj));
        if (status != ANI_OK) {
            PRINT_HILOGE("status: %{public}d", status);
            return;
        }
    }
}

ani_object StsPrintExtension::CreateStsPrintExtensionContext(ani_env *env,
    std::shared_ptr<PrintExtensionContext> context,
    const std::shared_ptr<OHOS::AppExecFwk::OHOSApplication> &application)
{
    PRINT_HILOGI("PrintExtension begin CreateStsPrintExtensionContext");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass("PrintExtensionContext.PrintExtensionContext", &cls)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    if (application == nullptr) {
        PRINT_HILOGE("application null");
        return nullptr;
    }
    BindExtensionInfo(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

ani_object StsPrintExtension::CreateSTSContext(ani_env* env, std::shared_ptr<PrintExtensionContext> context,
    int32_t screenMode, const std::shared_ptr<OHOSApplication> &application)
{
    ani_object obj = CreateStsPrintExtensionContext(env, context, application);
    return obj;
}

void StsPrintExtension::BindContext(ani_env*env, std::shared_ptr<AAFwk::Want> want,
    const std::shared_ptr<OHOSApplication> &application)
{
    if (env == nullptr || want == nullptr) {
        PRINT_HILOGE("Want info is null or env is null");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        PRINT_HILOGE("context null");
        return;
    }

    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::IDLE_SCREEN_MODE);
    ani_object contextObj = CreateSTSContext(env, context, screenMode, application);
    if (contextObj == nullptr) {
        PRINT_HILOGE("null contextObj");
        return;
    }

    ani_field contextField;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        ResetEnv(env);
        return;
    }

    ani_ref contextRef = nullptr;
    if ((status = env->GlobalReference_Create(contextObj, &contextRef)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return;
    }

    if ((status = env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        ResetEnv(env);
    }
}

bool StsPrintExtension::Callback(const std::string &funcName)
{
    PRINT_HILOGD("call %{public}s", funcName.c_str());
    if (etsObj_ == nullptr) {
        PRINT_HILOGE("etsObj_ is null");
        return false;
    }
    return CallObjectMethod(false, funcName.c_str(), nullptr);
}

bool StsPrintExtension::Callback(const std::string &funcName, const std::string &printerId)
{
    PRINT_HILOGD("call %{public}s", funcName.c_str());
    if (etsObj_ == nullptr) {
        PRINT_HILOGE("etsObj_ is null");
        return false;
    }
    
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        PRINT_HILOGE("env is null");
        return false;
    }
    
    ani_string stsPrinterId = CreateAniString(env, printerId);
    return CallObjectMethod(false, funcName.c_str(), "C{@ohos.lang.String}:", stsPrinterId);
}

bool StsPrintExtension::Callback(const std::string &funcName, const Print::PrintJob &job)
{
    PRINT_HILOGD("call %{public}s", funcName.c_str());
    if (etsObj_ == nullptr) {
        PRINT_HILOGE("etsObj_ is null");
        return false;
    }
    
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        PRINT_HILOGE("env is null");
        return false;
    }
    
    ani_object stsJob = AniPrintJobHelper::CreatePrintJob(env, job);
    return CallObjectMethod(false, funcName.c_str(), "C{@ohos.print.PrintJob}:", stsJob);
}

void StsPrintExtension::RegisterCb()
{
    RegisterDiscoveryCb();
    RegisterConnectionCb();
    RegisterPrintJobCb();
    RegisterPreviewCb();
    RegisterQueryCapCb();
    RegisterExtensionCb();
}

void StsPrintExtension::RegisterDiscoveryCb()
{
    PRINT_HILOGD("Register Print Extension Callback");
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_DISCOVERY,
        []() -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onStartDiscoverPrinter");
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_STOP_DISCOVERY,
        []() -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onStopDiscoverPrinter");
    });
}

void StsPrintExtension::RegisterConnectionCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CONNECT_PRINTER,
        [](const std::string &printId) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, stsExtension_->extensionId_);
            return StsPrintExtension::stsExtension_->Callback("onConnectPrinter", realPrinterId);
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_DISCONNECT_PRINTER,
        [](const std::string &printId) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, stsExtension_->extensionId_);
            return StsPrintExtension::stsExtension_->Callback("onDisconnectPrinter", realPrinterId);
    });
}

void StsPrintExtension::RegisterPrintJobCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_START_PRINT,
        [](const PrintJob &job) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onStartPrintJob", job);
    });
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_CANCEL_PRINT,
        [](const PrintJob &job) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onCancelPrintJob", job);
    });
}

void StsPrintExtension::RegisterPreviewCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_PREVIEW,
        [](const PrintJob &job) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onRequestPreview", job);
    });
}

void StsPrintExtension::RegisterQueryCapCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_REQUEST_CAP,
        [](const std::string &printId) -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            std::string realPrinterId = PrintUtils::GetLocalId(printId, stsExtension_->extensionId_);
            return StsPrintExtension::stsExtension_->Callback("onRequestPrinterCapability", realPrinterId);
    });
}

void StsPrintExtension::RegisterExtensionCb()
{
    PrintManagerClient::GetInstance()->RegisterExtCallback(extensionId_, PRINT_EXTCB_DESTROY_EXTENSION,
        []() -> bool {
            if (StsPrintExtension::stsExtension_ == nullptr) {
                PRINT_HILOGE("stsExtension_ is null");
                return false;
            }
            return StsPrintExtension::stsExtension_->Callback("onDestroy");
    });
}
} // AbilityRuntime
} // OHOS
