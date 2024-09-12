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

#include "napi/native_common.h"
#include "accesstoken_kit.h"

#include "print_task.h"
#include "napi_print_utils.h"
#include "print_callback.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_constant.h"

namespace OHOS::Print {

using namespace std;
using namespace Security::AccessToken;

const std::string EVENT_BLOCK = "block";
const std::string EVENT_SUCCESS = "succeed";
const std::string EVENT_FAIL = "fail";
const std::string EVENT_CANCEL = "cancel";

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string TOKEN_KEY = "ohos.ability.params.token";
static const std::string UI_EXTENSION_TYPE_NAME = "ability.want.params.uiExtensionType";
static const std::string PRINT_UI_EXTENSION_TYPE = "sysDialog/print";
static const std::string CALLER_PKG_NAME = "caller.pkgName";

PrintTask::PrintTask(const std::vector<std::string> &innerList, const sptr<IRemoteObject> &innerCallerToken_)
    : taskId_("")
{
    if (!innerList.empty()) {
        if (innerList.begin()->find("fd://") == 0) {
            PRINT_HILOGD("list type: fdlist");
            for (auto fdPath : innerList) {
                pathType_ = FD_PATH;
                uint32_t fd = PrintUtils::GetIdFromFdPath(fdPath);
                fdList_.emplace_back(fd);
            }
        } else {
            PRINT_HILOGD("list type: filelist");
            fileList_.assign(innerList.begin(), innerList.end());
            pathType_ = FILE_PATH_ABSOLUTED;
            if (!fileList_.empty() && fileList_.begin()->find("file://") == 0) {
                pathType_ = FILE_PATH;
            }
        }
    }

    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;
    callerToken_ = innerCallerToken_;
}

PrintTask::PrintTask(const std::string &innerPrintJobName_, const sptr<IPrintCallback> &innerPrintAdapterCallback_,
    const std::shared_ptr<PrintAttributes> &innerPrintAttributes_, const sptr<IRemoteObject> &innerCallerToken_)
    : taskId_("")
{
    supportEvents_[EVENT_BLOCK] = true;
    supportEvents_[EVENT_SUCCESS] = true;
    supportEvents_[EVENT_FAIL] = true;
    supportEvents_[EVENT_CANCEL] = true;
    printJobName_ = innerPrintJobName_;
    printAdapterCallback_ = innerPrintAdapterCallback_;
    printAttributes_ = innerPrintAttributes_;
    callerToken_ = innerCallerToken_;
}

PrintTask::~PrintTask()
{
    supportEvents_.clear();
    Stop();
}

uint32_t PrintTask::Start(napi_env env, napi_callback_info info)
{
    if (fileList_.empty() && fdList_.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    if (pathType_ == FILE_PATH_ABSOLUTED) {
        for (auto file : fileList_) {
            int32_t fd = PrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
                fdList_.clear();
                fileList_.clear();
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList_.emplace_back(fd);
        }
    }

    PRINT_HILOGI("call client's StartPrint interface.");
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    CreateDefaultAdapterParam(adapterParam);
    std::string jobId = PrintUtils::GetPrintJobId();
    adapterParam->jobId = jobId;
    taskId_ = jobId;
    uint32_t ret = CallSpooler(env, info, adapterParam, false);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler failed.");
        fdList_.clear();
        fileList_.clear();
        return ret;
    }
    return PrintManagerClient::GetInstance()->StartPrint(fileList_, fdList_, taskId_);
}

uint32_t PrintTask::StartPrintAdapter(napi_env env, napi_callback_info info)
{
    if (printAdapterCallback_ != nullptr && printAttributes_ != nullptr) {
        PRINT_HILOGI("call client's StartPrintAdapter interface.");
        if (callerToken_ != nullptr) {
            std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
            if (adapterParam == nullptr) {
                PRINT_HILOGE("create adapterParam failed.");
                return E_PRINT_SERVER_FAILURE;
            }
            adapterParam->documentName = printJobName_;
            adapterParam->isCheckFdList = false;
            adapterParam->printAttributes = *printAttributes_;
            std::string jobId = PrintUtils::GetPrintJobId();
            adapterParam->jobId = jobId;
            taskId_ = jobId;
            uint32_t ret = CallSpooler(env, info, adapterParam, true);
            if (ret != E_PRINT_NONE) {
                PRINT_HILOGE("CallSpooler failed.");
            }
            return PrintManagerClient::GetInstance()->Print(
                printJobName_, printAdapterCallback_, *printAttributes_, taskId_, callerToken_);
        }
    }
    return E_PRINT_INVALID_PARAMETER;
}

uint32_t PrintTask::CallSpooler(
    napi_env env, napi_callback_info info, const std::shared_ptr<AdapterParam> &adapterParam, bool isPrintByAdapter)
{
    PRINT_HILOGI("enter CallSpooler.");
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    size_t argc = isPrintByAdapter ? NapiPrintUtils::ARGC_FOUR : NapiPrintUtils::ARGC_TWO;
    size_t contextIndex = isPrintByAdapter ? NapiPrintUtils::INDEX_THREE : NapiPrintUtils::INDEX_ONE;
    size_t callBackIndex = isPrintByAdapter ? NapiPrintUtils::INDEX_FOUR : NapiPrintUtils::INDEX_TWO;
    size_t argMaxNum = isPrintByAdapter ? NapiPrintUtils::ARGC_FIVE : NapiPrintUtils::ARGC_THREE;
    napi_value argv[NapiPrintUtils::ARGC_FOUR] = {0};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_value result = nullptr;

    PRINT_CALL_BASE(env, napi_get_undefined(env, &result), E_PRINT_INVALID_PARAMETER);
    PRINT_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data), E_PRINT_INVALID_PARAMETER);
    PRINT_HILOGI("CallSpooler params size: %{public}zu", argc);
    if (argc < argMaxNum - 1) {
        PRINT_HILOGE("invalid parameters.");
        return E_PRINT_INVALID_PARAMETER;
    }

    auto asyncContext = std::make_shared<BaseContext>();
    asyncContext->env = env;
    asyncContext->requestType = PrintRequestType::REQUEST_TYPE_START;
    if (!ParseAbilityContextReq(env, argv[contextIndex], asyncContext->context, asyncContext->uiExtensionContext)) {
        PRINT_HILOGE("invalid parameters.");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (argc == argMaxNum) {
        napi_valuetype valueType = napi_undefined;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[callBackIndex], &valueType), napi_undefined);
        if (valueType == napi_function) {
            PRINT_CALL_BASE(env, napi_create_reference(env, argv[callBackIndex], 1, &asyncContext->callback),
                E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGD("is a callback api");
        }
    } else {
        PRINT_CALL_BASE(env, napi_create_promise(env, &asyncContext->deferred, &result), E_PRINT_INVALID_PARAMETER);
        PRINT_HILOGD("is a promise api");
    }
    StartUIExtensionAbility(asyncContext, adapterParam);
    PRINT_HILOGI("end CallSpooler");
    return E_PRINT_NONE;
}

bool PrintTask::ParseAbilityContextReq(napi_env env, const napi_value &obj,
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> &abilityContext,
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> &uiExtensionContext)
{
    PRINT_HILOGD("begin ParseAbilityContextReq");
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, obj, stageMode);
    if (status != napi_ok || !stageMode) {
        PRINT_HILOGE("it is not a stage mode");
        return false;
    }

    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, obj);
    if (context == nullptr) {
        PRINT_HILOGE("get context failed");
        return false;
    }

    abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        PRINT_HILOGE("get abilityContext failed");
        uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context);
        if (uiExtensionContext == nullptr) {
            PRINT_HILOGE("get uiExtensionContext failed");
            return false;
        }
    }

    PRINT_HILOGD("end ParseAbilityContextReq");
    return true;
}

void PrintTask::StartUIExtensionAbility(
    std::shared_ptr<BaseContext> asyncContext, const std::shared_ptr<AdapterParam> &adapterParam)
{
    PRINT_HILOGD("begin StartUIExtensionAbility");

    if (adapterParam == nullptr) {
        PRINT_HILOGE("adapterParam is nullptr.");
        return;
    }
    if ((adapterParam->isCheckFdList && fileList_.empty() && fdList_.empty())) {
        PRINT_HILOGE("to be printed filelist and fdlist are empty.");
        return;
    }
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, adapterParam->jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList_);
    PrintUtils::BuildAdapterParam(adapterParam, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string callerPkg = PrintUtils::GetBundleNameForUid(callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    want.SetParam(UI_EXTENSION_TYPE_NAME, PRINT_UI_EXTENSION_TYPE);

    StartUIExtensionAbility(want, asyncContext);
    PRINT_HILOGD("end StartUIExtensionAbility");
    return;
}

uint32_t PrintTask::StartUIExtensionAbility(OHOS::AAFwk::Want &want, std::shared_ptr<BaseContext> asyncContext)
{
    PRINT_HILOGI("begin StartUIExtensionAbility");
    if (asyncContext == nullptr) {
        PRINT_HILOGE("asyncContext is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (asyncContext->context == nullptr && asyncContext->uiExtensionContext == nullptr) {
        PRINT_HILOGE("asyncContext is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    auto uiContent = GetUIContent(asyncContext.get());
    if (uiContent == nullptr) {
        PRINT_HILOGE("UIContent is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    std::string info = uiContent->GetContentInfo();
    auto callback = std::make_shared<PrintModalUICallback>(asyncContext);
    if (callback == nullptr) {
        PRINT_HILOGE("create callback failed.");
        return E_PRINT_SERVER_FAILURE;
    }
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [callback](int32_t releaseCode) { callback->OnRelease(releaseCode); },
        [callback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            callback->OnResultForModal(resultCode, result);
        },
        [callback](const OHOS::AAFwk::WantParams& request) { callback->OnReceive(request); },
        [callback](int32_t code, const std::string& name, const std::string& message) {
            callback->OnError(code, name, message);
        }
    };

    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, config);
    PRINT_HILOGI("StartUIExtensionAbility sessionId %{public}d", sessionId);
    callback->SetSessionId(sessionId);

    PRINT_HILOGI("end StartUIExtensionAbility");
    return E_PRINT_NONE;
}

OHOS::Ace::UIContent *PrintTask::GetUIContent(const BaseContext *asyncContext)
{
    if (asyncContext == nullptr) {
        PRINT_HILOGE("asyncContext is nullptr.");
        return nullptr;
    }
    OHOS::Ace::UIContent *uiContent = nullptr;
    if (asyncContext->context != nullptr) {
        PRINT_HILOGI("get uiContext by ability context");
        uiContent = asyncContext->context->GetUIContent();
    } else if (asyncContext->uiExtensionContext != nullptr) {
        PRINT_HILOGI("get uiContext by ui extension ability context");
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    } else {
        PRINT_HILOGE("get uiContext failed.");
    }

    return uiContent;
}

void PrintTask::CreateDefaultAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam)
{
    adapterParam->documentName = "";
    adapterParam->isCheckFdList = true;
}

void PrintTask::Stop()
{
    PrintManagerClient::GetInstance()->StopPrint(taskId_);
    taskId_ = "";
}

const std::string &PrintTask::GetId() const
{
    return taskId_;
}

napi_value PrintTask::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_TWO, "need 2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    valuetype = napi_undefined;
    napi_typeof(env, argv[1], &valuetype);
    PRINT_ASSERT(env, valuetype == napi_function, "callback is not a function");

    PrintTask *task;
    PRINT_CALL(env, napi_unwrap(env, thisVal, reinterpret_cast<void **>(&task)));
    if (task == nullptr || !task->IsSupportType(type)) {
        PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
        return nullptr;
    }

    napi_ref callbackRef = NapiPrintUtils::CreateReference(env, argv[1]);
    sptr<IPrintCallback> callback = new (std::nothrow) PrintCallback(env, callbackRef);
    if (callback == nullptr) {
        PRINT_HILOGE("create print callback object fail");
        return nullptr;
    }
    int32_t ret = PrintManagerClient::GetInstance()->On(task->taskId_, type, callback);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to register event");
        return nullptr;
    }
    return nullptr;
}

napi_value PrintTask::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<TaskEventContext>();
    if (context == nullptr) {
        PRINT_HILOGE("create context failed.");
        return nullptr;
    }
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, "need 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "type is not a string", napi_string_expected);
        std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        PrintTask *task;
        PRINT_CALL_BASE(env, napi_unwrap(env, self, reinterpret_cast<void **>(&task)), napi_invalid_arg);
        if (task == nullptr || !task->IsSupportType(type)) {
            PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }

        context->type = type;
        context->taskId = task->taskId_;
        PRINT_HILOGD("event type : %{public}s", context->type.c_str());
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("context->result = %{public}d", context->result);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->Off(context->taskId, context->type);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to unregistered event");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

bool PrintTask::IsSupportType(const std::string &type) const
{
    return supportEvents_.find(type) != supportEvents_.end();
}

bool PrintTask::CheckPermission(const std::string &name)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        PRINT_HILOGE("invalid token id %{public}d", tokenId);
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, name);
    if (result != PERMISSION_GRANTED) {
        PRINT_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
}
} // namespace OHOS::Print
